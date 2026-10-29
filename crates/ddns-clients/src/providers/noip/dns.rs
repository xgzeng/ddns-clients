//! A minimal DNS client asking No-IP's authoritative nameservers for a
//! hostname's addresses, so caches and local overrides in the system resolver
//! don't hide what No-IP actually has.
//!
//! Queries go over TCP: some networks intercept DNS over UDP, and only
//! authoritative answers are accepted.

use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

use crate::Result;

/// The nameservers of No-IP's hostname domains, e.g. `ddns.net`.
const NAMESERVERS: [&str; 5] = [
    "nf1.no-ip.com",
    "nf2.no-ip.com",
    "nf3.no-ip.com",
    "nf4.no-ip.com",
    "nf5.no-ip.com",
];

/// Time allowed for one nameserver to answer both queries.
const TIMEOUT: Duration = Duration::from_secs(5);

const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;
const CLASS_IN: u16 = 1;

/// The A and AAAA addresses of `hostname`, from the first No-IP nameserver
/// that answers authoritatively.
pub(super) async fn lookup(hostname: &str) -> Result<Vec<IpAddr>> {
    let mut last_err = None;
    for nameserver in NAMESERVERS {
        match tokio::time::timeout(TIMEOUT, lookup_at(nameserver, hostname)).await {
            Ok(Ok(ips)) => return Ok(ips),
            Ok(Err(err)) => {
                log::debug!("{nameserver}: lookup of {hostname} failed: {err}");
                last_err = Some(err);
            }
            Err(_) => {
                log::debug!("{nameserver}: lookup of {hostname} timed out");
                last_err = Some(io::Error::from(io::ErrorKind::TimedOut).into());
            }
        }
    }
    Err(last_err.expect("NAMESERVERS is not empty"))
}

async fn lookup_at(nameserver: &str, hostname: &str) -> Result<Vec<IpAddr>> {
    let mut addrs: Vec<SocketAddr> = tokio::net::lookup_host((nameserver, 53)).await?.collect();
    // IPv4 first: many hosts have no IPv6 route
    addrs.sort_by_key(SocketAddr::is_ipv6);
    let addr = addrs
        .first()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "nameserver has no address"))?;

    let mut ips = query(*addr, hostname, TYPE_A).await?;
    ips.extend(query(*addr, hostname, TYPE_AAAA).await?);
    Ok(ips)
}

/// Asks `server` for `hostname`'s records of type `qtype`, over TCP.
async fn query(server: SocketAddr, hostname: &str, qtype: u16) -> Result<Vec<IpAddr>> {
    let id = query_id();
    let message = encode_query(id, hostname, qtype)?;

    let mut stream = TcpStream::connect(server).await?;
    // over TCP, each message is preceded by its length
    let mut framed = (message.len() as u16).to_be_bytes().to_vec();
    framed.extend(message);
    stream.write_all(&framed).await?;

    let mut len = [0; 2];
    stream.read_exact(&mut len).await?;
    let mut response = vec![0; u16::from_be_bytes(len).into()];
    stream.read_exact(&mut response).await?;
    Ok(parse_response(&response, id, qtype)?)
}

/// A query id that differs between queries; TCP needs no unpredictable ids.
fn query_id() -> u16 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    (nanos ^ (nanos >> 16)) as u16
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

/// A non-recursive query for `name`'s records of type `qtype`.
fn encode_query(id: u16, name: &str, qtype: u16) -> io::Result<Vec<u8>> {
    let mut message = Vec::with_capacity(18 + name.len());
    message.extend(id.to_be_bytes());
    message.extend([0, 0]); // standard query, recursion not desired
    message.extend([0, 1, 0, 0, 0, 0, 0, 0]); // one question, no other records
    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid hostname {name:?}"),
            ));
        }
        message.push(label.len() as u8);
        message.extend(label.as_bytes());
    }
    message.push(0);
    message.extend(qtype.to_be_bytes());
    message.extend(CLASS_IN.to_be_bytes());
    Ok(message)
}

/// The addresses of type `qtype` in the answer to query `id`.
///
/// Only authoritative answers without errors are accepted; No-IP answers
/// unknown hostnames with no records rather than an error.
fn parse_response(message: &[u8], id: u16, qtype: u16) -> io::Result<Vec<IpAddr>> {
    let u16_at = |pos: usize| -> io::Result<u16> {
        message
            .get(pos..pos + 2)
            .map(|b| u16::from_be_bytes([b[0], b[1]]))
            .ok_or_else(|| invalid("truncated dns message"))
    };

    if u16_at(0)? != id {
        return Err(invalid("dns answer to another query"));
    }
    let flags = u16_at(2)?;
    if flags & 0x8000 == 0 {
        return Err(invalid("dns message is not a response"));
    }
    if flags & 0x0400 == 0 {
        return Err(invalid("dns answer is not authoritative"));
    }
    if flags & 0x0200 != 0 {
        return Err(invalid("dns answer is truncated"));
    }
    let rcode = flags & 0x000f;
    if rcode != 0 {
        return Err(invalid(format!("dns error, rcode {rcode}")));
    }

    let questions = u16_at(4)?;
    let answers = u16_at(6)?;
    let mut pos = 12;
    for _ in 0..questions {
        pos = skip_name(message, pos)? + 4; // type and class
    }

    let mut ips = vec![];
    for _ in 0..answers {
        pos = skip_name(message, pos)?;
        let rtype = u16_at(pos)?;
        let class = u16_at(pos + 2)?;
        let len = usize::from(u16_at(pos + 8)?); // after the 4-byte TTL
        let data = message
            .get(pos + 10..pos + 10 + len)
            .ok_or_else(|| invalid("truncated dns message"))?;
        pos += 10 + len;

        if class != CLASS_IN || rtype != qtype {
            continue; // e.g. a CNAME
        }
        match (rtype, data.len()) {
            (TYPE_A, 4) => ips.push(Ipv4Addr::from(<[u8; 4]>::try_from(data).unwrap()).into()),
            (TYPE_AAAA, 16) => ips.push(Ipv6Addr::from(<[u8; 16]>::try_from(data).unwrap()).into()),
            _ => return Err(invalid("malformed address record")),
        }
    }
    Ok(ips)
}

/// The position after the (possibly compressed) name at `pos`.
fn skip_name(message: &[u8], mut pos: usize) -> io::Result<usize> {
    loop {
        let len = *message
            .get(pos)
            .ok_or_else(|| invalid("truncated dns message"))?;
        match len {
            0 => return Ok(pos + 1),
            // a pointer ends the name
            l if l & 0xc0 == 0xc0 => return Ok(pos + 2),
            l if l & 0xc0 == 0 => pos += 1 + usize::from(l),
            _ => return Err(invalid("malformed dns name")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: u16 = 0x1234;

    /// A response to `encode_query(ID, "h.ddns.net", qtype)` with `flags` and
    /// `answers`, each `(type, rdata)` named by a pointer to the question.
    fn response(flags: u16, qtype: u16, answers: &[(u16, &[u8])]) -> Vec<u8> {
        let mut message = encode_query(ID, "h.ddns.net", qtype).unwrap();
        message[2..4].copy_from_slice(&flags.to_be_bytes());
        message[6..8].copy_from_slice(&(answers.len() as u16).to_be_bytes());
        for (rtype, data) in answers {
            message.extend([0xc0, 12]); // the question's name
            message.extend(rtype.to_be_bytes());
            message.extend(CLASS_IN.to_be_bytes());
            message.extend(60u32.to_be_bytes());
            message.extend((data.len() as u16).to_be_bytes());
            message.extend(*data);
        }
        message
    }

    const AUTHORITATIVE: u16 = 0x8400;

    #[test]
    fn encodes_query() {
        let message = encode_query(ID, "h.ddns.net.", TYPE_AAAA).unwrap();
        assert_eq!(
            message,
            [
                &[0x12, 0x34, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0][..],
                b"\x01h\x04ddns\x03net\x00",
                &[0, 28, 0, 1],
            ]
            .concat()
        );
        assert!(encode_query(ID, "a..b", TYPE_A).is_err());
    }

    #[test]
    fn parses_addresses() {
        let cname: &[u8] = &[0xc0, 12];
        let message = response(
            AUTHORITATIVE,
            TYPE_A,
            &[
                (5, cname),
                (TYPE_A, &[192, 0, 2, 1]),
                (TYPE_A, &[192, 0, 2, 2]),
            ],
        );
        assert_eq!(
            parse_response(&message, ID, TYPE_A).unwrap(),
            vec![IpAddr::from([192, 0, 2, 1]), IpAddr::from([192, 0, 2, 2])]
        );

        let v6 = "2001:db8::1".parse::<Ipv6Addr>().unwrap().octets();
        let message = response(AUTHORITATIVE, TYPE_AAAA, &[(TYPE_AAAA, &v6)]);
        assert_eq!(
            parse_response(&message, ID, TYPE_AAAA).unwrap(),
            vec![IpAddr::from(v6)]
        );
    }

    #[test]
    fn no_records() {
        let message = response(AUTHORITATIVE, TYPE_AAAA, &[]);
        assert!(parse_response(&message, ID, TYPE_AAAA).unwrap().is_empty());
    }

    #[test]
    fn rejects_bad_responses() {
        let a: &[u8] = &[192, 0, 2, 1];
        let reject =
            |message: &[u8], id: u16| parse_response(message, id, TYPE_A).unwrap_err().to_string();
        let ok = response(AUTHORITATIVE, TYPE_A, &[(TYPE_A, a)]);
        assert!(reject(&ok, ID + 1).contains("another query"));
        // e.g. from a resolver intercepting the query
        let recursive = response(0x8080, TYPE_A, &[(TYPE_A, a)]);
        assert!(reject(&recursive, ID).contains("not authoritative"));
        let refused = response(AUTHORITATIVE | 5, TYPE_A, &[]);
        assert!(reject(&refused, ID).contains("rcode 5"));
        assert!(reject(&ok[..ok.len() - 1], ID).contains("truncated"));
        let bad_length = response(AUTHORITATIVE, TYPE_A, &[(TYPE_A, &[192, 0, 2])]);
        assert!(reject(&bad_length, ID).contains("malformed"));
    }

    #[tokio::test]
    #[ignore = "needs network"]
    async fn looks_up_no_ip_domain() {
        // the apex of one of No-IP's hostname domains
        let ips = lookup("ddns.net").await.unwrap();
        eprintln!("ddns.net: {ips:?}");
        assert!(!ips.is_empty());
    }
}
