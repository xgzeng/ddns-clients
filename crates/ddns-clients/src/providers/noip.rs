//! [No-IP](https://www.noip.com/) dynamic DNS provider, using its
//! [update API](https://www.noip.com/integrate/request).

mod dns;

use std::{fmt, net::IpAddr, time::Duration};

use async_trait::async_trait;

use super::DynDnsProvider;
use crate::{Error, Result};

const UPDATE_URL: &str = "https://dynupdate.no-ip.com/nic/update";

/// How long No-IP asks clients to wait after a server error.
const RETRY_AFTER: Duration = Duration::from_secs(30 * 60);

const DEFAULT_USER_AGENT: &str = concat!("ddns-clients ddns-clients/", env!("CARGO_PKG_VERSION"));

/// Updates No-IP hostnames with an account's username and password (or a
/// DDNS key).
///
/// - A hostname has at most one A and one AAAA record. Records cannot be
///   deleted, and re-pointing cannot change their type (A ↔ AAAA); such
///   operations fail with [`Error::Unsupported`].
/// - The update API cannot read records, so the addresses are read from
///   No-IP's nameservers (`nf1`–`nf5.no-ip.com`) over TCP. If none of them
///   answers, e.g. for a domain they don't serve, they are read through the
///   system resolver, whose answer may be cached or overridden. They are
///   cached, together with the addresses set by updates, until
///   [`refresh`](DynDnsProvider::refresh) or a failed update.
/// - The TTL of an update is ignored.
/// - Errors that need user intervention (bad credentials, unknown hostname,
///   blocked client) are [`Error::Rejected`], and No-IP requires clients to
///   stop updating until they are fixed. Server errors are
///   [`Error::Unavailable`] with a 30 minute retry delay.
pub struct NoIpProvider {
    client: reqwest::Client,
    username: String,
    password: String,
    hostname: String,
    /// The hostname's addresses, as last read or set; `None` when unknown.
    known: Option<Vec<IpAddr>>,
}

/// An error response from the No-IP update API.
///
/// Returned inside [`Error::Rejected`], [`Error::Unavailable`] or
/// [`Error::Provider`]; use `downcast_ref` to inspect it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum NoIpError {
    /// `nohost`: the hostname does not exist in this account.
    NoHost,
    /// `badauth`: invalid username or password.
    BadAuth,
    /// `badagent`: this client has been disabled.
    BadAgent,
    /// `!donator`: the request used a feature the account lacks.
    NotDonator,
    /// `abuse`: the account is blocked from updating.
    Abuse,
    /// `911` or an HTTP 5xx status: a server-side error.
    ServerError,
    /// A response this client does not understand.
    Unexpected { status: u16, body: String },
}

impl fmt::Display for NoIpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NoIpError::NoHost => f.write_str("nohost: hostname not found in this account"),
            NoIpError::BadAuth => f.write_str("badauth: invalid username or password"),
            NoIpError::BadAgent => f.write_str("badagent: client disabled by No-IP"),
            NoIpError::NotDonator => {
                f.write_str("!donator: feature not available for this account")
            }
            NoIpError::Abuse => f.write_str("abuse: account blocked from updating"),
            NoIpError::ServerError => f.write_str("911: No-IP server error"),
            NoIpError::Unexpected { status, body } => {
                write!(f, "HTTP {status}: unexpected response {body:?}")
            }
        }
    }
}

impl std::error::Error for NoIpError {}

/// Interprets the response to an update of a single hostname to `sent`.
///
/// A success must echo the sent addresses; No-IP has been seen answering
/// `nochg <client ip>` instead of `badauth` after repeated failed logins.
fn parse_response(status: u16, body: &str, sent: &[IpAddr]) -> Result<()> {
    let line = body.lines().next().unwrap_or_default().trim();
    let unexpected = || {
        Error::provider(NoIpError::Unexpected {
            status,
            body: line.to_string(),
        })
    };
    let (code, echoed) = line.split_once(' ').unwrap_or((line, ""));
    let err = match code {
        "good" | "nochg" => {
            let echoed: Vec<IpAddr> = echoed
                .split(',')
                .map(|ip| ip.trim().parse())
                .collect::<std::result::Result<_, _>>()
                .map_err(|_| unexpected())?;
            if echoed.len() != sent.len() || !echoed.iter().all(|ip| sent.contains(ip)) {
                return Err(unexpected());
            }
            return Ok(());
        }
        "nohost" => NoIpError::NoHost,
        "badauth" => NoIpError::BadAuth,
        "badagent" => NoIpError::BadAgent,
        "!donator" => NoIpError::NotDonator,
        "abuse" => NoIpError::Abuse,
        "911" => return Err(Error::unavailable(RETRY_AFTER, NoIpError::ServerError)),
        _ if status >= 500 => return Err(Error::unavailable(RETRY_AFTER, NoIpError::ServerError)),
        _ => return Err(unexpected()),
    };
    Err(Error::rejected(err))
}

/// Name of `ip`'s record type.
fn record_type(ip: &IpAddr) -> &'static str {
    if ip.is_ipv4() { "A" } else { "AAAA" }
}

/// `current` with `ip` added, IPv4 first; a hostname has at most one record
/// per family.
fn added(current: &[IpAddr], ip: IpAddr) -> Result<Vec<IpAddr>> {
    if current.iter().any(|c| c.is_ipv4() == ip.is_ipv4()) {
        return Err(Error::Unsupported(format!(
            "No-IP hostnames have at most one {} record",
            record_type(&ip)
        )));
    }
    let mut ips = current.to_vec();
    ips.push(ip);
    ips.sort_by_key(IpAddr::is_ipv6);
    Ok(ips)
}

/// `current` with `old` re-pointed to `new`; No-IP cannot change a record's
/// type.
fn replaced(domain: &str, current: &[IpAddr], old: IpAddr, new: IpAddr) -> Result<Vec<IpAddr>> {
    if !current.contains(&old) {
        return Err(Error::RecordNotFound {
            domain: domain.to_string(),
            ip: old,
        });
    }
    if old.is_ipv4() != new.is_ipv4() {
        return Err(Error::Unsupported(format!(
            "No-IP cannot change an {} record to {}",
            record_type(&old),
            record_type(&new)
        )));
    }
    Ok(current
        .iter()
        .map(|ip| if *ip == old { new } else { *ip })
        .collect())
}

impl NoIpProvider {
    /// Creates a provider for `hostname`, authenticating with `username` and
    /// `password`.
    pub fn new(
        username: impl Into<String>,
        password: impl Into<String>,
        hostname: impl Into<String>,
    ) -> Result<Self> {
        Self::with_user_agent(username, password, hostname, DEFAULT_USER_AGENT)
    }

    /// Like [`new`](Self::new), but identifies as `user_agent`.
    ///
    /// No-IP asks clients to send `Company NameOfProgram/Version
    /// maintainer-contact@example.com` and may block clients that don't.
    pub fn with_user_agent(
        username: impl Into<String>,
        password: impl Into<String>,
        hostname: impl Into<String>,
        user_agent: &str,
    ) -> Result<Self> {
        let client = reqwest::Client::builder().user_agent(user_agent).build()?;
        Ok(NoIpProvider {
            client,
            username: username.into(),
            password: password.into(),
            hostname: hostname.into(),
            known: None,
        })
    }

    /// The hostname's addresses, from the cache or else looked up.
    async fn addresses(&mut self) -> Result<Vec<IpAddr>> {
        if let Some(ips) = &self.known {
            return Ok(ips.clone());
        }
        let ips = self.lookup().await?;
        log::debug!("{}: addresses {ips:?}", self.hostname);
        self.known = Some(ips.clone());
        Ok(ips)
    }

    /// The hostname's addresses from No-IP's nameservers, or else the system
    /// resolver.
    async fn lookup(&self) -> Result<Vec<IpAddr>> {
        let hostname = &self.hostname;
        match dns::lookup(hostname).await {
            Ok(ips) => return Ok(ips),
            Err(err) => log::warn!(
                "{hostname}: no answer from No-IP's nameservers ({err}), using the system resolver"
            ),
        }
        let mut ips = vec![];
        for addr in tokio::net::lookup_host((hostname.as_str(), 0)).await? {
            if !ips.contains(&addr.ip()) {
                ips.push(addr.ip());
            }
        }
        Ok(ips)
    }

    /// Sets the hostname's addresses to `ips`, at most one per family.
    async fn set(&mut self, ips: Vec<IpAddr>) -> Result<()> {
        let myip = ips
            .iter()
            .map(IpAddr::to_string)
            .collect::<Vec<_>>()
            .join(",");

        // forget the cached addresses until the update is known to succeed
        self.known = None;
        let response = self
            .client
            .get(UPDATE_URL)
            .basic_auth(&self.username, Some(&self.password))
            .query(&[("hostname", self.hostname.as_str()), ("myip", &myip)])
            .send()
            .await?;
        let status = response.status().as_u16();
        let body = response.text().await?;
        parse_response(status, &body, &ips)?;
        log::debug!("{}: set addresses to {myip}", self.hostname);

        self.known = Some(ips);
        Ok(())
    }
}

#[async_trait]
impl DynDnsProvider for NoIpProvider {
    fn domain(&self) -> &str {
        &self.hostname
    }

    async fn list(&mut self) -> Result<Vec<IpAddr>> {
        self.addresses().await
    }

    async fn refresh(&mut self) -> Result<()> {
        self.known = None;
        self.addresses().await.map(drop)
    }

    /// Sets the hostname's address of `ip`'s family; fails if it already
    /// has one.
    async fn add(&mut self, ip: IpAddr, _ttl: Option<u32>) -> Result<()> {
        let current = self.addresses().await?;
        let ips = added(&current, ip)?;
        self.set(ips).await
    }

    /// Changes the hostname's address `old` to `new` of the same family.
    async fn replace(&mut self, old: IpAddr, new: IpAddr, _ttl: Option<u32>) -> Result<()> {
        let current = self.addresses().await?;
        let ips = replaced(&self.hostname, &current, old, new)?;
        // No-IP may block clients that send updates without changes
        if ips == current {
            return Ok(());
        }
        self.set(ips).await
    }

    /// Always fails: No-IP records cannot be removed.
    async fn delete(&mut self, ip: IpAddr) -> Result<()> {
        Err(Error::Unsupported(format!(
            "No-IP cannot remove the {} record of {}",
            record_type(&ip),
            self.hostname
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn ips(list: &[&str]) -> Vec<IpAddr> {
        list.iter().map(|s| ip(s)).collect()
    }

    fn inner(err: &Error) -> &NoIpError {
        let source = match err {
            Error::Rejected(source) | Error::Provider(source) => source,
            Error::Unavailable { source, .. } => source,
            err => panic!("unexpected error {err:?}"),
        };
        source.downcast_ref().unwrap()
    }

    #[test]
    fn parse_success() {
        let v4 = ip("192.0.2.1");
        let v6 = ip("2001:db8::1");
        assert!(parse_response(200, "good 192.0.2.1\r\n", &[v4]).is_ok());
        assert!(parse_response(200, "nochg 192.0.2.1,2001:db8::1", &[v4, v6]).is_ok());
        assert!(parse_response(200, "good 2001:db8::1", &[v6]).is_ok());
    }

    #[test]
    fn parse_other_addresses() {
        let sent = [ip("192.0.2.1"), ip("2001:db8::1")];
        for body in [
            "nochg 198.51.100.7",
            "good 192.0.2.1",
            "good",
            "good 192.0.2.1,x",
        ] {
            let err = parse_response(200, body, &sent).unwrap_err();
            assert!(
                matches!(inner(&err), NoIpError::Unexpected { .. }),
                "{body}: {err:?}"
            );
        }
    }

    #[test]
    fn parse_rejected() {
        for (body, expected) in [
            ("nohost", NoIpError::NoHost),
            ("badauth", NoIpError::BadAuth),
            ("badagent", NoIpError::BadAgent),
            ("!donator", NoIpError::NotDonator),
            ("abuse\n", NoIpError::Abuse),
        ] {
            let err = parse_response(401, body, &[]).unwrap_err();
            assert!(matches!(err, Error::Rejected(_)), "{body}: {err:?}");
            assert_eq!(inner(&err), &expected);
        }
    }

    #[test]
    fn parse_unavailable() {
        for (status, body) in [(200, "911"), (503, "<html>")] {
            let err = parse_response(status, body, &[]).unwrap_err();
            let Error::Unavailable { retry_after, .. } = &err else {
                panic!("{err:?}");
            };
            assert_eq!(*retry_after, RETRY_AFTER);
            assert_eq!(inner(&err), &NoIpError::ServerError);
        }
    }

    #[test]
    fn parse_unexpected() {
        let err = parse_response(200, "what", &[]).unwrap_err();
        assert!(matches!(err, Error::Provider(_)));
        assert_eq!(
            err.chain().to_string(),
            r#"dns provider error: HTTP 200: unexpected response "what""#
        );
    }

    #[test]
    fn adds_missing_family() {
        assert_eq!(
            added(&ips(&["2001:db8::1"]), ip("192.0.2.1")).unwrap(),
            ips(&["192.0.2.1", "2001:db8::1"])
        );
        assert_eq!(
            added(&[], ip("2001:db8::1")).unwrap(),
            ips(&["2001:db8::1"])
        );
    }

    #[test]
    fn add_rejects_second_per_family() {
        let err = added(&ips(&["192.0.2.1"]), ip("192.0.2.2")).unwrap_err();
        assert!(matches!(err, Error::Unsupported(_)), "{err:?}");
        assert!(err.to_string().contains("one A record"), "{err}");
    }

    #[test]
    fn replaces_within_family() {
        // the other family is sent unchanged
        assert_eq!(
            replaced(
                "h.ddns.net",
                &ips(&["192.0.2.1", "2001:db8::1"]),
                ip("192.0.2.1"),
                ip("192.0.2.2")
            )
            .unwrap(),
            ips(&["192.0.2.2", "2001:db8::1"])
        );
    }

    #[test]
    fn replace_rejects_missing_and_type_change() {
        let current = ips(&["192.0.2.1"]);
        let err = replaced("h.ddns.net", &current, ip("192.0.2.9"), ip("192.0.2.2")).unwrap_err();
        assert!(matches!(err, Error::RecordNotFound { .. }), "{err:?}");
        let err = replaced("h.ddns.net", &current, ip("192.0.2.1"), ip("2001:db8::1")).unwrap_err();
        assert!(err.to_string().contains("A record to AAAA"), "{err}");
    }
}
