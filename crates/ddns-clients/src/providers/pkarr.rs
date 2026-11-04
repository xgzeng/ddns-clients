//! [PKARR](https://pkdns.net) (Public-Key Addressable Resource Records)
//! provider: DNS records signed with an Ed25519 key, published on the
//! Mainline DHT and on PKARR relays.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{Context, Result, anyhow, bail};
use async_trait::async_trait;
use pkarr::{
    Client, Keypair, ResolvePolicy, SignedPacket,
    dns::{Name, ResourceRecord, rdata::RData},
    errors::ResolveError,
};

use super::{DynDnsProvider, warn_if_changed};

/// TTL of records added without one.
const DEFAULT_TTL: u32 = 300;

/// Publishes the address records of a name under a PKARR key.
///
/// - The domain is the key's z-base32 public key, or a name below it, e.g.
///   `home.<public key>`.
/// - All records of a key form one signed packet, which every operation
///   publishes again in full. Records of other names and types in the packet
///   are kept, unless [`keep_other_records`](Self::keep_other_records) is
///   turned off.
/// - The records are read from the network, and cached until
///   [`refresh_cache`](DynDnsProvider::refresh_cache) or a failed operation.
/// - DHT nodes drop packets after a few hours, so
///   [`refresh_cache`](DynDnsProvider::refresh_cache) also publishes the
///   packet it read again, re-signed; call it about every hour.
pub struct PkarrProvider {
    client: Client,
    keypair: Keypair,
    /// `<name>.<public key>`, or the public key itself.
    domain: String,
    keep_other_records: bool,
    /// The packet's records, as last read or published; `None` when unknown.
    records: Option<Records>,
}

/// The records of a packet.
#[derive(Debug, Clone, Default, PartialEq)]
struct Records {
    /// The domain's addresses, with their TTLs, in packet order.
    addrs: Vec<(IpAddr, u32)>,
    /// Every other record, kept as it is; empty unless `keep_other_records`.
    others: Vec<ResourceRecord<'static>>,
}

impl Records {
    fn ips(&self) -> Vec<IpAddr> {
        self.addrs.iter().map(|(ip, _)| *ip).collect()
    }

    /// Index of a record with `ip`.
    fn position(&self, domain: &str, ip: IpAddr) -> Result<usize> {
        self.addrs
            .iter()
            .position(|(addr, _)| *addr == ip)
            .ok_or_else(|| anyhow!("{domain} has no record for {ip}"))
    }
}

/// Parses a secret key written as 64 hex digits, as PKARR's key files hold.
fn parse_secret_key(hex: &str) -> Result<[u8; 32]> {
    let hex = hex.trim();
    if hex.len() != 64 || !hex.is_ascii() {
        bail!("pkarr secret key must be 64 hex digits");
    }
    let mut key = [0; 32];
    for (byte, digits) in key.iter_mut().zip(hex.as_bytes().chunks(2)) {
        // ASCII, so the chunk is a valid str
        let digits = std::str::from_utf8(digits).unwrap_or_default();
        *byte = u8::from_str_radix(digits, 16).context("pkarr secret key must be 64 hex digits")?;
    }
    Ok(key)
}

/// Generates a random secret key, returned as 64 hex digits with its
/// z-base32 public key.
pub fn generate_secret_key() -> (String, String) {
    let keypair = Keypair::random();
    let secret = keypair
        .secret_key()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    (secret, keypair.public_key().to_z32())
}

/// The full domain of `name` under the key `origin`: the key itself for an
/// empty name or `@`, else `<name>.<origin>` unless it already ends with it.
fn full_domain(name: &str, origin: &str) -> String {
    let name = name.trim_end_matches('.');
    if name.is_empty() || name == "@" || name.eq_ignore_ascii_case(origin) {
        return origin.to_string();
    }
    let lower = name.to_ascii_lowercase();
    if lower.ends_with(&format!(".{origin}")) {
        return lower;
    }
    format!("{lower}.{origin}")
}

/// The address of an A or AAAA record.
fn address(record: &ResourceRecord<'_>) -> Option<IpAddr> {
    match &record.rdata {
        RData::A(a) => Some(Ipv4Addr::from(a.address).into()),
        RData::AAAA(aaaa) => Some(Ipv6Addr::from(aaaa.address).into()),
        _ => None,
    }
}

/// Splits the records of `packet` into the addresses of `domain` and the
/// others, which are dropped unless `keep_others`.
fn records_of(packet: &SignedPacket, domain: &str, keep_others: bool) -> Records {
    let mut records = Records::default();
    for record in packet.all_resource_records() {
        match address(record) {
            Some(ip) if record.name.to_string().eq_ignore_ascii_case(domain) => {
                records.addrs.push((ip, record.ttl));
            }
            _ if keep_others => records.others.push(record.clone().into_owned()),
            _ => {}
        }
    }
    records
}

/// A packet of `records`, with `domain`'s addresses, signed with `keypair`.
fn sign(keypair: &Keypair, domain: &str, records: &Records) -> Result<SignedPacket> {
    let name = Name::new(domain)?;
    let mut builder = SignedPacket::builder();
    for record in &records.others {
        builder = builder.record(record.clone());
    }
    for &(ip, ttl) in &records.addrs {
        builder = builder.address(name.clone(), ip, ttl);
    }
    Ok(builder.sign(keypair)?)
}

impl PkarrProvider {
    /// Creates a provider for `name` under the key `secret_key` (64 hex
    /// digits): the key's own records for an empty name or `@`, else
    /// `<name>.<public key>`.
    ///
    /// `relays` are the PKARR relay URLs to publish to and read from besides
    /// the DHT; `None` uses the default relays, and an empty list only the DHT.
    ///
    /// Starts the DHT client, which joins the DHT in the background, and logs
    /// the public key.
    pub fn new(secret_key: &str, name: &str, relays: Option<&[String]>) -> Result<Self> {
        let keypair = Keypair::from_secret_key(&parse_secret_key(secret_key)?);
        let public_key = keypair.public_key().to_z32();
        let domain = full_domain(name, &public_key);
        Name::new(&domain).with_context(|| format!("invalid pkarr name {name:?}"))?;
        log::info!("{domain}: pkarr public key {public_key}");

        let mut builder = Client::builder();
        match relays {
            None => {}
            Some([]) => {
                builder.no_relays();
            }
            Some(relays) => {
                builder.relays(relays)?;
            }
        }
        Ok(PkarrProvider {
            client: builder.build()?,
            keypair,
            domain,
            keep_other_records: true,
            records: None,
        })
    }

    /// Whether records of other names and types in the key's packet are kept
    /// when publishing it (default `true`); if not, they are removed.
    pub fn keep_other_records(mut self, keep: bool) -> Self {
        self.keep_other_records = keep;
        self
    }

    /// The packet's records, from the cache or else read.
    async fn records(&mut self) -> Result<Records> {
        if let Some(records) = &self.records {
            return Ok(records.clone());
        }
        let records = self.read().await?;
        log::debug!("{}: addresses {:?}", self.domain, records.ips());
        self.records = Some(records.clone());
        Ok(records)
    }

    /// Reads the packet from the network; none found means no records.
    async fn read(&self) -> Result<Records> {
        let key = self.keypair.public_key();
        match self.client.resolve(&key, ResolvePolicy::NetworkOnly).await {
            Ok(packet) => Ok(records_of(&packet, &self.domain, self.keep_other_records)),
            Err(ResolveError::NotFound) => Ok(Records::default()),
            Err(err) => {
                Err(anyhow!(err).context(format!("{}: reading the pkarr packet", self.domain)))
            }
        }
    }

    /// Signs and publishes a packet of `records`.
    async fn publish(&mut self, records: Records) -> Result<()> {
        // forget the cached records until the publish is known to succeed
        self.records = None;
        let packet = sign(&self.keypair, &self.domain, &records)?;
        self.client
            .publish(&packet)
            .await
            .with_context(|| format!("{}: publishing the pkarr packet", self.domain))?;
        self.records = Some(records);
        Ok(())
    }
}

#[async_trait]
impl DynDnsProvider for PkarrProvider {
    fn domain(&self) -> &str {
        &self.domain
    }

    async fn list(&mut self) -> Result<Vec<IpAddr>> {
        Ok(self.records().await?.ips())
    }

    /// Reads the packet again and publishes it, re-signed, so that it stays on
    /// the DHT.
    async fn refresh_cache(&mut self) -> Result<()> {
        let cached = self.records.take();
        let records = self.read().await?;
        if let Some(cached) = cached {
            warn_if_changed(&self.domain, &cached.ips(), &records.ips());
        }
        if records == Records::default() {
            // nothing to keep alive
            self.records = Some(records);
            return Ok(());
        }
        self.publish(records).await?;
        log::debug!("{}: republished the pkarr packet", self.domain);
        Ok(())
    }

    async fn add(&mut self, ip: IpAddr, ttl: Option<u32>) -> Result<()> {
        let mut records = self.records().await?;
        records.addrs.push((ip, ttl.unwrap_or(DEFAULT_TTL)));
        self.publish(records).await
    }

    async fn replace(&mut self, old: IpAddr, new: IpAddr, ttl: Option<u32>) -> Result<()> {
        let mut records = self.records().await?;
        let i = records.position(&self.domain, old)?;
        let ttl = ttl.unwrap_or(records.addrs[i].1);
        records.addrs[i] = (new, ttl);
        self.publish(records).await
    }

    async fn delete(&mut self, ip: IpAddr) -> Result<()> {
        let mut records = self.records().await?;
        let i = records.position(&self.domain, ip)?;
        records.addrs.remove(i);
        self.publish(records).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn keypair() -> Keypair {
        Keypair::from_secret_key(&parse_secret_key(SECRET).unwrap())
    }

    #[test]
    fn parses_secret_key() {
        let key = parse_secret_key(&format!(" {} \n", SECRET.to_uppercase())).unwrap();
        assert_eq!(key[..3], [0x01, 0x23, 0x45]);
        assert!(parse_secret_key(&SECRET[2..]).is_err());
        assert!(parse_secret_key(&SECRET.replace('0', "g")).is_err());
        assert!(parse_secret_key(&SECRET.replace("01", "é")).is_err());
    }

    #[test]
    fn generates_secret_key() {
        let (secret, public) = generate_secret_key();
        let keypair = Keypair::from_secret_key(&parse_secret_key(&secret).unwrap());
        assert_eq!(keypair.public_key().to_z32(), public);
        assert_ne!(generate_secret_key().0, secret);
    }

    #[test]
    fn full_domains() {
        let origin = "abc";
        assert_eq!(full_domain("", origin), "abc");
        assert_eq!(full_domain("@", origin), "abc");
        assert_eq!(full_domain("abc", origin), "abc");
        assert_eq!(full_domain("Home", origin), "home.abc");
        assert_eq!(full_domain("home.abc.", origin), "home.abc");
        assert_eq!(full_domain("*.lan", origin), "*.lan.abc");
    }

    #[test]
    fn splits_records() {
        let keypair = keypair();
        let origin = keypair.public_key().to_z32();
        let domain = format!("home.{origin}");
        let (v4, v6): (IpAddr, IpAddr) =
            ("192.0.2.1".parse().unwrap(), "2001:db8::1".parse().unwrap());
        let packet = SignedPacket::builder()
            .address("home".try_into().unwrap(), v4, 60)
            .txt("_note".try_into().unwrap(), "hi".try_into().unwrap(), 60)
            .address(".".try_into().unwrap(), v4, 60)
            .address("home".try_into().unwrap(), v6, 120)
            .sign(&keypair)
            .unwrap();

        let records = records_of(&packet, &domain, true);
        assert_eq!(records.addrs, [(v4, 60), (v6, 120)]);
        // the TXT record, and the apex's A record
        assert_eq!(records.others.len(), 2);

        let records = records_of(&packet, &domain, false);
        assert_eq!(records.addrs, [(v4, 60), (v6, 120)]);
        assert!(records.others.is_empty());

        // the apex
        let records = records_of(&packet, &origin, false);
        assert_eq!(records.addrs, [(v4, 60)]);
    }

    #[test]
    fn signs_records() {
        let keypair = keypair();
        let domain = format!("home.{}", keypair.public_key().to_z32());
        let read = records_of(
            &SignedPacket::builder()
                .txt("_note".try_into().unwrap(), "hi".try_into().unwrap(), 60)
                .sign(&keypair)
                .unwrap(),
            &domain,
            true,
        );
        let records = Records {
            addrs: vec![
                ("2001:db8::1".parse().unwrap(), 120),
                ("192.0.2.1".parse().unwrap(), 60),
            ],
            others: read.others,
        };
        let packet = sign(&keypair, &domain, &records).unwrap();
        assert_eq!(records_of(&packet, &domain, true), records);
    }
}
