//! [No-IP](https://www.noip.com/) dynamic DNS provider, using its
//! [update API](https://www.noip.com/integrate/request).

use std::{collections::HashMap, fmt, net::IpAddr, time::Duration};

use async_trait::async_trait;

use super::{ChangePlan, DynDnsProvider, RecordUpdate, UpdateBuilder, UpdateSummary, plan_changes};
use crate::{Error, Result};

const UPDATE_URL: &str = "https://dynupdate.no-ip.com/nic/update";

/// How long No-IP asks clients to wait after a server error.
const RETRY_AFTER: Duration = Duration::from_secs(30 * 60);

const DEFAULT_USER_AGENT: &str = concat!("ddns-clients ddns-clients/", env!("CARGO_PKG_VERSION"));

/// Updates No-IP hostnames with an account's username and password (or a
/// DDNS key).
///
/// - A hostname has at most one A and one AAAA record, and records cannot be
///   removed, only re-pointed; other updates fail with
///   [`Error::Unsupported`].
/// - The update API cannot read records, so [`list`](DynDnsProvider::list)
///   returns the addresses set by this provider's last successful update,
///   or else resolves the hostname through the system resolver.
/// - The TTL of an update is ignored.
/// - Errors that need user intervention (bad credentials, unknown hostname,
///   blocked client) are [`Error::Rejected`], and No-IP requires clients to
///   stop updating until they are fixed. Server errors are
///   [`Error::Unavailable`] with a 30 minute retry delay.
pub struct NoIpProvider {
    client: reqwest::Client,
    username: String,
    password: String,
    known: HashMap<String, Vec<IpAddr>>, // addresses set by the last update, per hostname
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

/// The addresses after carrying out `plan` on `existing`, IPv4 first.
///
/// Fails if they need more than one address per family, or the removal of
/// a family's last address.
fn planned_addresses(existing: &[IpAddr], plan: &ChangePlan<IpAddr>) -> Result<Vec<IpAddr>> {
    let changed =
        |ip: &IpAddr| plan.delete.contains(ip) || plan.repoint.iter().any(|(id, _)| id == ip);
    let mut ips: Vec<IpAddr> = existing.iter().copied().filter(|ip| !changed(ip)).collect();
    ips.extend(plan.repoint.iter().map(|(_, ip)| *ip));
    ips.extend(&plan.create);
    ips.sort_by_key(|ip| ip.is_ipv6());

    for (name, is_family) in [
        ("A", IpAddr::is_ipv4 as fn(&IpAddr) -> bool),
        ("AAAA", IpAddr::is_ipv6),
    ] {
        let count = ips.iter().filter(|ip| is_family(ip)).count();
        if count > 1 {
            return Err(Error::Unsupported(format!(
                "No-IP hostnames have at most one {name} record"
            )));
        }
        if count == 0 && existing.iter().any(is_family) {
            return Err(Error::Unsupported(format!(
                "No-IP cannot remove the {name} record of a hostname"
            )));
        }
    }
    Ok(ips)
}

impl NoIpProvider {
    /// Creates a provider authenticating with `username` and `password`.
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Result<Self> {
        Self::with_user_agent(username, password, DEFAULT_USER_AGENT)
    }

    /// Like [`new`](Self::new), but identifies as `user_agent`.
    ///
    /// No-IP asks clients to send `Company NameOfProgram/Version
    /// maintainer-contact@example.com` and may block clients that don't.
    pub fn with_user_agent(
        username: impl Into<String>,
        password: impl Into<String>,
        user_agent: &str,
    ) -> Result<Self> {
        let client = reqwest::Client::builder().user_agent(user_agent).build()?;
        Ok(NoIpProvider {
            client,
            username: username.into(),
            password: password.into(),
            known: HashMap::new(),
        })
    }

    async fn addresses(&self, domain: &str) -> Result<Vec<IpAddr>> {
        if let Some(ips) = self.known.get(domain) {
            return Ok(ips.clone());
        }
        let mut ips = vec![];
        for addr in tokio::net::lookup_host((domain, 0)).await? {
            if !ips.contains(&addr.ip()) {
                ips.push(addr.ip());
            }
        }
        Ok(ips)
    }
}

#[async_trait]
impl DynDnsProvider for NoIpProvider {
    async fn list(&mut self, domain: &str) -> Result<Vec<IpAddr>> {
        self.addresses(domain).await
    }

    fn update<'a>(&'a mut self, domain: &str) -> UpdateBuilder<'a> {
        UpdateBuilder::new(self, domain)
    }

    async fn apply_update(&mut self, update: RecordUpdate) -> Result<UpdateSummary> {
        let existing = self.addresses(&update.domain).await?;
        let records: Vec<(IpAddr, IpAddr)> = existing.iter().map(|ip| (*ip, *ip)).collect();
        let plan = plan_changes(&records, &update);
        // No-IP may block clients that send updates without changes
        if plan.summary().is_unchanged() {
            return Ok(plan.summary());
        }
        let ips = planned_addresses(&existing, &plan)?;
        let myip = ips
            .iter()
            .map(IpAddr::to_string)
            .collect::<Vec<_>>()
            .join(",");

        // forget the cached addresses until the update is known to succeed
        self.known.remove(&update.domain);
        let response = self
            .client
            .get(UPDATE_URL)
            .basic_auth(&self.username, Some(&self.password))
            .query(&[("hostname", update.domain.as_str()), ("myip", &myip)])
            .send()
            .await?;
        let status = response.status().as_u16();
        let body = response.text().await?;
        parse_response(status, &body, &ips)?;
        log::debug!("{}: set addresses to {myip}", update.domain);

        self.known.insert(update.domain, ips);
        Ok(plan.summary())
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

    fn planned(existing: &[&str], add: &[&str], remove: &[&str]) -> Result<Vec<IpAddr>> {
        let existing = ips(existing);
        let records: Vec<_> = existing.iter().map(|ip| (*ip, *ip)).collect();
        let update = RecordUpdate {
            add: ips(add),
            remove: ips(remove),
            ..Default::default()
        };
        planned_addresses(&existing, &plan_changes(&records, &update))
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
    fn planned_replaces_and_adds() {
        assert_eq!(
            planned(
                &["192.0.2.1"],
                &["192.0.2.2", "2001:db8::1"],
                &["192.0.2.1"]
            )
            .unwrap(),
            ips(&["192.0.2.2", "2001:db8::1"])
        );
        // untouched families are sent unchanged
        assert_eq!(
            planned(
                &["2001:db8::1", "192.0.2.1"],
                &["192.0.2.2"],
                &["192.0.2.1"]
            )
            .unwrap(),
            ips(&["192.0.2.2", "2001:db8::1"])
        );
        assert_eq!(
            planned(&[], &["2001:db8::1"], &[]).unwrap(),
            ips(&["2001:db8::1"])
        );
    }

    #[test]
    fn planned_rejects_two_per_family() {
        let err = planned(&[], &["192.0.2.1", "192.0.2.2"], &[]).unwrap_err();
        assert!(matches!(err, Error::Unsupported(_)), "{err:?}");
    }

    #[test]
    fn planned_rejects_removal() {
        let err = planned(&["192.0.2.1", "2001:db8::1"], &[], &["2001:db8::1"]).unwrap_err();
        assert!(err.to_string().contains("AAAA"), "{err}");
    }
}
