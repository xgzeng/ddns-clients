//! [Cloudflare](https://www.cloudflare.com/) DNS provider, using the
//! [v4 REST API](https://developers.cloudflare.com/api/) directly.

use std::{fmt, net::IpAddr};

use async_trait::async_trait;
use reqwest::RequestBuilder;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use super::{DynDnsProvider, RecordUpdate, UpdateBuilder, UpdateSummary, plan_changes};
use crate::{Error, Result};

const BASE_URL: &str = "https://api.cloudflare.com/client/v4";

/// Manages records of a single Cloudflare zone using an API token.
///
/// The token needs the `Zone:Read` and `DNS:Edit` permissions.
pub struct CloudflareProvider {
    client: reqwest::Client,
    api_token: String,
    zone_name: String,
    zone_id: Option<String>, // zone id cache
}

/// An error response from the Cloudflare API.
///
/// Returned inside [`Error::Provider`]; use `downcast_ref` to inspect it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudflareError {
    /// The HTTP status code.
    pub status: u16,
    /// The errors reported in the response body, if any.
    pub errors: Vec<ApiMessage>,
}

/// One entry of a Cloudflare API response's `errors` list.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ApiMessage {
    pub code: u32,
    pub message: String,
}

impl fmt::Display for CloudflareError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HTTP {}", self.status)?;
        for (i, err) in self.errors.iter().enumerate() {
            let sep = if i == 0 { ": " } else { "; " };
            write!(f, "{sep}{} {}", err.code, err.message)?;
        }
        Ok(())
    }
}

impl std::error::Error for CloudflareError {}

#[derive(Debug, Deserialize)]
struct Envelope<T> {
    success: bool,
    #[serde(default)]
    errors: Vec<ApiMessage>,
    result: Option<T>,
}

#[derive(Debug, Deserialize)]
struct Zone {
    id: String,
}

#[derive(Debug, Deserialize)]
struct DnsRecord {
    id: String,
    r#type: String,
    content: String,
}

#[derive(Debug, Deserialize)]
struct Deleted {}

#[derive(Serialize)]
struct RecordBody<'a> {
    r#type: &'static str,
    name: &'a str,
    content: IpAddr,
    #[serde(skip_serializing_if = "Option::is_none")]
    ttl: Option<u32>,
}

impl<'a> RecordBody<'a> {
    fn new(name: &'a str, ip: IpAddr, ttl: Option<u32>) -> Self {
        RecordBody {
            r#type: record_type(ip),
            name,
            content: ip,
            ttl,
        }
    }
}

fn record_type(ip: IpAddr) -> &'static str {
    match ip {
        IpAddr::V4(_) => "A",
        IpAddr::V6(_) => "AAAA",
    }
}

/// Extracts the `result` of a response, or the error it describes.
fn parse_response<T: DeserializeOwned>(status: u16, body: &str) -> Result<T> {
    let failure = |errors| Error::provider(CloudflareError { status, errors });
    let Ok(envelope) = serde_json::from_str::<Envelope<T>>(body) else {
        return Err(failure(vec![]));
    };
    match envelope.result {
        Some(result) if envelope.success && (200..300).contains(&status) => Ok(result),
        _ => Err(failure(envelope.errors)),
    }
}

/// The id and address of an A/AAAA record; `None` for other types.
fn address_record(record: DnsRecord) -> Option<(String, IpAddr)> {
    let ip = match record.r#type.as_str() {
        "A" | "AAAA" => record.content.parse().ok()?,
        _ => return None,
    };
    Some((record.id, ip))
}

impl CloudflareProvider {
    /// Creates a provider for `zone_name`, authenticating with `api_token`.
    ///
    /// The zone id is looked up lazily on the first request.
    pub fn new(api_token: impl Into<String>, zone_name: impl Into<String>) -> Result<Self> {
        let client = reqwest::Client::builder()
            .user_agent(concat!("ddns-clients/", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(CloudflareProvider {
            client,
            api_token: api_token.into(),
            zone_name: zone_name.into(),
            zone_id: None,
        })
    }

    async fn call<T: DeserializeOwned>(&self, request: RequestBuilder) -> Result<T> {
        let response = request.bearer_auth(&self.api_token).send().await?;
        let status = response.status().as_u16();
        let body = response.text().await?;
        parse_response(status, &body)
    }

    async fn zone_id(&mut self) -> Result<String> {
        if let Some(zone_id) = &self.zone_id {
            return Ok(zone_id.clone());
        }

        let request = self
            .client
            .get(format!("{BASE_URL}/zones"))
            .query(&[("name", &self.zone_name)]);
        let zones: Vec<Zone> = self.call(request).await?;
        let Some(zone) = zones.into_iter().next() else {
            return Err(Error::ZoneNotFound(self.zone_name.clone()));
        };
        self.zone_id = Some(zone.id.clone());
        Ok(zone.id)
    }

    /// Ids and addresses of all A/AAAA records of `domain`.
    async fn address_records(&mut self, domain: &str) -> Result<Vec<(String, IpAddr)>> {
        let zone_id = self.zone_id().await?;
        let request = self
            .client
            .get(format!("{BASE_URL}/zones/{zone_id}/dns_records"))
            .query(&[("name", domain), ("per_page", "100")]);
        let records: Vec<DnsRecord> = self.call(request).await?;
        Ok(records.into_iter().filter_map(address_record).collect())
    }
}

#[async_trait]
impl DynDnsProvider for CloudflareProvider {
    async fn list(&mut self, domain: &str) -> Result<Vec<IpAddr>> {
        let records = self.address_records(domain).await?;
        Ok(records.into_iter().map(|(_, ip)| ip).collect())
    }

    fn update<'a>(&'a mut self, domain: &str) -> UpdateBuilder<'a> {
        UpdateBuilder::new(self, domain)
    }

    async fn apply_update(&mut self, update: RecordUpdate) -> Result<UpdateSummary> {
        let existing = self.address_records(&update.domain).await?;
        let plan = plan_changes(&existing, &update);
        let zone_id = self.zone_id().await?;
        let records_url = format!("{BASE_URL}/zones/{zone_id}/dns_records");

        for (id, ip) in &plan.repoint {
            // PATCH keeps fields we don't send, e.g. proxied, comment and tags
            let request = self
                .client
                .patch(format!("{records_url}/{id}"))
                .json(&RecordBody::new(&update.domain, *ip, update.ttl));
            let _: DnsRecord = self.call(request).await?;
            log::debug!("{}: re-pointed record {id} to {ip}", update.domain);
        }
        for id in &plan.delete {
            let request = self.client.delete(format!("{records_url}/{id}"));
            let _: Deleted = self.call(request).await?;
            log::debug!("{}: deleted record {id}", update.domain);
        }
        for ip in &plan.create {
            let request = self.client.post(&records_url).json(&RecordBody::new(
                &update.domain,
                *ip,
                update.ttl,
            ));
            let _: DnsRecord = self.call(request).await?;
            log::debug!("{}: created record for {ip}", update.domain);
        }

        Ok(plan.summary())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cloudflare_error(err: Error) -> CloudflareError {
        match err {
            Error::Provider(err) => err.downcast_ref::<CloudflareError>().unwrap().clone(),
            err => panic!("unexpected error {err:?}"),
        }
    }

    #[test]
    fn parse_success() {
        let body = r#"{"success":true,"errors":[],"messages":[],"result":[{"id":"z1","name":"example.com"}]}"#;
        let zones: Vec<Zone> = parse_response(200, body).unwrap();
        assert_eq!(zones[0].id, "z1");
    }

    #[test]
    fn parse_api_error() {
        let body = r#"{"success":false,"errors":[{"code":6003,"message":"Invalid request headers"},{"code":6111,"message":"Invalid format for Authorization header"}],"messages":[],"result":null}"#;
        let err = cloudflare_error(parse_response::<Vec<Zone>>(400, body).unwrap_err());
        assert_eq!(err.status, 400);
        assert_eq!(
            err.to_string(),
            "HTTP 400: 6003 Invalid request headers; 6111 Invalid format for Authorization header"
        );
    }

    #[test]
    fn parse_null_result() {
        let body = r#"{"success":true,"errors":[],"result":null}"#;
        let err = cloudflare_error(parse_response::<Vec<Zone>>(200, body).unwrap_err());
        assert_eq!(err.to_string(), "HTTP 200");
    }

    #[test]
    fn parse_error_status() {
        let body = r#"{"success":true,"errors":[],"result":[]}"#;
        assert!(parse_response::<Vec<Zone>>(500, body).is_err());
    }

    #[test]
    fn parse_non_json() {
        let err = cloudflare_error(parse_response::<Vec<Zone>>(502, "<html>").unwrap_err());
        assert_eq!(
            err,
            CloudflareError {
                status: 502,
                errors: vec![]
            }
        );
    }

    #[test]
    fn parse_delete() {
        let body = r#"{"success":true,"errors":[],"result":{"id":"r1"}}"#;
        assert!(parse_response::<Deleted>(200, body).is_ok());
    }

    #[test]
    fn record_body() {
        let body = RecordBody::new("h.example.com", "1.2.3.4".parse().unwrap(), Some(120));
        assert_eq!(
            serde_json::to_string(&body).unwrap(),
            r#"{"type":"A","name":"h.example.com","content":"1.2.3.4","ttl":120}"#
        );
        let body = RecordBody::new("h.example.com", "2001:db8::1".parse().unwrap(), None);
        assert_eq!(
            serde_json::to_string(&body).unwrap(),
            r#"{"type":"AAAA","name":"h.example.com","content":"2001:db8::1"}"#
        );
    }

    #[test]
    fn address_records() {
        let body = r#"{"success":true,"errors":[],"result":[
            {"id":"a","type":"A","content":"1.2.3.4","name":"h.example.com","proxied":false,"ttl":1},
            {"id":"b","type":"AAAA","content":"2001:db8::1","name":"h.example.com"},
            {"id":"c","type":"TXT","content":"hello","name":"h.example.com"},
            {"id":"d","type":"CNAME","content":"other.example.com","name":"h.example.com"}
        ]}"#;
        let records: Vec<DnsRecord> = parse_response(200, body).unwrap();
        let records: Vec<_> = records.into_iter().filter_map(address_record).collect();
        assert_eq!(
            records,
            vec![
                ("a".to_string(), "1.2.3.4".parse().unwrap()),
                ("b".to_string(), "2001:db8::1".parse().unwrap()),
            ]
        );
    }
}
