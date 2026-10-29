use std::{
    net::{AddrParseError, IpAddr},
    time::Duration,
};

/// Errors returned by this crate.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The provider has no zone with the given name.
    #[error("zone {0:?} not found")]
    ZoneNotFound(String),

    /// An HTTP request failed.
    #[error("http request failed")]
    Http(#[from] reqwest::Error),

    /// A response did not contain a valid IP address.
    #[error("invalid ip address")]
    InvalidIp(#[from] AddrParseError),

    /// An I/O error, e.g. while opening a netlink socket.
    #[error("i/o error")]
    Io(#[from] std::io::Error),

    /// A netlink request failed.
    #[cfg(target_os = "linux")]
    #[error("netlink request failed")]
    Netlink(#[from] rtnetlink::Error),

    /// A DNS provider reported an error.
    #[error("dns provider error")]
    Provider(#[source] Box<dyn std::error::Error + Send + Sync>),

    /// A DNS provider rejected the request; retrying cannot succeed until the
    /// configuration (e.g. credentials or domain) is fixed.
    #[error("dns provider rejected the request")]
    Rejected(#[source] Box<dyn std::error::Error + Send + Sync>),

    /// A DNS provider is temporarily unavailable and asks clients not to
    /// retry before `retry_after` has passed.
    #[error("dns provider unavailable, retry in {}s", .retry_after.as_secs())]
    Unavailable {
        retry_after: Duration,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// The provider cannot make the requested change.
    #[error("unsupported update: {0}")]
    Unsupported(String),

    /// The domain has no record with the address, e.g. because it was
    /// changed elsewhere since it was listed.
    #[error("{domain} has no record for {ip}")]
    RecordNotFound { domain: String, ip: IpAddr },

    /// A [`DynDnsClient`](crate::DynDnsClient) was configured incorrectly,
    /// e.g. with an unknown provider or a missing parameter.
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),
}

impl Error {
    /// Wraps an arbitrary error from a [`DynDnsProvider`](crate::providers::DynDnsProvider) implementation.
    pub fn provider(err: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> Self {
        Error::Provider(err.into())
    }

    /// Wraps a provider error that must not be retried; see [`Error::Rejected`].
    pub fn rejected(err: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> Self {
        Error::Rejected(err.into())
    }

    /// Wraps a provider error that may be retried after `retry_after`; see
    /// [`Error::Unavailable`].
    pub fn unavailable(
        retry_after: Duration,
        err: impl Into<Box<dyn std::error::Error + Send + Sync>>,
    ) -> Self {
        Error::Unavailable {
            retry_after,
            source: err.into(),
        }
    }

    /// Displays this error followed by its chain of sources, `: `-separated.
    pub(crate) fn chain(&self) -> impl std::fmt::Display + '_ {
        Chain(self)
    }
}

struct Chain<'a>(&'a dyn std::error::Error);

impl std::fmt::Display for Chain<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)?;
        let mut source = self.0.source();
        while let Some(err) = source {
            write!(f, ": {err}")?;
            source = err.source();
        }
        Ok(())
    }
}

/// A `Result` alias using this crate's [`Error`].
pub type Result<T> = std::result::Result<T, Error>;
