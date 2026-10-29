//! Tests against the real provider APIs.
//!
//! The tests are `#[ignore]`d, so plain `cargo test` lists them as ignored.
//! Run them with `cargo test -p ddns-clients --test live -- --include-ignored`
//! (or `mise run test-live`); the record tests fail if their provider's
//! variables are missing, the Cloudflare bad-token test only needs network
//! access. There is no No-IP bad-credentials test: repeated failed logins
//! make No-IP stop answering `badauth` and may block the client's IP.
//!
//! - Cloudflare: `DDNS_CLOUDFLARE_API_TOKEN` (needs `Zone:Read` and
//!   `DNS:Edit`) and `DDNS_CLOUDFLARE_ZONE`. Records are created on
//!   `DDNS_CLOUDFLARE_TEST_DOMAIN`, by default a fresh
//!   `ddns-clients-test-<unix-seconds>.<zone>`, and removed afterwards.
//! - No-IP: `DDNS_NOIP_USERNAME`, `DDNS_NOIP_PASSWORD` and
//!   `DDNS_NOIP_HOSTNAME` (an existing hostname with one A record). The
//!   hostname's A record is pointed at a test address and then restored.

use std::net::IpAddr;

/// Reads the variables `names`; panics listing the missing ones.
fn required_env<const N: usize>(names: [&str; N]) -> [String; N] {
    let values = names.map(|name| std::env::var(name).ok());
    let missing: Vec<&str> = names
        .iter()
        .zip(&values)
        .filter(|(_, value)| value.is_none())
        .map(|(name, _)| *name)
        .collect();
    assert!(missing.is_empty(), "{} not set", missing.join(", "));
    values.map(Option::unwrap)
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

mod cloudflare {
    use std::{
        net::IpAddr,
        time::{SystemTime, UNIX_EPOCH},
    };

    use ddns_clients::{
        CloudflareProvider, DynDnsProvider, Error, providers::cloudflare::CloudflareError,
    };

    use super::{ip, required_env};

    struct LiveEnv {
        api_token: String,
        zone: String,
        domain: String,
    }

    fn live_env() -> LiveEnv {
        let [api_token, zone] = required_env(["DDNS_CLOUDFLARE_API_TOKEN", "DDNS_CLOUDFLARE_ZONE"]);
        let domain = std::env::var("DDNS_CLOUDFLARE_TEST_DOMAIN").unwrap_or_else(|_| {
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
            format!("ddns-clients-test-{}.{zone}", now.as_secs())
        });
        LiveEnv {
            api_token,
            zone,
            domain,
        }
    }

    /// The cached and the actual addresses, each sorted; they should match.
    async fn sorted_ips(
        provider: &mut CloudflareProvider,
    ) -> Result<(Vec<IpAddr>, Vec<IpAddr>), Error> {
        let mut cached = provider.list().await?;
        cached.sort();
        provider.refresh().await?;
        let mut actual = provider.list().await?;
        actual.sort();
        Ok((cached, actual))
    }

    async fn delete_all_records(provider: &mut CloudflareProvider) -> Result<(), Error> {
        provider.refresh().await?;
        for ip in provider.list().await? {
            provider.delete(ip).await?;
        }
        Ok(())
    }

    async fn exercise_records(provider: &mut CloudflareProvider) -> Result<(), Error> {
        let domain = provider.domain().to_string();
        let records = provider.list().await?;
        assert!(
            records.is_empty(),
            "{domain} already has records: {records:?}"
        );

        let (a1, a2, a3) = (ip("192.0.2.1"), ip("198.51.100.1"), ip("203.0.113.1"));
        let aaaa1 = ip("2001:db8::1");

        provider.add(a1, Some(120)).await?;
        provider.add(aaaa1, Some(120)).await?;
        let expected = vec![a1, aaaa1];
        assert_eq!(sorted_ips(provider).await?, (expected.clone(), expected));

        provider.replace(a1, a2, None).await?;
        let expected = vec![a2, aaaa1];
        assert_eq!(sorted_ips(provider).await?, (expected.clone(), expected));

        // AAAA -> A on the same record
        provider.replace(aaaa1, a3, None).await?;
        let expected = vec![a2, a3];
        assert_eq!(sorted_ips(provider).await?, (expected.clone(), expected));

        // the AAAA record is gone
        let err = provider.delete(aaaa1).await.unwrap_err();
        assert!(matches!(err, Error::RecordNotFound { .. }), "{err:?}");

        provider.delete(a2).await?;
        provider.delete(a3).await?;
        assert_eq!(sorted_ips(provider).await?, (vec![], vec![]));
        Ok(())
    }

    #[tokio::test]
    #[ignore = "needs DDNS_CLOUDFLARE_* variables"]
    async fn record_lifecycle() {
        let env = live_env();
        eprintln!("using cloudflare test domain {}", env.domain);
        let new_provider = || {
            CloudflareProvider::new(
                env.api_token.as_str(),
                env.zone.as_str(),
                env.domain.as_str(),
            )
            .unwrap()
        };

        // run in a task so a failed assertion still reaches the cleanup below
        let mut provider = new_provider();
        let result = tokio::spawn(async move { exercise_records(&mut provider).await }).await;

        match result {
            Ok(Ok(())) => return,
            Ok(Err(err)) => eprintln!("record lifecycle failed: {err:?}"),
            Err(join_err) => eprintln!("record lifecycle panicked: {join_err}"),
        }

        // best-effort cleanup
        let mut provider = new_provider();
        if let Err(err) = delete_all_records(&mut provider).await {
            eprintln!("cleanup of {} failed: {err:?}", env.domain);
        }
        panic!("cloudflare record lifecycle test failed, see output above");
    }

    #[tokio::test]
    #[ignore = "needs network"]
    async fn bad_token_is_reported() {
        let mut provider =
            CloudflareProvider::new("not-a-valid-token", "example.com", "ddns.example.com")
                .unwrap();
        let err = provider.list().await.unwrap_err();
        let Error::Provider(err) = err else {
            panic!("unexpected error {err:?}");
        };
        let err = err
            .downcast_ref::<CloudflareError>()
            .expect("a CloudflareError");
        assert!(!(200..300).contains(&err.status), "{err}");
        assert!(!err.errors.is_empty(), "{err}");
    }
}

mod noip {
    use std::net::IpAddr;

    use ddns_clients::{DynDnsProvider, NoIpProvider};

    use super::{ip, required_env};

    struct LiveEnv {
        username: String,
        password: String,
        hostname: String,
    }

    fn live_env() -> LiveEnv {
        let [username, password, hostname] = required_env([
            "DDNS_NOIP_USERNAME",
            "DDNS_NOIP_PASSWORD",
            "DDNS_NOIP_HOSTNAME",
        ]);
        LiveEnv {
            username,
            password,
            hostname,
        }
    }

    #[tokio::test]
    #[ignore = "needs DDNS_NOIP_* variables"]
    async fn repoint_and_restore() {
        let env = live_env();
        let mut provider = NoIpProvider::new(env.username, env.password, &env.hostname).unwrap();

        let mut original = provider.list().await.unwrap();
        eprintln!("{} has {original:?}", env.hostname);
        let original_v4: Vec<IpAddr> = original.iter().copied().filter(IpAddr::is_ipv4).collect();
        assert_eq!(
            original_v4.len(),
            1,
            "{} needs exactly one A record",
            env.hostname
        );

        let test_ip = if original_v4[0] == ip("192.0.2.10") {
            ip("192.0.2.11")
        } else {
            ip("192.0.2.10")
        };

        provider
            .replace(original_v4[0], test_ip, None)
            .await
            .unwrap();
        let current = provider.list().await.unwrap();
        assert!(current.contains(&test_ip), "{current:?}");

        provider
            .replace(test_ip, original_v4[0], None)
            .await
            .unwrap();
        let mut restored = provider.list().await.unwrap();
        restored.sort();
        original.sort();
        assert_eq!(restored, original);
    }
}
