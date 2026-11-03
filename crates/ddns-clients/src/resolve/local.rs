use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use futures_util::{StreamExt, TryStreamExt, stream::BoxStream};
use netlink_packet_route::{
    AddressFamily, RouteNetlinkMessage,
    address::{AddressAttribute, AddressScope},
};
use rtnetlink::{
    MulticastGroup,
    packet_core::{NetlinkMessage, NetlinkPayload},
};

use super::IpResolver;

/// Resolves addresses assigned to local interfaces via netlink.
///
/// Useful when the host has a public address directly, e.g. IPv6 or no NAT.
/// Skips non-global and deprecated addresses. Must be used from within a
/// Tokio runtime.
///
/// `LocalResolver::default()` reads all interfaces; [`interface`](Self::interface)
/// limits it to one.
#[derive(Debug, Clone, Default)]
pub struct LocalResolver {
    interface: Option<String>,
}

impl LocalResolver {
    /// Only use the addresses of the interface `name`, e.g. `eth0`.
    pub fn interface(mut self, name: impl Into<String>) -> Self {
        self.interface = Some(name.into());
        self
    }
}

#[async_trait]
impl IpResolver for LocalResolver {
    async fn resolve_a(&self) -> Result<Vec<Ipv4Addr>> {
        let addrs = global_addrs(AddressFamily::Inet, self.interface.as_deref()).await?;
        Ok(addrs
            .into_iter()
            .filter_map(|addr| match addr {
                IpAddr::V4(addr) => Some(addr),
                IpAddr::V6(_) => None,
            })
            .collect())
    }

    async fn resolve_aaaa(&self) -> Result<Vec<Ipv6Addr>> {
        let addrs = global_addrs(AddressFamily::Inet6, self.interface.as_deref()).await?;
        Ok(addrs
            .into_iter()
            .filter_map(|addr| match addr {
                IpAddr::V6(addr) => Some(addr),
                IpAddr::V4(_) => None,
            })
            .collect())
    }
}

/// Waits for changes of the global addresses of local interfaces, or of one
/// interface, e.g. to look up the public addresses again after a WAN
/// reconnect.
///
/// Listens for the kernel's address notifications via netlink, and reports a
/// change only when the global, non-deprecated addresses differ, not on e.g.
/// IPv6 lifetime updates. Must be used from within a Tokio runtime.
pub struct AddressMonitor {
    messages: BoxStream<'static, NetlinkMessage<RouteNetlinkMessage>>,
    /// The interface to watch; all if `None`.
    interface: Option<String>,
    /// The sorted addresses last read.
    known: Vec<IpAddr>,
}

impl AddressMonitor {
    /// Starts watching `interface`, or all interfaces if `None`. An interface
    /// that doesn't exist, e.g. while a PPPoE link is down, has no addresses
    /// until it appears. Fails if the netlink socket can't be opened.
    pub async fn new(interface: Option<&str>) -> Result<Self> {
        let (conn, _, messages) = rtnetlink::new_multicast_connection(&[
            MulticastGroup::Ipv4Ifaddr,
            MulticastGroup::Ipv6Ifaddr,
        ])
        .context("open netlink socket")?;
        tokio::spawn(conn);

        // listening already, so no change is missed between here and changed()
        let interface = interface.map(str::to_owned);
        let known = match all_global_addrs(interface.as_deref()).await {
            Ok(addrs) => addrs,
            Err(err) => {
                log::warn!("{err:#}; waiting for it");
                vec![]
            }
        };
        Ok(AddressMonitor {
            messages: messages.map(|(message, _)| message).boxed(),
            interface,
            known,
        })
    }

    /// Waits until the addresses differ from when this monitor was created or
    /// this last returned. Fails if the netlink socket closes.
    pub async fn changed(&mut self) -> Result<()> {
        loop {
            let Some(message) = self.messages.next().await else {
                bail!("netlink address monitor closed");
            };
            if !matches!(
                message.payload,
                NetlinkPayload::InnerMessage(
                    RouteNetlinkMessage::NewAddress(_) | RouteNetlinkMessage::DelAddress(_)
                )
            ) {
                continue;
            }
            let addrs = match all_global_addrs(self.interface.as_deref()).await {
                Ok(addrs) => addrs,
                Err(err) => {
                    log::debug!("{err:#}");
                    vec![]
                }
            };
            if addrs != self.known {
                self.known = addrs;
                return Ok(());
            }
        }
    }
}

/// The sorted global, non-deprecated addresses of both families, on local
/// interfaces or only on `interface`.
async fn all_global_addrs(interface: Option<&str>) -> Result<Vec<IpAddr>> {
    let mut addrs = global_addrs(AddressFamily::Inet, interface).await?;
    addrs.extend(global_addrs(AddressFamily::Inet6, interface).await?);
    addrs.sort();
    Ok(addrs)
}

/// The global, non-deprecated addresses of `wanted_family` on local
/// interfaces, or only on `interface`.
async fn global_addrs(
    wanted_family: AddressFamily,
    interface: Option<&str>,
) -> Result<Vec<IpAddr>> {
    let (conn, handle, _) = rtnetlink::new_connection().context("open netlink socket")?;
    // Spawn the `Connection` so that it starts polling the netlink socket in the background.
    tokio::spawn(conn);

    let mut request = handle.address().get();
    if let Some(name) = interface {
        // looked up every time: e.g. a PPPoE interface gets a new index when it
        // comes back up
        let link = handle
            .link()
            .get()
            .match_name(name)
            .execute()
            .try_next()
            .await
            .with_context(|| format!("interface {name}"))?
            .with_context(|| format!("interface {name} not found"))?;
        request = request.set_link_index_filter(link.header.index);
    }
    let mut stream = request.execute();
    let mut addrs = vec![];

    while let Some(addr_msg) = stream.try_next().await.context("netlink request failed")? {
        if addr_msg.header.family != wanted_family {
            continue;
        }

        let addr = addr_msg.attributes.iter().find_map(|attr| match attr {
            AddressAttribute::Address(addr) => Some(*addr),
            _ => None,
        });
        let Some(addr) = addr else {
            continue;
        };

        if addr_msg.header.scope != AddressScope::Universe {
            log::debug!("non-global address {addr}, skipping");
            continue;
        }

        if !is_global(&addr) {
            log::debug!("non-public address {addr}, skipping");
            continue;
        }

        let cache_info = addr_msg.attributes.iter().find_map(|attr| match attr {
            AddressAttribute::CacheInfo(cache_info) => Some(cache_info),
            _ => None,
        });
        if cache_info.is_some_and(|info| info.ifa_preferred == 0 || info.ifa_valid == 0) {
            log::debug!("address {addr} is deprecated, skipping");
            continue;
        }

        addrs.push(addr);
    }

    Ok(addrs)
}

/// Whether `addr` is publicly routable, i.e. worth publishing in DNS.
///
/// The kernel reports e.g. private IPv4 addresses with global scope, so the
/// scope alone is not enough.
fn is_global(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V4(addr) => is_global_v4(addr),
        IpAddr::V6(addr) => is_unicast_global(addr),
    }
}

fn is_global_v4(addr: &Ipv4Addr) -> bool {
    let [a, b, c, _] = addr.octets();
    !addr.is_private() // 10/8, 172.16/12, 192.168/16
        && !addr.is_loopback()
        && !addr.is_link_local()
        && !addr.is_unspecified()
        && !addr.is_broadcast()
        && !addr.is_documentation()
        && !addr.is_multicast()
        && a != 0 // "this network"
        && !(a == 100 && (b & 0xc0) == 64) // shared address space (CGNAT), 100.64/10
        && !(a == 192 && b == 0 && c == 0) // IETF protocol assignments, 192.0.0/24
        && !(a == 198 && (b & 0xfe) == 18) // benchmarking, 198.18/15
        && a < 240 // reserved, 240/4
}

fn is_unicast_global(addr: &Ipv6Addr) -> bool {
    !addr.is_multicast() // is_unicast
        && !addr.is_loopback()
        && (addr.segments()[0] & 0xffc0) != 0xfe80 // !is_unicast_link_local
        && (addr.segments()[0] & 0xfe00) != 0xfc00 // !is_unique_local
        && !addr.is_unspecified()
        && !((addr.segments()[0] == 0x2001) && (addr.segments()[1] == 0xdb8)) // !documentation
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn global_v4() {
        let global = |s: &str| is_global(&s.parse().unwrap());
        assert!(global("1.1.1.1"));
        assert!(global("50.118.185.32"));
        assert!(global("100.128.0.1"));
        assert!(global("172.32.0.1"));
        assert!(!global("10.0.0.1"));
        assert!(!global("172.16.0.1"));
        assert!(!global("192.168.1.10"));
        assert!(!global("127.0.0.1"));
        assert!(!global("169.254.1.1"));
        assert!(!global("100.64.0.1"));
        assert!(!global("100.127.255.254"));
        assert!(!global("0.0.0.0"));
        assert!(!global("0.1.2.3"));
        assert!(!global("192.0.0.8"));
        assert!(!global("192.0.2.1"));
        assert!(!global("198.18.0.1"));
        assert!(!global("198.19.255.1"));
        assert!(!global("203.0.113.1"));
        assert!(!global("224.0.0.1"));
        assert!(!global("240.0.0.1"));
        assert!(!global("255.255.255.255"));
    }

    #[test]
    fn unicast_global() {
        let global = |s: &str| is_unicast_global(&s.parse().unwrap());
        assert!(global("2606:4700::1111"));
        assert!(global("2408:8207:1:2::3"));
        assert!(!global("::1"));
        assert!(!global("::"));
        assert!(!global("fe80::1"));
        assert!(!global("fd00::1"));
        assert!(!global("fc12::1"));
        assert!(!global("ff02::1"));
        assert!(!global("2001:db8::1"));
    }
}
