//! The N6 data-network device: a Linux **TUN** interface.
//!
//! This is the privileged edge of the user plane — opening a TUN needs `CAP_NET_ADMIN`
//! (run as root or `setcap cap_net_admin+ep` the binary). The UPF opens it best-effort at
//! startup and degrades to "N6 disabled" when it can't (see the UPF binary), so the
//! forwarding logic in the crate root is exercised in tests without any privileges.
//!
//! The device carries **bare IP packets** (no Ethernet header): what we read is a
//! downlink packet from the data network; what we write is a decapsulated uplink packet.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};

use tun::AsyncDevice;

/// A TUN device on N6. Configured with the UPF's address *inside* the UE IP pool so the
/// kernel installs a route for that pool toward this interface — return traffic to any UE
/// then arrives here as a downlink packet.
pub struct N6Tun {
    dev: AsyncDevice,
    name: String,
}

impl N6Tun {
    /// Bring up TUN `name` addressed `address`/`netmask` (the UPF's own N6 address, which
    /// must sit inside the UE subnet) with the given `mtu`. When `ipv6` is set, also add
    /// an IPv6 `(address, prefix_len)` covering the UE IPv6 pool (design/131) so the
    /// kernel routes UE return traffic here — the `tun` crate configures only IPv4, so
    /// the v6 address is added via iproute2. Returns an error — typically
    /// `PermissionDenied` — when the process lacks `CAP_NET_ADMIN`.
    pub fn open(
        name: &str,
        address: Ipv4Addr,
        netmask: Ipv4Addr,
        mtu: u16,
        ipv6: Option<(Ipv6Addr, u8)>,
    ) -> io::Result<Self> {
        let mut cfg = tun::configure();
        cfg.tun_name(name).address(address).netmask(netmask).mtu(mtu).up();
        let dev = tun::create_as_async(&cfg).map_err(io::Error::other)?;
        if let Some((addr6, prefix_len)) = ipv6 {
            add_ipv6(name, addr6, prefix_len)?;
        }
        Ok(Self { dev, name: name.to_string() })
    }

    /// The interface name the kernel assigned (may differ from the requested one).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Read one IP packet from the data network into `buf`, returning its length.
    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.dev.recv(buf).await
    }

    /// Write one IP packet out to the data network.
    pub async fn send(&self, pkt: &[u8]) -> io::Result<()> {
        self.dev.send(pkt).await.map(|_| ())
    }
}

/// Add an IPv6 address (covering the UE IPv6 pool) to TUN `name` via iproute2, so the
/// kernel routes that prefix here. `nodad` skips Duplicate Address Detection — a
/// point-to-point TUN has no L2 neighbours, and DAD would otherwise leave the address
/// `tentative` (and unusable) briefly. Also clears `disable_ipv6` on the interface,
/// which some hosts default on.
fn add_ipv6(name: &str, addr: Ipv6Addr, prefix_len: u8) -> io::Result<()> {
    // Best-effort: enable IPv6 on the interface (ignore failure — often already on).
    let _ = std::process::Command::new("sysctl")
        .arg("-w")
        .arg(format!("net.ipv6.conf.{name}.disable_ipv6=0"))
        .status();
    let status = std::process::Command::new("ip")
        .args(["-6", "addr", "add", &format!("{addr}/{prefix_len}"), "dev", name, "nodad"])
        .status()?;
    if !status.success() {
        return Err(io::Error::other(format!("`ip -6 addr add {addr}/{prefix_len} dev {name}` failed")));
    }
    Ok(())
}
