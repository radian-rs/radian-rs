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
use std::net::Ipv4Addr;

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
    /// must sit inside the UE subnet) with the given `mtu`. Returns an error — typically
    /// `PermissionDenied` — when the process lacks `CAP_NET_ADMIN`.
    pub fn open(name: &str, address: Ipv4Addr, netmask: Ipv4Addr, mtu: u16) -> io::Result<Self> {
        let mut cfg = tun::configure();
        cfg.tun_name(name).address(address).netmask(netmask).mtu(mtu).up();
        let dev = tun::create_as_async(&cfg).map_err(io::Error::other)?;
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
