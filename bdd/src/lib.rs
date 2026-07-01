//! Netns-based integration-test support for radiant-rs.
//!
//! [`netns`] wraps `ip netns`/veth setup; [`datapath`] drives a live UPF's N4/N3 to prove
//! the user-plane forwards a real packet. Used by `tests/cucumber.rs`.

pub mod datapath;
pub mod netns;
