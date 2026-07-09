//! Netns-based integration-test support for radian-rs.
//!
//! [`netns`] wraps `ip netns`/veth setup; [`datapath`] drives a live UPF's N4/N3 to prove
//! the user-plane forwards a real packet; [`ran`] scripts a gNB + UE speaking real
//! NGAP/NAS to the live AMF (design/116 Tier B). Used by `tests/cucumber.rs`.

pub mod datapath;
pub mod netns;
pub mod ran;
