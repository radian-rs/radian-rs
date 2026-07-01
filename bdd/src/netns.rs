//! Minimal Linux network-namespace helpers for the datapath BDD test.
//!
//! Everything shells out to `sudo ip …`; the caller must have passwordless (or cached)
//! sudo. Functions are best-effort where teardown correctness matters — deleting a
//! namespace that never existed is a success, so a partial setup can still be swept.

use std::process::Stdio;

use anyhow::{Context, Result};
use tokio::process::Command;

/// Run `sudo <args…>`, returning an error (with `ctx`) on non-zero exit.
async fn sudo(args: &[&str], ctx: &str) -> Result<()> {
    let status = Command::new("sudo").args(args).status().await.context(ctx.to_string())?;
    anyhow::ensure!(status.success(), "{ctx}: `sudo {}` failed", args.join(" "));
    Ok(())
}

/// Whether a network namespace exists.
pub async fn netns_exists(ns: &str) -> bool {
    list_netns_with_prefix(ns).await.unwrap_or_default().iter().any(|n| n == ns)
}

/// Create a namespace and bring its loopback up.
pub async fn create_netns(ns: &str) -> Result<()> {
    sudo(&["ip", "netns", "add", ns], "create netns").await?;
    sudo(&["ip", "netns", "exec", ns, "ip", "link", "set", "lo", "up"], "netns lo up").await
}

/// Delete a namespace (no-op if absent, so teardown of a partial setup is safe).
pub async fn delete_netns(ns: &str) -> Result<()> {
    if !netns_exists(ns).await {
        return Ok(());
    }
    sudo(&["ip", "netns", "del", ns], "delete netns").await
}

/// List namespaces whose name starts with `prefix`.
pub async fn list_netns_with_prefix(prefix: &str) -> Result<Vec<String>> {
    let out = Command::new("sudo")
        .args(["ip", "netns", "list"])
        .stdout(Stdio::piped())
        .output()
        .await
        .context("list netns")?;
    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| l.split_whitespace().next())
        .filter(|n| n.starts_with(prefix))
        .map(String::from)
        .collect())
}

/// Wire a veth pair between the host and namespace `ns`, assigning `/24` addresses and
/// bringing both ends up. `host_veth`/`ns_veth` are the interface names; the host keeps
/// `host_ip`, the namespace gets `ns_ip`.
pub async fn connect_host_to_netns(
    ns: &str,
    host_veth: &str,
    ns_veth: &str,
    host_ip: &str,
    ns_ip: &str,
) -> Result<()> {
    sudo(&["ip", "link", "add", host_veth, "type", "veth", "peer", ns_veth], "add veth").await?;
    sudo(&["ip", "link", "set", ns_veth, "netns", ns], "move veth to netns").await?;
    sudo(&["ip", "addr", "add", &format!("{host_ip}/24"), "dev", host_veth], "host veth addr").await?;
    sudo(&["ip", "link", "set", host_veth, "up"], "host veth up").await?;
    sudo(&["ip", "netns", "exec", ns, "ip", "addr", "add", &format!("{ns_ip}/24"), "dev", ns_veth], "ns veth addr").await?;
    sudo(&["ip", "netns", "exec", ns, "ip", "link", "set", ns_veth, "up"], "ns veth up").await
}

/// Delete a host-side veth (its peer went away with the namespace, but `ip netns del`
/// returns the ns-side end to the host rather than destroying it — so sweep the host end).
pub async fn delete_veth(host_veth: &str) -> Result<()> {
    // Quiet: sweeping a veth that was never created (first run) is expected, so don't let
    // `ip`'s "Cannot find device" reach the console.
    let _ = Command::new("sudo")
        .args(["ip", "link", "del", host_veth])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await;
    Ok(())
}

/// PIDs of processes running inside namespace `ns`.
pub async fn pids_in_netns(ns: &str) -> Vec<u32> {
    if !netns_exists(ns).await {
        return Vec::new();
    }
    let out = Command::new("sudo")
        .args(["ip", "netns", "pids", ns])
        .stdout(Stdio::piped())
        .output()
        .await;
    let Ok(out) = out else { return Vec::new() };
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .filter_map(|p| p.parse().ok())
        .collect()
}

/// Kill every process running inside namespace `ns` (SIGKILL, best-effort).
pub async fn kill_netns_procs(ns: &str) -> Result<()> {
    for pid in pids_in_netns(ns).await {
        let _ = Command::new("sudo").args(["kill", "-9", &pid.to_string()]).status().await;
    }
    Ok(())
}

/// Spawn `cmd args…` inside namespace `ns` with extra env vars (which must precede the
/// command via `env` because `sudo` resets the environment). Output is discarded.
pub async fn spawn_in_netns_env(
    ns: &str,
    env: &[(&str, &str)],
    cmd: &str,
    args: &[&str],
) -> Result<tokio::process::Child> {
    let mut c = Command::new("sudo");
    c.args(["ip", "netns", "exec", ns, "env"]);
    for (k, v) in env {
        c.arg(format!("{k}={v}"));
    }
    c.arg(cmd).args(args);
    c.stdout(Stdio::null()).stderr(Stdio::null());
    c.spawn().with_context(|| format!("spawn {cmd} in netns {ns}"))
}
