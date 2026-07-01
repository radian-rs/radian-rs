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

/// Spawn a **host** process with extra env vars, optionally under `sudo` (needed for the UPF's
/// N6 TUN). Output is discarded; the child is detached (not killed on drop).
pub async fn spawn_host_env(
    root: bool,
    env: &[(&str, &str)],
    cmd: &str,
    args: &[&str],
) -> Result<tokio::process::Child> {
    let mut c = if root {
        let mut c = Command::new("sudo");
        c.arg("env");
        c
    } else {
        Command::new("env")
    };
    for (k, v) in env {
        c.arg(format!("{k}={v}"));
    }
    c.arg(cmd).args(args);
    c.stdout(Stdio::null()).stderr(Stdio::null());
    c.spawn().with_context(|| format!("spawn host process {cmd}"))
}

/// Wire a veth pair between two namespaces, assigning `/24` addresses and bringing both ends
/// up. Used for the RAN↔UE link (both ends live inside namespaces).
pub async fn connect_netns_pair(
    ns_a: &str,
    veth_a: &str,
    ip_a: &str,
    ns_b: &str,
    veth_b: &str,
    ip_b: &str,
) -> Result<()> {
    sudo(&["ip", "link", "add", veth_a, "type", "veth", "peer", veth_b], "add veth pair").await?;
    sudo(&["ip", "link", "set", veth_a, "netns", ns_a], "move veth a").await?;
    sudo(&["ip", "link", "set", veth_b, "netns", ns_b], "move veth b").await?;
    sudo(&["ip", "netns", "exec", ns_a, "ip", "addr", "add", &format!("{ip_a}/24"), "dev", veth_a], "veth a addr").await?;
    sudo(&["ip", "netns", "exec", ns_a, "ip", "link", "set", veth_a, "up"], "veth a up").await?;
    sudo(&["ip", "netns", "exec", ns_b, "ip", "addr", "add", &format!("{ip_b}/24"), "dev", veth_b], "veth b addr").await?;
    sudo(&["ip", "netns", "exec", ns_b, "ip", "link", "set", veth_b, "up"], "veth b up").await
}

/// Add a route inside a namespace: `ip route add <dest> <spec>` where `spec` is e.g.
/// `["via", "10.0.1.1"]` or `["dev", "ueTun0"]`.
pub async fn add_route(ns: &str, dest: &str, spec: &[&str]) -> Result<()> {
    let mut args = vec!["ip", "netns", "exec", ns, "ip", "route", "add", dest];
    args.extend_from_slice(spec);
    sudo(&args, "add route").await
}

/// Whether interface `iface` exists inside namespace `ns`.
pub async fn iface_exists(ns: &str, iface: &str) -> bool {
    Command::new("sudo")
        .args(["ip", "netns", "exec", ns, "ip", "link", "show", iface])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .map(|s| s.success())
        .unwrap_or(false)
}

/// The first global IPv4 address on `iface` inside `ns` (e.g. the UE's `ueTun0` address).
pub async fn iface_ipv4(ns: &str, iface: &str) -> Option<String> {
    let out = Command::new("sudo")
        .args(["ip", "netns", "exec", ns, "ip", "-4", "-o", "addr", "show", iface])
        .stdout(Stdio::piped())
        .output()
        .await
        .ok()?;
    // `… inet 10.45.0.2/32 scope global ueTun0 …`
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .skip_while(|t| *t != "inet")
        .nth(1)
        .and_then(|cidr| cidr.split('/').next())
        .map(String::from)
}

/// Whether a **host** socket is listening on `port`. `kind` is "tcp" (`ss -lnt`) or "sctp"
/// (`ss -lna`, matching lines whose state is LISTEN).
pub async fn host_port_listening(port: u16, kind: &str) -> bool {
    let flag = if kind == "sctp" { "-lna" } else { "-lnt" };
    let Ok(out) = Command::new("ss").arg(flag).stdout(Stdio::piped()).output().await else {
        return false;
    };
    let needle = format!(":{port}");
    String::from_utf8_lossy(&out.stdout).lines().any(|l| {
        l.contains(&needle) && l.contains("LISTEN") && (kind != "sctp" || l.contains("sctp"))
    })
}

/// Whether a **host** interface exists (e.g. the UPF's `n6upf0` after it opens its TUN).
pub async fn host_iface_exists(iface: &str) -> bool {
    Command::new("ip")
        .args(["link", "show", iface])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .map(|s| s.success())
        .unwrap_or(false)
}

/// SIGKILL every **host** process whose command line matches `pattern` (best-effort).
pub async fn kill_host_procs(pattern: &str) -> Result<()> {
    let _ = Command::new("sudo").args(["pkill", "-9", "-f", pattern]).status().await;
    Ok(())
}

/// Ping `dst` from inside `ns` (sourced from `src`); returns whether any reply came back.
pub async fn ping_from_netns(ns: &str, src: &str, dst: &str, count: u32, timeout_s: u32) -> bool {
    Command::new("sudo")
        .args([
            "ip", "netns", "exec", ns, "ping", "-c", &count.to_string(), "-W", &timeout_s.to_string(),
            "-I", src, dst,
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .map(|s| s.success())
        .unwrap_or(false)
}
