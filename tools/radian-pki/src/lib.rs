//! PKI bootstrap for the radian-rs SBI mutual-TLS mesh (design/58).
//!
//! Generates and maintains the core CA, the per-NF identities that
//! `RADIAN_SBI_TLS_DIR` points at (design/57), and the CA's certificate
//! revocation list. It drives the **`openssl` CLI** (`rcgen` isn't available
//! offline) but encodes every wire-level gotcha in one place so a live
//! full-core mTLS run is a single `radian-pki init`:
//!
//! - leafs are X.509 **v3** (rustls rejects v1) — the CSR carries the
//!   extensions and the CA copies them (`copy_extensions = copy`);
//! - every NF is both an SBI server *and* client, so each cert carries
//!   **both** `serverAuth` and `clientAuth` EKUs plus a SAN;
//! - issuance goes through an **`openssl ca` database** (`ca-db/`), so
//!   `revoke`/`rotate` can maintain a real **CRL** (`ca.crl`) that
//!   `sbi_core::tls` enforces on both sides of every handshake.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, bail};

/// The NFs of the core, in the names `TlsIdentity::from_env` expects.
pub const DEFAULT_NFS: &[&str] = &["nrf", "amf", "smf", "ausf", "udm", "udr", "pcf", "chf"];

const EC_KEY: &[&str] = &["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes"];
const DAYS: &str = "3650";

/// Whether the `openssl` CLI is present (the tool's only external dependency).
pub fn openssl_available() -> bool {
    Command::new("openssl")
        .arg("version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Initialize a PKI in `dir`: the core CA, one identity per NF (`<nf>.crt` /
/// `<nf>.key`), and an (initially empty) `ca.crl` — ready to be used as
/// `RADIAN_SBI_TLS_DIR`.
pub fn init(dir: &Path, nfs: &[&str], san_ip: &str) -> anyhow::Result<()> {
    let db = dir.join("ca-db");
    std::fs::create_dir_all(db.join("newcerts")).context("create ca-db")?;
    let dir = dir.canonicalize().context("resolve PKI dir")?;

    // The `openssl ca` issuance database: an index of every issued cert (which
    // is what makes revocation and CRL generation possible later).
    write_new(dir.join("ca-db/index.txt"), "")?;
    // Re-issuing the same CN (rotation) must be allowed.
    write_new(dir.join("ca-db/index.txt.attr"), "unique_subject = no\n")?;
    write_new(dir.join("ca-db/serial"), "1000\n")?;
    write_new(dir.join("ca-db/crlnumber"), "1000\n")?;
    write_new(dir.join("ca-db/openssl.cnf"), &ca_config(&dir))?;

    // The core CA (self-signed, CA:TRUE by openssl-3 default for `req -x509`).
    openssl(
        &dir,
        [
            &["req", "-x509"][..],
            EC_KEY,
            &["-keyout", "ca.key", "-out", "ca.crt", "-subj", "/CN=radian-core-ca", "-days", DAYS],
        ]
        .concat(),
    )?;
    owner_only(&dir.join("ca.key"))?;

    for nf in nfs {
        issue(&dir, nf, san_ip)?;
    }
    gencrl(&dir)
}

/// Issue (or re-issue) the identity for one NF from the existing CA.
pub fn issue(dir: &Path, nf: &str, san_ip: &str) -> anyhow::Result<()> {
    let dir = dir.canonicalize().context("resolve PKI dir")?;
    let (key, csr, crt) = (format!("{nf}.key"), format!("{nf}.csr"), format!("{nf}.crt"));
    // The CSR carries the extensions (making the leaf v3 once copied): a SAN
    // and BOTH EKUs — every NF serves its SBI and dials its peers.
    openssl(
        &dir,
        [
            &["req"][..],
            EC_KEY,
            &["-keyout", &key, "-out", &csr, "-subj", &format!("/CN={nf}")],
            &["-addext", &format!("subjectAltName=IP:{san_ip}")],
            &["-addext", "extendedKeyUsage=serverAuth,clientAuth"],
        ]
        .concat(),
    )?;
    openssl(
        &dir,
        vec![
            "ca", "-batch", "-notext", "-config", "ca-db/openssl.cnf", "-in", &csr, "-out", &crt,
        ],
    )?;
    std::fs::remove_file(dir.join(&csr)).ok();
    owner_only(&dir.join(&key))
}

/// Revoke an NF's current certificate and regenerate `ca.crl`. A serving NF
/// picks the new CRL up on its next accepted connection (`sbi_core::tls`
/// hot-reload); dialing NFs pick it up at restart.
pub fn revoke(dir: &Path, nf: &str) -> anyhow::Result<()> {
    let dir = dir.canonicalize().context("resolve PKI dir")?;
    let crt = format!("{nf}.crt");
    openssl(&dir, vec!["ca", "-config", "ca-db/openssl.cnf", "-revoke", &crt])?;
    gencrl(&dir)
}

/// Rotate an NF's identity: revoke the current certificate (so the old key
/// can't keep authenticating) and issue a fresh key + certificate.
pub fn rotate(dir: &Path, nf: &str, san_ip: &str) -> anyhow::Result<()> {
    revoke(dir, nf)?;
    issue(dir, nf, san_ip)
}

fn gencrl(dir: &Path) -> anyhow::Result<()> {
    openssl(dir, vec!["ca", "-config", "ca-db/openssl.cnf", "-gencrl", "-out", "ca.crl"])
}

/// Minimal `openssl ca` configuration. Absolute paths: `openssl ca` resolves
/// them from the CWD, not from the config file.
fn ca_config(dir: &Path) -> String {
    let d = dir.display();
    format!(
        "[ ca ]\n\
         default_ca = radian_ca\n\
         \n\
         [ radian_ca ]\n\
         database         = {d}/ca-db/index.txt\n\
         new_certs_dir    = {d}/ca-db/newcerts\n\
         serial           = {d}/ca-db/serial\n\
         crlnumber        = {d}/ca-db/crlnumber\n\
         certificate      = {d}/ca.crt\n\
         private_key      = {d}/ca.key\n\
         default_md       = sha256\n\
         default_days     = {DAYS}\n\
         default_crl_days = {DAYS}\n\
         policy           = radian_policy\n\
         copy_extensions  = copy\n\
         x509_extensions  = radian_leaf\n\
         unique_subject   = no\n\
         \n\
         [ radian_policy ]\n\
         commonName = supplied\n\
         \n\
         [ radian_leaf ]\n\
         basicConstraints = CA:FALSE\n"
    )
}

fn openssl(dir: &Path, args: Vec<&str>) -> anyhow::Result<()> {
    let out = Command::new("openssl")
        .args(&args)
        .current_dir(dir)
        .output()
        .context("run openssl (is it installed?)")?;
    if !out.status.success() {
        bail!("openssl {} failed: {}", args.join(" "), String::from_utf8_lossy(&out.stderr));
    }
    Ok(())
}

/// Create a file that must not already exist (a second `init` into a live PKI
/// would silently reset the issuance database).
fn write_new(path: PathBuf, content: &str) -> anyhow::Result<()> {
    if path.exists() {
        bail!("{} already exists — refusing to re-init an existing PKI", path.display());
    }
    std::fs::write(&path, content).with_context(|| format!("write {}", path.display()))
}

/// Private keys are secrets: owner-only, like the UDR's credential store.
fn owner_only(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("chmod 600 {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verify(dir: &Path, crt: &str, crl_check: bool) -> bool {
        let mut args = vec!["verify", "-CAfile", "ca.crt"];
        if crl_check {
            args.extend(["-crl_check", "-CRLfile", "ca.crl"]);
        }
        args.push(crt);
        Command::new("openssl")
            .args(&args)
            .current_dir(dir)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    #[test]
    fn init_revoke_rotate_lifecycle() {
        if !openssl_available() {
            eprintln!("skipping PKI test: openssl not found");
            return;
        }
        let tmp = std::env::temp_dir().join(format!("radian-pki-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);

        // init: a CA + all default NF identities + an (empty) CRL.
        init(&tmp, DEFAULT_NFS, "127.0.0.1").unwrap();
        for nf in DEFAULT_NFS {
            assert!(tmp.join(format!("{nf}.crt")).exists() && tmp.join(format!("{nf}.key")).exists());
            assert!(verify(&tmp, &format!("{nf}.crt"), true), "{nf}.crt verifies incl. CRL");
        }

        // revoke: the AMF's cert fails CRL-checked verification; others still pass.
        revoke(&tmp, "amf").unwrap();
        assert!(!verify(&tmp, "amf.crt", true), "revoked amf.crt is refused under CRL check");
        assert!(verify(&tmp, "amf.crt", false), "…but still chains to the CA (CRL is the gate)");
        assert!(verify(&tmp, "udm.crt", true), "unrevoked peers are unaffected");

        // rotate: the UDR gets a fresh identity that passes; re-init is refused.
        let old = std::fs::read(tmp.join("udr.crt")).unwrap();
        rotate(&tmp, "udr", "127.0.0.1").unwrap();
        assert_ne!(old, std::fs::read(tmp.join("udr.crt")).unwrap(), "cert actually changed");
        assert!(verify(&tmp, "udr.crt", true), "rotated udr.crt verifies incl. CRL");
        assert!(init(&tmp, DEFAULT_NFS, "127.0.0.1").is_err(), "re-init of a live PKI refused");

        let _ = std::fs::remove_dir_all(&tmp);
    }
}
