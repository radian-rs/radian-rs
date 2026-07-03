//! `radian-pki` — bootstrap and maintain the SBI mutual-TLS PKI (design/58).
//!
//! One command stands up everything a full-core mTLS run needs:
//!
//! ```text
//! radian-pki init --dir /etc/radian/tls
//! RADIAN_SBI_TLS_DIR=/etc/radian/tls nf-nrf &   # …and the other NFs
//! ```

use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "radian-pki", about = "Bootstrap/maintain the radian-rs SBI mutual-TLS PKI")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create a core CA + per-NF identities + CRL, ready for RADIAN_SBI_TLS_DIR
    Init {
        /// PKI directory to create (the future RADIAN_SBI_TLS_DIR)
        #[arg(long)]
        dir: PathBuf,
        /// Comma-separated NF names to issue identities for
        #[arg(long, value_delimiter = ',', default_values_t = radian_pki::DEFAULT_NFS.iter().map(|s| s.to_string()))]
        nfs: Vec<String>,
        /// IP the certificates' SAN carries (where the NFs are reachable)
        #[arg(long, default_value = "127.0.0.1")]
        ip: String,
    },
    /// Revoke an NF's current certificate and regenerate the CRL
    Revoke {
        #[arg(long)]
        dir: PathBuf,
        /// NF whose certificate to revoke
        #[arg(long)]
        nf: String,
    },
    /// Rotate an NF's identity: revoke the current certificate, issue a fresh one
    Rotate {
        #[arg(long)]
        dir: PathBuf,
        /// NF whose identity to rotate
        #[arg(long)]
        nf: String,
        #[arg(long, default_value = "127.0.0.1")]
        ip: String,
    },
}

fn main() -> anyhow::Result<()> {
    match Cli::parse().cmd {
        Cmd::Init { dir, nfs, ip } => {
            let nfs: Vec<&str> = nfs.iter().map(String::as_str).collect();
            radian_pki::init(&dir, &nfs, &ip)?;
            println!("PKI ready in {} — point RADIAN_SBI_TLS_DIR at it", dir.display());
        }
        Cmd::Revoke { dir, nf } => {
            radian_pki::revoke(&dir, &nf)?;
            println!("{nf} revoked; ca.crl regenerated (serving NFs reload it live)");
        }
        Cmd::Rotate { dir, nf, ip } => {
            radian_pki::rotate(&dir, &nf, &ip)?;
            println!("{nf} rotated: old certificate revoked, fresh identity issued");
        }
    }
    Ok(())
}
