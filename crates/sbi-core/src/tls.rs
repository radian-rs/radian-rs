//! Mutual TLS for the SBI (TS 33.501 §13.1) — the confidentiality layer the OAuth
//! slices ([46](../../design/46-sbi-oauth.md)/[55](../../design/55-sbi-asymmetric-oauth.md))
//! left as the remaining hardening step.
//!
//! Each NF holds a certificate signed by the **core CA** plus the CA cert. A server
//! serves over TLS and **requires + verifies the client's certificate** against the
//! CA; a client presents its certificate and verifies the server against the CA. So
//! both ends authenticate the peer as a core member, and traffic is encrypted.
//!
//! rustls with the **ring** crypto provider (aws-lc-rs isn't available offline).
//!
//! **Opt-in:** an NF with `…_TLS_DIR` set loads a [`TlsIdentity`] and serves/dials
//! over mTLS; otherwise the SBI is cleartext h2c (the dev-phase default).

use std::net::SocketAddr;
use std::sync::Arc;

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use crate::SbiError;

/// An NF's mTLS identity: its certificate chain + private key + the core CA trust
/// root, loaded from PEM files.
pub struct TlsIdentity {
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    ca: Vec<CertificateDer<'static>>,
}

impl TlsIdentity {
    /// Load this NF's mTLS identity from the shared `RADIAN_SBI_TLS_DIR` directory
    /// (`<nf_name>.crt`, `<nf_name>.key`, `ca.crt`). Returns `Ok(None)` — cleartext
    /// h2c — when the env var is unset, so callers can opt into mTLS uniformly.
    pub fn from_env(nf_name: &str) -> Result<Option<Self>, SbiError> {
        match std::env::var("RADIAN_SBI_TLS_DIR") {
            Ok(dir) => Self::load(&dir, nf_name).map(Some),
            Err(_) => Ok(None),
        }
    }

    /// Load an identity from `dir`: `<name>.crt` (chain), `<name>.key`, and
    /// `ca.crt` (the core CA trust root).
    pub fn load(dir: &str, name: &str) -> Result<Self, SbiError> {
        let certs = CertificateDer::pem_file_iter(format!("{dir}/{name}.crt"))
            .map_err(|e| SbiError::Tls(format!("read {name}.crt: {e}")))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| SbiError::Tls(format!("parse {name}.crt: {e}")))?;
        let key = PrivateKeyDer::from_pem_file(format!("{dir}/{name}.key"))
            .map_err(|e| SbiError::Tls(format!("read {name}.key: {e}")))?;
        let ca = CertificateDer::pem_file_iter(format!("{dir}/ca.crt"))
            .map_err(|e| SbiError::Tls(format!("read ca.crt: {e}")))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| SbiError::Tls(format!("parse ca.crt: {e}")))?;
        Ok(Self { certs, key, ca })
    }

    fn provider() -> Arc<rustls::crypto::CryptoProvider> {
        Arc::new(rustls::crypto::ring::default_provider())
    }

    fn root_store(&self) -> Result<rustls::RootCertStore, SbiError> {
        let mut roots = rustls::RootCertStore::empty();
        for c in &self.ca {
            roots.add(c.clone()).map_err(|e| SbiError::Tls(format!("add CA cert: {e}")))?;
        }
        Ok(roots)
    }

    /// A rustls `ServerConfig` that **requires** and verifies the client certificate
    /// against the CA (mutual TLS), advertising HTTP/2 via ALPN.
    pub fn server_config(&self) -> Result<Arc<rustls::ServerConfig>, SbiError> {
        let roots = Arc::new(self.root_store()?);
        let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
            roots,
            Self::provider(),
        )
        .build()
        .map_err(|e| SbiError::Tls(format!("build client verifier: {e}")))?;
        let mut cfg = rustls::ServerConfig::builder_with_provider(Self::provider())
            .with_safe_default_protocol_versions()
            .map_err(|e| SbiError::Tls(format!("tls versions: {e}")))?
            .with_client_cert_verifier(verifier)
            .with_single_cert(self.certs.clone(), self.key.clone_key())
            .map_err(|e| SbiError::Tls(format!("server cert: {e}")))?;
        cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Ok(Arc::new(cfg))
    }

    /// A rustls `ClientConfig` that presents this identity and verifies the server
    /// against the CA, advertising HTTP/2 via ALPN.
    pub fn client_config(&self) -> Result<rustls::ClientConfig, SbiError> {
        let mut cfg = rustls::ClientConfig::builder_with_provider(Self::provider())
            .with_safe_default_protocol_versions()
            .map_err(|e| SbiError::Tls(format!("tls versions: {e}")))?
            .with_root_certificates(self.root_store()?)
            .with_client_auth_cert(self.certs.clone(), self.key.clone_key())
            .map_err(|e| SbiError::Tls(format!("client cert: {e}")))?;
        cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Ok(cfg)
    }

    /// A reqwest client that dials over mTLS with this identity (the client analogue
    /// of [`crate::h2c_client`]).
    pub fn client(&self) -> Result<reqwest::Client, SbiError> {
        reqwest::Client::builder()
            .use_preconfigured_tls(self.client_config()?)
            .build()
            .map_err(|e| SbiError::Tls(format!("build TLS reqwest client: {e}")))
    }
}

/// Serve an SBI router over **mutual TLS** on `addr` (the TLS analogue of
/// [`crate::run`]). Each accepted connection completes an mTLS handshake — a client
/// without a CA-signed certificate is rejected at the handshake — then is served by
/// `app` over HTTP/2 (or HTTP/1.1).
pub async fn run_tls(
    addr: SocketAddr,
    app: axum::Router,
    config: Arc<rustls::ServerConfig>,
) -> Result<(), SbiError> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "SBI mutual-TLS listener up");
    run_tls_on(listener, app, config).await
}

/// Serve mTLS on an already-bound listener (lets callers pick the port, e.g. an
/// ephemeral `127.0.0.1:0` in tests).
pub async fn run_tls_on(
    listener: tokio::net::TcpListener,
    app: axum::Router,
    config: Arc<rustls::ServerConfig>,
) -> Result<(), SbiError> {
    let acceptor = tokio_rustls::TlsAcceptor::from(config);
    loop {
        let (stream, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let app = app.clone();
        tokio::spawn(async move {
            let tls = match acceptor.accept(stream).await {
                Ok(tls) => tls,
                // A failed handshake (no/invalid client cert, etc.) — drop the conn.
                Err(e) => {
                    tracing::debug!(%peer, "mTLS handshake rejected: {e}");
                    return;
                }
            };
            let io = hyper_util::rt::TokioIo::new(tls);
            let service = hyper_util::service::TowerToHyperService::new(app);
            if let Err(e) = hyper_util::server::conn::auto::Builder::new(
                hyper_util::rt::TokioExecutor::new(),
            )
            .serve_connection(io, service)
            .await
            {
                tracing::debug!(%peer, "connection error: {e}");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn openssl_available() -> bool {
        std::process::Command::new("openssl")
            .arg("version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    fn sh(dir: &Path, cmd: &str) {
        let status = std::process::Command::new("sh")
            .arg("-c")
            .arg(cmd)
            .current_dir(dir)
            .status()
            .expect("run openssl");
        assert!(status.success(), "command failed: {cmd}");
    }

    /// Generate a demo PKI in `dir`: a core CA + a server cert (SAN 127.0.0.1) + a
    /// client cert (both core-signed), and a rogue CA + rogue client cert (untrusted).
    fn gen_pki(dir: &Path) {
        // Leaf certs carry extensions (EKU / SAN) so they are X.509 **v3** — rustls
        // rejects v1 certs; `-copy_extensions copy` carries them from the CSR.
        let ec = "-newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes";
        sh(dir, &format!("openssl req -x509 {ec} -keyout ca.key -out ca.crt -subj /CN=radian-ca -days 3650 2>/dev/null"));
        sh(dir, &format!("openssl req {ec} -keyout server.key -out server.csr -subj /CN=udr -addext subjectAltName=IP:127.0.0.1 -addext extendedKeyUsage=serverAuth 2>/dev/null"));
        sh(dir, "openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -out server.crt -days 3650 -copy_extensions copy -CAcreateserial 2>/dev/null");
        sh(dir, &format!("openssl req {ec} -keyout client.key -out client.csr -subj /CN=udm -addext extendedKeyUsage=clientAuth 2>/dev/null"));
        sh(dir, "openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -out client.crt -days 3650 -copy_extensions copy -CAcreateserial 2>/dev/null");
        // A rogue client signed by a DIFFERENT CA (not trusted by the core).
        sh(dir, &format!("openssl req -x509 {ec} -keyout rogue-ca.key -out rogue-ca.crt -subj /CN=rogue-ca -days 3650 2>/dev/null"));
        sh(dir, &format!("openssl req {ec} -keyout rogue.key -out rogue.csr -subj /CN=rogue -addext extendedKeyUsage=clientAuth 2>/dev/null"));
        sh(dir, "openssl x509 -req -in rogue.csr -CA rogue-ca.crt -CAkey rogue-ca.key -out rogue.crt -days 3650 -copy_extensions copy -CAcreateserial 2>/dev/null");
    }

    #[tokio::test]
    async fn mutual_tls_requires_a_core_signed_client_cert() {
        if !openssl_available() {
            eprintln!("skipping mTLS test: openssl not found");
            return;
        }
        let tmp = std::env::temp_dir().join(format!("radian-mtls-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        gen_pki(&tmp);
        let dir = tmp.to_str().unwrap();

        // A trivial mTLS server that requires a core-signed client certificate.
        let server = TlsIdentity::load(dir, "server").unwrap();
        let app = axum::Router::new().route("/", axum::routing::get(|| async { "ok" }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let cfg = server.server_config().unwrap();
        tokio::spawn(async move { run_tls_on(listener, app, cfg).await.unwrap() });
        let url = format!("https://127.0.0.1:{}/", addr.port());

        // 1) A client with a core-signed certificate is admitted.
        let client = TlsIdentity::load(dir, "client").unwrap().client().unwrap();
        let resp = client.get(&url).send().await.expect("mTLS handshake + request");
        assert_eq!(resp.status(), 200);
        assert_eq!(resp.text().await.unwrap(), "ok");

        // 2) A client presenting a rogue (non-core-CA) certificate is rejected — it
        //    trusts the core server (loads ca.crt) but its own cert isn't core-signed.
        let rogue = TlsIdentity {
            certs: CertificateDer::pem_file_iter(format!("{dir}/rogue.crt"))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap(),
            key: PrivateKeyDer::from_pem_file(format!("{dir}/rogue.key")).unwrap(),
            ca: CertificateDer::pem_file_iter(format!("{dir}/ca.crt"))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap(),
        };
        assert!(
            rogue.client().unwrap().get(&url).send().await.is_err(),
            "a client cert not signed by the core CA is rejected at the handshake"
        );

        // 3) A client presenting NO certificate is rejected (mutual auth is required).
        let no_cert = {
            let mut roots = rustls::RootCertStore::empty();
            for c in &server.ca {
                roots.add(c.clone()).unwrap();
            }
            let mut c = rustls::ClientConfig::builder_with_provider(TlsIdentity::provider())
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth();
            c.alpn_protocols = vec![b"h2".to_vec()];
            reqwest::Client::builder().use_preconfigured_tls(c).build().unwrap()
        };
        assert!(
            no_cert.get(&url).send().await.is_err(),
            "a client with no certificate is rejected (mutual auth required)"
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }
}
