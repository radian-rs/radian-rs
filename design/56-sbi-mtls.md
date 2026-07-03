# SBI Mutual TLS — Implementation Notes

> Built 2026-07-03 on branch `feat/sbi-mtls`. The confidentiality layer the OAuth
> slices ([46](46-sbi-oauth.md)/[55](55-sbi-asymmetric-oauth.md)) deferred: the SBI
> has been cleartext **h2c** since [04](04-sbi-spine-nrf.md). This adds **mutual
> TLS** (TS 33.501 §13.1) — each NF presents a **core-CA-signed certificate**, both
> ends verify the peer, and traffic is encrypted. Opt-in, wired on the UDR↔UDM
> exemplar (as OAuth was).

## What was built

### `sbi_core::tls`

- **`TlsIdentity`** — an NF's cert chain + private key + the core CA trust root,
  `load`ed from PEM files (`<name>.crt`, `<name>.key`, `ca.crt`) via
  `rustls-pki-types`' `PemObject`.
  - **`server_config()`** — a rustls `ServerConfig` that **requires** a client
    certificate and verifies it against the CA (`WebPkiClientVerifier`); ALPN `h2`.
  - **`client_config()` / `client()`** — a rustls `ClientConfig` (and a reqwest
    client via `use_preconfigured_tls`) that presents this identity and verifies the
    server against the CA.
- **`run_tls` / `run_tls_on`** — serve an axum router over mTLS: a `tokio-rustls`
  accept loop (a client without a CA-signed cert is rejected **at the handshake**)
  feeding `hyper-util`'s auto server. The TLS analogue of `run` / `run_on`.

### Crypto backend — ring (offline constraint)

`aws-lc-rs` (rustls's default) isn't available offline, so everything pins the
**ring** provider: `rustls`/`tokio-rustls` with `default-features = false,
features = ["ring", …]`, and reqwest with `rustls-no-provider`. That reqwest
feature requires a process-default provider before building **any** client (even
h2c), so `h2c_client()` now installs `rustls::crypto::ring::default_provider()`
once (`ensure_crypto_provider`).

### Wiring (opt-in, the UDR↔UDM exemplar)

- **`nf-udr`** — with `RADIAN_UDR_TLS_DIR` set, loads its identity and serves via
  `run_tls` (mutual TLS) instead of `run` (h2c).
- **`nf-udm`** — with `RADIAN_UDM_TLS_DIR` set, builds the `UdrClient` with an mTLS
  reqwest client (`UdrClient::with_transport`) and rewrites the UDR base to `https`.
- mTLS composes with the OAuth layers: a request must pass the mTLS handshake **and**
  (if configured) carry a valid access token.

## Boundaries / notes

- **Exemplar scope** — only the UDR serves mTLS (the UDM dials it), mirroring the
  OAuth exemplar. Extending to the NRF is heavier (every NF registers/discovers/gets
  tokens through it); the other server↔client pairs are mechanical follow-ups.
- **PKI is external** — certs are loaded from a directory; provisioning them (a CA +
  per-NF certs) is an operator/deployment step. The tests generate a demo PKI with
  the `openssl` CLI (`rcgen` isn't available offline). Certs must be X.509 **v3**
  (rustls rejects v1) — leaf certs carry an EKU/SAN extension.
- **No cert rotation / revocation** (CRL/OCSP) yet.

## Verification

- `cargo test --workspace --exclude bdd` — green (115 tests). New:
  - `tls::mutual_tls_requires_a_core_signed_client_cert` — generates a demo PKI,
    serves a trivial mTLS router, and asserts: a **core-signed** client is admitted
    (200), a **rogue-CA** client is rejected, and a **no-cert** client is rejected —
    i.e. mutual authentication. (Skips if `openssl` is absent.)
- **BDD 5 scenarios / 25 steps green** — default h2c, unaffected.
- **Live (real binaries)**: the `nf-udr` binary with `RADIAN_UDR_TLS_DIR` set serves
  over mutual TLS; a `curl` with **no client certificate is rejected** (exit 55, no
  response) and a `curl` with the **core-signed client cert is authorized** (404 =
  no record, through the mTLS layer).

## Known limitations / next steps

- **Extend mTLS to the NRF and the other NFs** (AUSF/SMF/AMF/PCF), and make the NRF
  profile scheme (`http`/`https`) drive discovered client transports.
- **Certificate rotation, CRL/OCSP revocation**, and SPIFFE-style identity.
- A **PKI bootstrap tool** (generate + distribute the CA + per-NF certs) so a live
  full-core mTLS run is a single command.
