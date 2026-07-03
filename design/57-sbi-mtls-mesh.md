# SBI Mutual TLS — Full-Core Mesh

> Built 2026-07-03 on branch `feat/sbi-mtls-mesh`. Design [56](56-sbi-mtls.md)
> wired mutual TLS on the **UDR↔UDM exemplar** only. This extends it to the
> **whole core**: every NF serves its SBI over mTLS *and* dials every other NF
> over mTLS, driven by one shared identity directory and an `https` scheme that
> propagates through NRF registration/discovery. A homogeneous core — all-mTLS
> or all-h2c — flipped by a single env var.

## What was built

### A process-wide SBI transport (`sbi_core`)

Design/56 threaded an mTLS `reqwest::Client` by hand into the one client that
needed it. That doesn't scale to ~20 call sites, so the transport is now a
**process-wide singleton** configured once at startup:

- **`TlsIdentity::from_env(nf_name)`** — loads `<nf_name>.crt/.key` + `ca.crt`
  from the shared **`RADIAN_SBI_TLS_DIR`**, or `None` (h2c) when unset.
- **`configure_transport(Option<&TlsIdentity>)`** — installs the transport: with
  an identity, an mTLS client + scheme `https`; without, an h2c client + `http`.
  Called once per NF `main`, before any client is built.
- **`sbi_client()`** — the shared client every constructor now uses (mTLS or h2c).
- **`sbi_client_builder()`** — a `reqwest::ClientBuilder` on the same transport,
  for the one caller (the UDR→AMF deregistration callback) that needs an extra
  option (`redirect(none)`).
- **`sbi_scheme()`** → `"https"`/`"http"`; **`sbi_base(url)`** rewrites a
  configured base's scheme to match (so an env-supplied `http://nrf` becomes
  `https://nrf` under mTLS).

Every SBI client constructor (`NrfClient`, `UdrClient`, `NudmClient`,
`AusfClient`, `PcfClient`, `TokenSource`, `JwksCache`) switched
`h2c_client()` → `sbi_client()`. Unconfigured (tests) it falls back to h2c, so
the whole existing test surface is unchanged.

### `https` propagates through discovery

- NFs register their service with **`scheme: sbi_scheme()`** (was hardcoded
  `"http"`).
- **`NfProfile::service_base()`** builds a discovered peer's base URL from its
  advertised scheme (`{scheme}://{ip}:{port}`), so a discovering NF dials the
  transport the target actually serves. Every discovery site (AMF→AUSF, AMF→SMF,
  AMF→UDM, SMF→AMF/UDM/PCF) now goes through it instead of hardcoding `http://`.

### Per-NF `main` wiring

Each NF (`nrf`, `amf`, `smf`, `ausf`, `udm`, `udr`, `pcf`) now:
`from_env` → `configure_transport` → rewrite its configured NRF/UDR/UDM base with
`sbi_base` → serve via `run_tls` (with its `server_config()`) when an identity is
present, else `run` (h2c). The AMF also emits its own `deregCallbackUri` with the
transport scheme so the UDR dials it back over mTLS.

The design/56 per-NF envs (`RADIAN_UDR_TLS_DIR`, `RADIAN_UDM_TLS_DIR`) are
**replaced** by the single `RADIAN_SBI_TLS_DIR` (per-NF cert *name*, shared dir).

## Boundaries / notes

- **Homogeneous core** — the mesh assumes all NFs share one CA and one setting.
  Mixed http/https per-peer is representable (the scheme rides the profile) but
  not exercised; a real deployment would run all-mTLS.
- **PKI is still external** — an operator provisions the CA + per-NF certs into
  `RADIAN_SBI_TLS_DIR`. Certs must be X.509 **v3** (rustls rejects v1) and each NF
  needs **both** `serverAuth` + `clientAuth` EKU (it is both). No rotation /
  revocation (CRL/OCSP) yet — carried over from design/56.
- **Composes with OAuth** — a request still must pass the mTLS handshake *and*
  (if configured) carry a valid access token; the token endpoints/JWKS are now
  served over mTLS too.

## Verification

- `cargo test --workspace --exclude bdd` — green (116 tests). New:
  `nnrf::service_base_follows_advertised_scheme` (scheme-correct discovery URLs;
  `http` default for an empty scheme; `None` with no service).
- **BDD 2 features / 5 scenarios / 25 steps green** — default h2c, including the
  full free-ran-ue e2e (register → PDU session → ping). Unaffected by the change.
- **Live full-core mTLS (real binaries)** — NRF/UDR/UDM/AUSF/PCF started with
  `RADIAN_SBI_TLS_DIR` set to an openssl-generated per-NF PKI:
  - all five register with the NRF over `https://` (mTLS client handshake);
  - NRF **discovery** over mTLS returns the AUSF profile advertising
    `scheme: "https"`; a **no-client-cert** curl is rejected at the handshake
    (exit 55);
  - an AUSF **UEAuthentication** (with a core-signed client cert) returns a real
    5G-AKA vector (RAND/AUTN/HXRES\*, HTTP 201) — proving the **AUSF → UDM → UDR**
    chain (fixed-target *and* env-config transports) end to end over mTLS with no
    handshake errors in any log.

## Known limitations / next steps

- **Certificate rotation, CRL/OCSP revocation**, SPIFFE-style identity.
- A **PKI bootstrap tool** (generate + distribute the CA + per-NF certs) so a
  live full-core mTLS run is a single command.
- **Per-peer heterogeneous transports** (some NFs mTLS, some h2c) if a staged
  rollout ever needs it.
