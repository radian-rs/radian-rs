# PKI Bootstrap Tool + Certificate Rotation & CRL Revocation

> Built 2026-07-03 on branch `feat/pki-bootstrap-crl`. Design [57](57-sbi-mtls-mesh.md)
> left the PKI as a hand-rolled openssl runbook and revocation/rotation as open
> items. This adds **`radian-pki`** — one command stands up the whole mesh PKI —
> and makes the mesh **operable**: a certificate can be revoked (CRL, enforced on
> both sides of every handshake) or rotated, and serving NFs pick either up
> **live**, without a restart.

## What was built

### `tools/radian-pki` (new workspace member: lib + CLI)

```
radian-pki init   --dir DIR [--nfs nrf,amf,…] [--ip 127.0.0.1]
radian-pki revoke --dir DIR --nf NAME
radian-pki rotate --dir DIR --nf NAME [--ip 127.0.0.1]
```

- **`init`** — core CA + one identity per NF (`<nf>.crt/.key`) + an (initially
  empty) `ca.crl`, ready to be `RADIAN_SBI_TLS_DIR`. Refuses to re-init a live
  PKI (that would reset the issuance database).
- **`revoke`** — revokes an NF's current certificate and regenerates `ca.crl`.
- **`rotate`** — revoke the current certificate (so the old key can't keep
  authenticating), then issue a fresh key + certificate.

It drives the **`openssl` CLI** (`rcgen` isn't cached offline) but encodes every
wire-level gotcha in one place: leafs are X.509 **v3** (CSR carries the
extensions, `copy_extensions = copy`), each cert has **both** `serverAuth` and
`clientAuth` EKUs (every NF is both) plus a SAN, keys are chmod 600, and
issuance goes through a real **`openssl ca` database** (`ca-db/`,
`unique_subject = no` so rotation can re-issue a CN) — which is what makes
`-revoke`/`-gencrl` possible.

### CRL enforcement (`sbi_core::tls`)

`TlsIdentity::load` now also loads `{dir}/ca.crl` when present (present but
unreadable ⇒ **error** — fail closed, never silently skip revocation):

- **`server_config()`** — the client-cert verifier gets `.with_crls(…)`: a
  **revoked client** is refused at the handshake.
- **`client_config()`** — with a CRL, the default verifier is replaced by an
  explicit `WebPkiServerVerifier` with the CRL attached: a **revoked server**
  is refused by the dialing NF.
- rustls defaults apply: full-chain revocation check, **deny unknown status** —
  right for a single-CA core where the one CRL covers every leaf.

### Hot reload (`tls::serve` / `serve_on`)

The TLS analogue of `run`, replacing `run_tls` in every NF main: before each
accepted connection it compares the source files' mtimes (`<nf>.crt/.key`,
`ca.crt`, `ca.crl`) and rebuilds the `ServerConfig` on change — so a
`radian-pki revoke`/`rotate` takes effect on the **next connection**, no
restart. A failed reload (files mid-rewrite) keeps the previous config and
retries. `TlsIdentity` remembers its `(dir, name)` source; `run_tls`/`run_tls_on`
remain for fixed-config callers (tests).

## Boundaries / notes

- **Client-side pickup at restart** — the CRL a *dialing* NF enforces is loaded
  when its reqwest client is built (startup). Serving-side hot reload is the
  security-critical half (it gates admission); a revoked *server* is refused by
  clients restarted after the revocation.
- **No OCSP** — CRL only. An OCSP responder is a service of its own; the CRL
  covers revocation for a single-CA core mesh.
- **No CA rotation** — `rotate` rotates leaf identities; rotating the CA itself
  (cross-signing, trust-anchor rollover) is a bigger operation.
- CRL expiry (`nextUpdate`) is not enforced (rustls default) — a stale CRL still
  gates what it lists but won't fail the handshake.

## Verification

- `cargo test --workspace --exclude bdd` — green (**119** tests). New:
  - `radian_pki::init_revoke_rotate_lifecycle` — init (all NFs verify incl. CRL
    with the openssl CLI itself), revoke (fails only under `-crl_check`), rotate
    (fresh cert verifies), re-init refused.
  - `tls::crl_revocation_is_enforced_and_hot_reloaded` — against a **running**
    `serve_on`: a `radian-pki` revocation refuses that client on the next
    connection; a rotation serves the new certificate live.
  - `tls::client_refuses_a_revoked_server` — the dialing side of revocation.
- **BDD 2 features / 5 scenarios / 25 steps green** (live free-ran-ue e2e; h2c
  default unaffected).
- **Live (real binaries)** — `radian-pki init` (one command) → full core up over
  mTLS, AUSF→UDM→UDR auth chain HTTP 201; `revoke --nf amf` while the core runs
  → the running NRF refuses the revoked cert at the handshake (curl exit 56)
  while an unrevoked peer still gets 200; `rotate --nf udr` → the running UDR
  flips its served serial (1005→1007, observed via `openssl s_client`) with no
  restart and the auth chain still completes. Logs show the expected
  `TLS identity/CRL reloaded` events and nothing else.

## Known limitations / next steps

- **OCSP / CRL distribution points**, CRL `nextUpdate` enforcement.
- **CA rotation** (trust-anchor rollover, cross-signing).
- **Client-side CRL hot reload** (rebuild the process-wide transport on CRL
  change) if restart-time pickup ever proves too slow.
- SPIFFE-style workload identity remains the longer-term direction.
