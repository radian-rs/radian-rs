# SBI Spine + NRF — Implementation Notes

> Built 2026-06-29 on branch `feat/sbi-spine-nrf`. The first real JSON / HTTP-2 surface.

This graduates `sbi-core` from a placeholder TCP loop to a real **HTTP/2 + JSON**
SBI runtime, and stands up the **NRF** — the registry every other NF depends on.
It unblocks the authentication slice (AMF → AUSF → UDM).

## What was built

- **`sbi-core` transport** — a real SBI server runner (`run` / `run_on`) over
  `axum`/`hyper`, and an h2c JSON client (`h2c_client`). Plus `ProblemDetails`
  (RFC 7807) and `new_nf_instance_id()` (UUIDv4).
- **NRF** (`sbi_core::nnrf`) — Nnrf_NFManagement + Nnrf_NFDiscovery (TS 29.510):
  the `NfProfile` model, an in-memory `NrfStore`, the `router`, and an `NrfClient`
  other NFs use to register/discover.
- **NF binaries** — `nf-nrf` runs the real NRF; the other SBI NFs (`nf-smf`,
  `nf-ausf`, `nf-udm`, `nf-udr`, `nf-pcf`) now serve a real (otherwise empty)
  HTTP/2 health endpoint via `sbi_core::run`.

## Transport choices

- **HTTP/2 cleartext (h2c), no TLS.** Server: `axum::serve` uses hyper's auto
  builder, serving both HTTP/1.1 and HTTP/2 by sniffing the connection preface.
  Client: `reqwest` with `.http2_prior_knowledge()` forces h2c. This matches a
  typical intra-core SBI deployment (TLS/OAuth2 are a later hardening slice).
- **camelCase JSON** via serde `rename_all`, matching the 3GPP OpenAPI field names
  (`nfInstanceId`, `nfType`, …); discovery query params are kebab-case
  (`target-nf-type`).

## NRF API (TS 29.510)

| Method & path | Operation | Result |
|---|---|---|
| `PUT /nnrf-nfm/v1/nf-instances/{id}` | NFRegister | `201` + profile |
| `PATCH /nnrf-nfm/v1/nf-instances/{id}` | NFUpdate / heartbeat | `204`, or `404` if unknown |
| `DELETE /nnrf-nfm/v1/nf-instances/{id}` | NFDeregister | `204` |
| `GET /nnrf-nfm/v1/nf-instances` | NFListRetrieval | `200` + all profiles |
| `GET /nnrf-disc/v1/nf-instances?target-nf-type=…` | NFDiscovery | `200` + matching profiles |

The path is authoritative for the NF instance ID on register; `nfStatus` defaults
to `REGISTERED`.

## Verification

- `cargo test -p sbi-core` — green:
  - `register_discover_heartbeat_deregister` — full lifecycle over **real h2c**
    (axum server + reqwest h2c client on an ephemeral port): an AUSF registers, the
    AMF discovers it, heartbeat, deregister, re-discovery empty.
  - `heartbeat_unknown_nf_errors` — heartbeat on an unknown NF → `404` → error.
- Runtime smoke test of the `nf-nrf` binary: `PUT` register → `201`; `GET`
  discovery over `--http2-prior-knowledge` → `http/2 200` returning the profile.

## Crate impact

`sbi-core` gained `axum`, `reqwest` (h2c: `default-features = false`,
`json`/`http2`/`query`), and `uuid`. The `nnrf` module lives in `sbi-core` because
the registry is core infrastructure every NF needs; future *service* APIs
(`nausf`, `nudm`, …) can become their own crates.

## Known limitations / next steps

- **In-memory registry** — no persistence; no heartbeat-timer expiry (a stale NF is
  never evicted); single NRF instance.
- **No TLS / OAuth2** — h2c only; SBI security (TLS, `Nnrf` access tokens) is a
  later hardening slice.
- **Trimmed `NfProfile`** — only the fields this stack uses; discovery filters by
  `target-nf-type` only (no S-NSSAI / DNN / service-name filters).
- **NFs don't self-register yet** — only the NRF runs the registry; wiring each NF
  to register on startup comes with the auth slice.
- **Next slice** — `Nausf_UEAuthentication` (AUSF) + `Nudm_UEAuthentication` (UDM)
  with Milenage/5G-AKA, then wire the AMF to discover the AUSF via NRF and drive
  Authentication Request → Security Mode → Registration Accept.
