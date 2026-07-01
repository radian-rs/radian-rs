# The SBI Spine and the NRF

Most of a 5G core is not binary protocols — it is control-plane NFs talking to
each other over HTTP. That bus is the **Service-Based Interface (SBI)**, and the
NF that lets everyone find everyone else is the **NRF** (Network Repository
Function).

## SBI transport

radiant-rs's SBI is **HTTP/2 cleartext (h2c)** with JSON bodies. `crates/sbi-core`
provides both ends:

- a server built on `axum`, exposed via `sbi_core::run(addr, router)`;
- a client built on `reqwest` with HTTP/2 prior knowledge
  (`sbi_core::h2c_client()`).

JSON uses the 3GPP OpenAPI conventions — camelCase field names, `serde`
`rename_all`. There is no TLS and no OAuth2 token check: SBI is
**unauthenticated** at this stage and relies on a trusted network segment. This
is a documented gap (TS 33.501) rather than a finished posture.

## The NRF

The NRF (`nf-nrf`, SBI on **:8000**) implements the two services that make the
service mesh self-organising (TS 29.510):

- **Nnrf_NFManagement** — NFs **register**, **heartbeat**, and **deregister**
  their profiles.
- **Nnrf_NFDiscovery** — NFs **discover** peers by type.

An NF profile names the NF instance, its type (`AMF`, `SMF`, `AUSF`, …), status,
addresses, and the services it offers (each with a service name and an
IP/port endpoint). Registration is a `PUT`:

```
PUT /nnrf-nfm/v1/nf-instances/{nf_instance_id}
```

and discovery is a `GET`:

```
GET /nnrf-disc/v1/nf-instances?target-nf-type=AUSF&requester-nf-type=AMF
```

The store is in-memory.

## Who registers, who discovers

| NF | Registers with NRF | Discovers via NRF |
|----|--------------------|-------------------|
| **SMF** | yes — `nsmf-pdusession` | — |
| **AUSF** | yes — `nausf-auth` | — |
| **AMF** | — | AUSF (for auth), SMF (for sessions) |

The SMF and AUSF **self-register** on startup. The AMF is a pure consumer: when a
UE authenticates it does `discover("AUSF", "AMF")`, and when a UE starts a session
it does `discover("SMF", "AMF")`, using whatever endpoint the NRF returns.

The NRF base each NF uses is configurable:

```
RADIANT_SMF_NRF=http://127.0.0.1:8000     # SMF
RADIANT_AUSF_NRF=http://127.0.0.1:8000    # AUSF
```

The AMF's NRF base is fixed at `http://127.0.0.1:8000`.

## The service modules

`sbi-core` also hosts the SBI **server** logic for several NFs so they can stay
thin binaries:

- `sbi_core::nnrf` — the NRF service (used by `nf-nrf`).
- `sbi_core::nausf` — `Nausf_UEAuthentication` (used by `nf-ausf`).
- `sbi_core::nudm` — `Nudm_UEAuthentication`, a stateless front end over the
  subscriber store (used by `nf-udm`).

The SMF's `Nsmf_PDUSession` server lives in the `nf-smf` binary itself, because it
is tightly coupled to that NF's PFCP state.

## Verification

Register and discover an NF by hand with `curl` (h2c prior knowledge):

```
curl --http2-prior-knowledge \
  "http://127.0.0.1:8000/nnrf-disc/v1/nf-instances?target-nf-type=SMF&requester-nf-type=AMF"
```

A registered SMF comes back as a JSON `nfInstances` array with its
`nsmf-pdusession` endpoint.
