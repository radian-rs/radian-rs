# The SBI Spine and the NRF

Most of a 5G core is not binary protocols — it is control-plane NFs talking to
each other over HTTP. That bus is the **Service-Based Interface (SBI)**, and the
NF that lets everyone find everyone else is the **NRF** (Network Repository
Function).

## SBI transport

radian-rs's SBI is **HTTP/2 cleartext (h2c)** with JSON bodies. `crates/sbi-core`
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
| **AMF** | yes — `namf-callback` | AUSF, SMF, UDM, PCF |
| **SMF** | yes — `nsmf-pdusession` | UDM, PCF, CHF |
| **AUSF** | yes — `nausf-auth` | — |
| **UDM** | yes — `nudm-ueau` / `nudm-sdm` | — |
| **UDR** | yes — `nudr-dr` | — |
| **PCF** | yes — `npcf-smpolicycontrol` / `npcf-am-policy-control` | — |
| **CHF** | yes — `nchf-convergedcharging` | — |

Every SBI NF **self-registers** on startup and heartbeats to stay in the registry.
The **AMF** and **SMF** are the discoverers: when a UE authenticates the AMF does
`discover("AUSF", "AMF")`, when it starts a session the AMF does `discover("SMF",
"AMF")`, and each in turn discovers the UDM/PCF/CHF it needs — always using
whatever endpoint the NRF returns. The AMF also registers its own
`namf-callback` service so SBI callbacks (a UDR subscription withdrawal, a PCF
`UpdateNotify`) can find their way back to it.

A few backend links are still **configured static bases** rather than NRF-discovered:
AUSF→UDM (`:8004`, fixed for now), UDM→UDR (`RADIAN_UDM_UDR`, default `:8005`), and
PCF→UDR (`RADIAN_PCF_UDR`, default `:8005`). Moving these onto NRF discovery is
incremental work behind the same client seam.

The NRF base each NF uses is configurable — `RADIAN_<NF>_NRF`, e.g.:

```
RADIAN_SMF_NRF=http://127.0.0.1:8000     # SMF
RADIAN_AUSF_NRF=http://127.0.0.1:8000    # AUSF
RADIAN_PCF_NRF=http://127.0.0.1:8000     # PCF   (likewise UDR, UDM, CHF)
```

The AMF's NRF base is fixed at `http://127.0.0.1:8000`.

## The service modules

`sbi-core` also hosts the SBI **server** logic for several NFs so they can stay
thin binaries:

- `sbi_core::nnrf` — the NRF service (used by `nf-nrf`).
- `sbi_core::nausf` — `Nausf_UEAuthentication` (used by `nf-ausf`).
- `sbi_core::nudm` — `Nudm_UEAuthentication` / `Nudm_SDM`, a stateless front end
  that relays to the UDR over `Nudr` (used by `nf-udm`).
- `sbi_core::nudr` — the `Nudr` data-repository service over the subscriber store
  (used by `nf-udr`).
- `sbi_core::npcf` / `npcf_am` — `Npcf_SMPolicyControl` / `Npcf_AMPolicyControl`
  (used by `nf-pcf`).
- `sbi_core::nchf` — `Nchf_ConvergedCharging` (used by `nf-chf`).

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
