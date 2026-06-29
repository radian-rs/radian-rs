# GTP-U Datapath — N3 Uplink Decapsulation

> Built 2026-06-29 on branch `feat/gtpu-datapath`. The UPF's first user-plane packet handling.

Fleshes out the `gtpu` stub into a real GTP-U (TS 29.281) codec and gives the UPF an
**N3 listener**, so it now serves both user-plane planes — N4 (PFCP control) and N3
(GTP-U data) — over one shared session table. An uplink G-PDU is decapsulated and
routed to the session whose N3 TEID the PFCP layer allocated.

## What was built

- **`gtpu` crate** — a dependency-free codec:
  - `parse` → `N3Message` (G-PDU / Echo Request / Echo Response / Other), handling the
    8-byte header (+4 optional octets when the sequence flag is set).
  - `encap(teid, payload)` / `decap` for G-PDUs; `echo_request` / `echo_response`.
- **`nf-upf`** — two concurrent UDP loops over a shared `Arc<Mutex<UpfState>>`:
  - **N4 (:8805)** — PFCP (association / heartbeat / session establishment).
  - **N3 (:2152)** — GTP-U: answers Echo, and for an uplink **G-PDU** checks the TEID
    against the session table (`UpfState::knows_teid`), decapsulates, and logs the
    inner packet (forwarding to N6 is TODO).

## The N4 ⇄ N3 link

This is the slice where the control and data planes of the UPF meet: PFCP Session
Establishment allocates an N3 F-TEID (slice 09); GTP-U uses that same TEID to route
an uplink packet to its session. The headline test exercises exactly that path.

## Verification

- `cargo test` — green (26 tests workspace-wide):
  - `gtpu`: `gpdu_encap_decap_roundtrip`, `echo_roundtrip`,
    `rejects_non_gtpv1_short_and_non_gpdu`.
  - `nf-upf`: `n3_uplink_recognizes_session_teid` — establish a session over N4,
    then an uplink G-PDU on the allocated TEID decaps to its inner packet and is
    recognized as belonging to a known session.
- Runtime: `nf-upf` binds **both** N4 (:8805) and N3 (:2152).

## Known limitations / next steps

- **No N6 forwarding** — decapsulated uplink packets are logged, not written to a
  data network (needs a TUN / raw socket). The actual packet egress is future.
- **No downlink path** — requires a downlink PDR/FAR with **Outer Header Creation**
  to the **gNB** F-TEID, which is learned after N2 PDU Session Resource Setup and
  applied via **PFCP Session Modification** (next user-plane slice).
- **No extension headers / N-PDU numbers** — parsed-around but not interpreted.
- **Not wired to the call flow** — the end-to-end PDU session (UE NAS-SM → AMF → SMF
  `Nsmf_PDUSession` → N4 → N2 resource setup → GTP-U) is a later orchestration slice.
