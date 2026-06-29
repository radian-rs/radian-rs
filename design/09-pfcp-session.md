# PFCP Session Establishment — Provisioning the User Plane

> Built 2026-06-29 on branch `feat/pfcp-session`. The N4 step that actually creates a PDU session's forwarding state.

Extends N4 (TS 29.244) from node-level association to **session establishment**: the
SMF provisions an uplink PDR/FAR and the UPF **allocates an N3 F-TEID**, tracks the
session, and returns its UP F-SEID + the allocated F-TEID. This is the forwarding
state every PDU session's data path is built on.

## What was built

- **`pfcp` crate**
  - SMF-side `session_establishment_request` — builds a basic uplink PDU session: a
    Create PDR (PDI source = Access → FAR 1) and a Create FAR (forward to Core).
  - `UpfState` — N3 TEID / UP-SEID allocators + a session table (UP-SEID → N3 TEID).
  - `handle_n4` is now **stateful** and handles **Session Establishment Request**:
    reads the SMF's CP F-SEID, allocates a UP-SEID + N3 F-TEID, records the session,
    and replies with cause *accepted*, the UP F-SEID, and a Created PDR carrying the
    allocated F-TEID.
- **`nf-upf`** — serves the stateful handler and logs the live session count.

## Security review fix (PR #9)

The push review flagged the UPF's N4 loop. Addressed here:

- **Fail-open recv loop (DoS) — fixed.** The loop previously used `?` on
  `recv_from`/`send_to`, so a single datagram error tore down the whole UPF. It now
  logs per-datagram errors and keeps serving. Malformed PFCP is already handled
  (`parse(...).ok()` → "unhandled", no panic).
- **Unauthenticated N4 on 0.0.0.0 — acknowledged, deferred.** PFCP has no app-layer
  auth (TS 29.244); it relies on an isolated N4 network / IPsec (TS 33.501). A
  `# Security` caveat is now in `nf-upf`; binding to the N4 address + IPsec is part of
  the deferred network-hardening slice (same posture as the SBI findings).

## Verification

- `cargo test -p pfcp` — green:
  - `session_establishment_allocates_and_tracks` — `handle_n4` on a Session
    Establishment Request allocates an F-TEID, records the session
    (`session_count() == 1`), and returns a Created PDR + UP F-SEID.
  - `n4_exchange_over_udp` — a real UDP round-trip: associate → heartbeat →
    **session establishment**.
- Runtime: `nf-upf` binds N4 on `:8805`.

## Known limitations / next steps

- **Uplink only** — the downlink PDR/FAR (Core → Access with Outer Header Creation
  to the **gNB** F-TEID) isn't set up yet; the gNB F-TEID is learned after N2 PDU
  Session Resource Setup and applied via **PFCP Session Modification** (next).
- **No GTP-U datapath** — the `gtpu` crate is still a stub; nothing forwards packets.
- **No session modification/deletion** in `handle_n4` yet.
- **Not wired to the call flow** — a real session is triggered by the UE's NAS-SM
  (PDU Session Establishment Request) → AMF → SMF (`Nsmf_PDUSession`) → this N4 setup
  → N2 PDU Session Resource Setup. That orchestration is a later slice.
