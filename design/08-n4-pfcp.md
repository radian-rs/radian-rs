# N4 / PFCP — SMF ↔ UPF Control Channel

> Built 2026-06-29 on branch `feat/n4-pfcp`. The first **user-plane** slice.

Brings up the **N4 interface** (TS 29.244) — the PFCP control channel between the
SMF and the UPF that every PDU session is built on. The `pfcp` crate graduates from
a stub to the real `rs-pfcp` codec, and the UPF becomes a real N4 endpoint.

## What was built

- **`pfcp` crate** — wraps [`rs-pfcp`](https://crates.io/crates/rs-pfcp) 0.3 (TS 29.244
  codec). Adds SMF-side request builders (`association_setup_request`,
  `heartbeat_request`) and a UPF-side `handle_n4` that answers:
  - **Association Setup Request** → Association Setup Response (cause *accepted*,
    Node ID, Recovery Time Stamp).
  - **Heartbeat Request** → Heartbeat Response.
- **`nf-upf`** — binds an N4 UDP listener on `:8805` and serves PFCP via `handle_n4`.
  This is the first time the UPF does anything (it had no SBI and no datapath before).

## Why this first

PFCP is the foundation of the user plane: the SMF must establish a PFCP **association**
with a UPF before it can create any **session**. Wiring `rs-pfcp` and proving the
association/heartbeat exchange de-risks the rest of the user-plane work, which is
large (session establishment + the GTP-U datapath + the AMF↔SMF↔UPF call flow).

## Verification

- `cargo test -p pfcp` — green:
  - `n4_association_and_heartbeat` — a **real UDP round-trip**: an SMF socket sends an
    Association Setup Request to a UPF socket running `handle_n4`, receives an
    Association Setup Response, then exchanges a Heartbeat.
- Runtime: `nf-upf` binds the N4 PFCP listener on `:8805`.

## Known limitations / next steps

- **Association + heartbeat only** — no PFCP **Session Establishment** yet (PDRs/FARs,
  F-SEID, F-TEID allocation). That is the next slice and is what actually creates a
  PDU session's forwarding state in the UPF.
- **No GTP-U datapath** — the `gtpu` crate is still a stub; N3 encap/decap and the
  forwarding loop are unimplemented.
- **Stateless UPF** — associations aren't tracked; no node/session table.
- **IPv4 / single node** — Node ID is a fixed loopback IPv4; no FQDN or multi-UPF.
- **Not yet wired to the call flow** — the AMF→SMF (`Nsmf_PDUSession`) and
  SMF→UPF session setup that a UE's PDU Session Establishment Request triggers are
  future slices. End-to-end: UE NAS-SM → AMF → SMF → N4 session → N2 PDU Session
  Resource Setup → GTP-U.
