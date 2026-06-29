# PFCP Session Modification — the Downlink Path

> Built 2026-06-29 on branch `feat/pfcp-session-modification`. The N4 control step that points downlink traffic at the gNB.

Session Establishment (slice 09) set up the **uplink** half: a PDR matching traffic
from the access side and the UPF's own N3 F-TEID. The **downlink** half can't be
completed at establishment because the gNB's F-TEID isn't known yet — it comes back in
the **N2 PDU Session Resource Setup Response**. This slice adds the **PFCP Session
Modification** that carries that gNB F-TEID to the UPF as **Outer Header Creation**.

## What was built

- **`pfcp::session_modification_request(up_seid, seq, far_id, gnb_teid, gnb_ip)`** —
  an **Update FAR** with `ApplyAction=FORW` and **Update Forwarding Parameters →
  Outer Header Creation** (GTP-U/IPv4) to the gNB's N3 F-TEID. Addressed by the
  **UP-SEID** the UPF handed out at establishment.
- **`pfcp::handle_n4`** — a `SessionModificationRequest` arm: reads the gNB target out
  of the Update FAR's Outer Header Creation, stores it on the session
  (`UpfState::set_downlink`), and replies `SessionModificationResponse` (accepted).
- **`UpfState`** — the session table now holds an optional downlink `(TEID, IP)`;
  `downlink_for(up_seid)` exposes it to the GTP-U datapath. `nf-upf` picks this up for
  free (its N4 loop already dispatches through `handle_n4`).

## The flow this completes

```
Establishment :  SMF → UPF   uplink PDR + UPF allocates N3 F-TEID (uplink)
   (N2 setup) :  gNB → AMF → SMF   gNB returns its own N3 F-TEID (downlink)
Modification  :  SMF → UPF   Update FAR + Outer Header Creation(gNB F-TEID)
   → UPF now encapsulates downlink packets toward the gNB
```

## Verification

- `cargo test` — green (32 tests workspace-wide). New:
  - `pfcp::session_modification_installs_downlink` — establish → modify → the response
    is a `SessionModificationResponse` and `downlink_for(up_seid)` returns the gNB
    `(TEID, IP)`.
  - `nf-upf::downlink_path_encaps_to_gnb_teid` — after modification, the UPF
    encapsulates a downlink packet as a GTP-U **G-PDU addressed to the gNB's TEID**.

## Known limitations / next steps

- **No N6 ingress** — downlink packets originate from the data network; the UPF still
  has no TUN/raw socket to receive them. The encap capability is proven; the live
  downlink loop awaits N6 forwarding.
- **gNB F-TEID is supplied directly** in tests — wiring it from a real **N2 PDU Session
  Resource Setup Response** is the call-flow orchestration slice (AMF↔SMF
  `Nsmf_PDUSession`, N2-SM-info).
- **No QER / buffering / BAR** — no QoS enforcement or downlink-data buffering yet.
- **No UE IP ↔ session lookup** — downlink routing by UE IP (the FAR's PDI on the core
  side) isn't modeled; only the per-session downlink target is stored.
