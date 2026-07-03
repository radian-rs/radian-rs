# Per-flow GBR Enforcement at the UPF — QERs + Classifier — Implementation Notes

> Built 2026-07-02 on branch `feat/upf-per-flow-gbr`. Extends the session-AMBR
> policing of [49](49-upf-ambr-qer.md): a GBR QoS flow now gets its **own** QER
> (MBR = MFBR) and a **packet classifier**, so the UPF steers matching traffic to
> the flow and polices it against its guaranteed rate — independently of the
> aggregate session AMBR.

## What was built

### PFCP — per-flow QERs + a classifier (`pfcp`)

- **`FlowFilter { protocol, port_low, port_high }`** — a compact packet classifier
  (transport protocol + a port range, matched against **either** endpoint). It is
  a greenfield stand-in for a full TS 29.244 SDF filter; it's carried in the PDR's
  **SDF filter** field as a self-described `flow_description`
  (`proto=<n>;ports=<lo>-<hi>`) — a production UPF parses IPFilterRule syntax.
- **`FlowQer { qfi, filter, mfbr_dl_bps, mfbr_ul_bps }`** — what the SMF installs
  per GBR flow.
- **`session_establishment_request(.., flows: &[FlowQer])`** — per flow, adds a
  **Create QER** (id `PER_FLOW_QER_BASE + qfi`, MBR = MFBR) + a **classifier PDR**
  (higher precedence, SDF filter, bound to that QER). The session-AMBR QER (id 1)
  is unchanged.
- **`handle_n4`** links each classifier PDR (SDF filter) to its QER's MBR by
  `qer_id` and installs a per-flow policer on the session.
- **The datapath classifies + polices**: `UpfState::admit_uplink/admit_downlink`
  now take the packet; `Session::admit` extracts `(protocol, src_port, dst_port)`
  (`transport_key`) and polices the packet against the **first matching flow's**
  MFBR token bucket, falling back to the session-AMBR bucket for unmatched (non-GBR)
  traffic. `UpfState::flow_qfis` exposes the installed flows.

### Policy → SMF (`sbi_core::npcf`, `nf-smf`, `nf-udr`)

- **`npcf::QosFlowPolicy`** gains an optional **`filter: PacketFilterPolicy`**
  (`{protocol, portLow, portHigh}`). The demo GBR flow (`PolicyConfig::demo`) and
  the **UDR** demo policy-data both carry `UDP 5000–5010`.
- **`nf-smf`** builds the `FlowQer`s from the decision's GBR flows that carry a
  filter (`flow_qers`) and passes them into the N4 establishment.

## Model / boundaries

- **Session AMBR (aggregate non-GBR) + per-flow GBR** are enforced together: a
  packet is policed by the first matching per-flow QER, else the session AMBR.
- **Classifier is a protocol + port-range** matched against either endpoint — a
  simplification of directional SDF filters (uplink vs. downlink packet filters).
  One classifier per flow applies to both directions.
- **Establishment-time only.** A GBR flow's per-flow QER is installed at session
  setup; a **mid-session per-flow re-rate / add / release** (the analogue of the
  session-AMBR `session_qer_update_request`) is a follow-up — the mid-session
  refresh (design/49/50) still re-rates only the session AMBR at the UPF.
- No **URR / usage reporting**, no **GFBR** admission control (only the MFBR ceiling
  is policed, not the guaranteed floor), no **buffering / gate control**.

## Verification

- `cargo test --workspace --exclude bdd` — green (108 tests). New:
  - `pfcp::flow_filter_matches_and_roundtrips` — the classifier match + the SDF
    `flow_description` round trip.
  - `pfcp::per_flow_qer_polices_matched_flow_independently` — an establishment with
    a small (80 kbps) per-flow QER under a large session AMBR: matching UDP :5005
    bursts then throttles at the MFBR, while non-matching UDP :9999 still rides the
    session AMBR.
  - `n6::per_flow_gbr_policed_through_datapath` — the same, through `n6::uplink`
    (classified + policed in the forwarding path; `RateLimited` on the GBR flow,
    forwarded on the session AMBR).
  - `nf-smf::pcf_drives_sm_policy_and_release_deletes_it` (extended) — asserts the
    PCF's GBR flow's per-flow QER reaches the UPF (`flow_qfis(1) == [2]`).
- **BDD, 5 scenarios / 25 steps green**, incl. the live **`@sim`** e2e — the demo
  session installs the GBR flow's per-flow QER (UDP 5000–5010); the free-ran-ue
  ping is ICMP, so it doesn't match and rides the session AMBR — the datapath is
  unaffected.

## Known limitations / next steps

- **Mid-session per-flow QoS change** (re-rate / add / remove a flow) at the UPF +
  RAN/UE, extending design/49/50 to per-flow.
- **GFBR admission control** and **usage reporting** (URR); **buffering / QER gate**.
- **Directional / richer SDF filters** (real IPFilterRule parsing), and IP-address
  match beyond protocol + ports.
