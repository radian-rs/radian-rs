# Per-Flow QoS (5QI / GBR / ARP) — Implementation Notes

> Built 2026-07-03 on branch `feat/per-flow-qos`. Retires the last big QoS
> simplification: the single hardcoded non-GBR flow (5QI 9, default ARP) in the
> N2 setup transfer and the lone match-all rule in the N1 accept. QoS is now
> per-flow — 5QI, ARP, and GBR rates — driven by the subscription, and carried
> to **both** the RAN (N2 transfer) and the UE (N1 accept).

## What was built

- **NGAP** (`crates/ngap`): `QosFlow { qfi, five_qi, arp_priority, pre_empt_cap,
  pre_empt_vuln, gbr: Option<Gbr> }` (+ `Gbr` GFBR/MFBR in bits/sec). The setup
  transfer builds one `QosFlowSetupRequestItem` per flow — NonDynamic5QI, the
  flow's ARP, and `GBR_QosInformation` when guaranteed.
  `pdu_session_resource_setup_request(..., flows: &[QosFlow], ...)`.
- **NAS** (`crates/nas`): `QosFlowDesc { qfi, five_qi, gbr: Option<GbrFlow> }`
  and the **Authorized QoS flow descriptions** IE (0x79, TS 24.501 §9.11.4.12).
  The byte layout matches free5gc-nas exactly — `QFI`, `opcode<<5` (create),
  `E<<6 | nParams`, then `id,len,content` params (5QI, and GFBR/MFBR as unit +
  16-bit value, reusing the Session-AMBR encoding). The accept builder emits the
  IE when the flow list is non-empty; an empty list leaves the single-flow
  accept **byte-for-byte unchanged**.
- **Subscription → SMF → AMF**: sm-data's `dnnConfigurations[dnn].5gQosProfile`
  gives the default flow's 5QI/ARP (QFI 1); an optional `qosFlows` array adds GBR
  flows (a demo stand-in for PCF-driven flows). The SMF returns `qosFlows` in
  CreateSMContext; the AMF parses them into NGAP form (bits/sec GBR) for the N2
  transfer and NAS form (unit/value GBR) for the N1 flow descriptions. Fail-open:
  no flows → the AMF sends the default non-GBR flow and omits the N1 IE.
- **Demo provisioning**: the demo subscriber now carries a default 5QI-9 flow +
  a GBR flow (QFI 2, 5QI 1, GFBR 100 Mbps / MFBR 200 Mbps each way).

## Verification

- `cargo test --workspace --exclude bdd` — green (26 suites). New:
  - `ngap::pdu_session_resource_setup_request_roundtrips` now carries a default
    + a GBR flow through APER.
  - `nas::qos_flow_descriptions_ie_encoding` — exact byte assertions against the
    free5gc layout (non-GBR + GBR), the 0x79 IE in the accept, and that an empty
    flow list omits the IE.
  - `nf-smf` create test asserts the default + GBR flow ride back in the response.
- **Live `@sim` (the headline)**: the demo now provisions **two flows incl. a
  GBR flow**. free-ran-ue's **free5gc-ngap gNB accepts both flows in the N2
  transfer**, its **free5gc-nas UE decodes the accept carrying the 0x79 flow
  descriptions IE** (with GBR params), and the PDU session + datapath ping
  complete (5 scenarios / 25 steps green). So per-flow QoS is wire-verified on
  both interfaces against a real free5GC stack — not just unit-pinned.

## Known limitations / next steps

- **One match-all QoS rule** in the N1 (all traffic → default flow). Per-flow
  packet filters (mapping specific traffic to the GBR flow) need a traffic
  classifier we don't model; the flow *descriptions* are complete, the *rules*
  are still the single default.
- **GBR flows from sm-data** — a stand-in; real GBR/PCC rules come from the PCF
  (still a scaffold).
- SBI security hardening (TLS/OAuth2) remains the big open item.
