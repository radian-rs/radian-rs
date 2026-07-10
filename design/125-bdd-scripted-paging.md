# BDD Scripted Paging Trigger (downlink data → paging)

> Built 2026-07-09 on branch `feat/bdd-scripted-paging`. Eighth BDD slice of the design/116
> plan: a **real downlink packet to a CM-IDLE UE triggers paging** end-to-end (design/65) —
> UPF buffer → Downlink Data Report → SMF → AMF → NGAP Paging — driven and asserted from the
> scripted gNB, using the loopback-alias datapath topology from design/124. Pure test code;
> no crate behaviour changed.

## What was built (all in `bdd`)

- **Inject step** — "a downlink packet arrives for the UE on the data network": a UDP send to
  the UE's assigned IP. The host routes `10.45.0.0/16` to the UPF's `n6upf0` TUN, so the UPF
  sees a genuine downlink packet for the (now CM-IDLE) UE — it buffers it and raises a
  Downlink Data Report.
- **Assertion step** — "the gNB is paged for the UE in TAC …": the scripted gNB receives an
  NGAP `Paging` on its association and asserts it carries the UE's 5G-S-TMSI
  (`tmsi_from_paging`) and a TAI list covering the UE's TAC (`tacs_from_paging`).
- **Scenario** in `scripted_datapath.feature`: register → PDU session → AN release (CM-IDLE) →
  inject a downlink packet → the gNB is paged. It reuses the shared core the datapath echo
  scenario starts.

The whole chain is real: after the AN release the UPF's downlink FAR is `BUFF`+`NOCP`
(design/65), so the injected packet is buffered and a Downlink Data Report goes to the SMF;
`handle_dl_data_report` discovers the AMF and POSTs `Namf_Communication_N1N2MessageTransfer`;
`page_ue` resolves the SUPI to its retained 5G-TMSI and `spawn_paging` broadcasts to the
gNB associations, which build the `Paging` the scripted gNB then reads.

## Verification

- **`cargo test -p bdd` — 3 features / 17 scenarios / 171 steps GREEN** (deterministic across
  reruns): the new scenario drives the full downlink-data → paging chain against the live
  core; the rest of the suite is unaffected.
- `cargo clippy -p bdd --tests` — no net-new warnings (1 site before == after).
- No workspace crate changed.

## Boundaries / next

- This slice proves the **paging trigger** — the DL packet reaches the UPF, buffers, reports,
  and the gNB is paged. The **buffer flush on resume** (the UE resumes with a Service Request,
  the UPF flushes the buffered packet to the new N3 tunnel, and the gNB receives it) is the
  natural follow-up: it needs the gNB to hold an N3 socket across the resume and a small
  `bdd::datapath` helper to receive the flushed G-PDU. Design/65 already covers the flush
  path in the core; this only adds the scripted assertion.
- Beyond that: **T3513** paging retransmission (design/74 — shrink the timer env, count the
  repeated pagings), and **per-flow QoS / GBR** traffic policing over the datapath (designs
  49/51). Then the handover / lifecycle features.
