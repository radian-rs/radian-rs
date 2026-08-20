# 155 — N4 URR packet counts: per-packet measurement through to charging (G18, third slice)

**Status:** implemented
**Gap item:** [137](137-free5gc-422-gap-survey.md) §3.3 / §8 **G18** (N4 generic rule engine — third slice)
**Builds on:** [151](151-n4-qer-gate-status.md) + [153](153-n4-query-urr.md) (the URR/gate slices)

## Problem

Third self-contained G18 remnant. The UPF measured only **volume** (octets): every URR
usage report set the Volume Measurement flags to a hardcoded `TOVOL|ULVOL|DLVOL` and
carried no **packet counts** — one of the "no packet counts (flags hardcoded …)" defects
in §3.3. So the charging path (CHF) could bill per-byte but never per-packet, even though
packet counts are a first-class charging dimension (TS 29.244 Volume Measurement carries a
Number-of-Packets alongside the octet counts; TS 32.291 used-unit containers carry both).

Unlike bare report enrichment, this slice threads packet counts **all the way to a
consumer**: UPF measures → SMF relays → CHF accumulates per rating group. So it is a real,
consumed capability, not latent data.

## Design

- **UPF (`pfcp`):** `Session` (session URR) and `FlowEnforcer` (per-flow URR) gain
  `ul_pkts`/`dl_pkts` counters, incremented in `Session::admit` alongside the byte
  counters — so a packet is counted under exactly the same one URR as its bytes (matched
  flow, else session). `Session` also gains `reported_{ul,dl}_pkts` watermarks so the
  session URR's threshold reports carry a **packet delta** consistent with its volume
  delta. `UsageVolume` gains `total_pkts`/`uplink_pkts`/`downlink_pkts`, populated by
  `remove` (final), `query_urr_usage` (immediate) and `take_due_report` (threshold).
  `usage_report_for` sets the Volume Measurement packet flags (`TONOP|ULNOP|DLNOP`) and
  counts; a new `usage_volume_from` reader pulls them back off a report (defaulting packet
  counts to `0` for a peer that omits them), shared by all three SMF-side parsers.
- **CHF (`sbi-core::nchf`):** `UsedUnitContainer` gains `uplink_packets`/`downlink_packets`/
  `total_packets` (serde-defaulted for back-compat); `Cdr::absorb` sums them per rating
  group exactly as it does volume.
- **SMF (`nf-smf`):** `container_for` copies the packet counts from the URR usage into the
  Nchf used-unit container.

Purely additive: an absent packet field defaults to `0`, so a peer that predates this
change (or a report without the packet flags) behaves exactly as before.

## Tests

- `pfcp::per_flow_urrs_measure_and_report_at_deletion` / `query_urr_reports_live_usage…` /
  `volume_threshold_triggers_a_session_report` — extended to assert the packet counts in
  the deletion, query and threshold reports match the number of admitted packets.
- `sbi-core::nchf::charging_session_lifecycle_accumulates_the_cdr` — extended to assert the
  CDR accumulates packet counts per rating group alongside volume.
- pfcp/sbi-core/nf-smf tests + clippy clean; full build; BDD datapath tiers green (packet
  counting rides the admit path — no forwarding regression).

## Follow-ups (rest of G18)

- StartTime/EndTime and a real monotonic per-URR URSEQN (the remaining URR-fidelity items).
- Duration/PERIO measurement, BAR, OHR, PDR precedence evaluation.
- The pivot-gated wire-fidelity half (generic PDR/FAR/QER/URR tables + IPFilterRule SDF) —
  still awaiting the §7 decision.
