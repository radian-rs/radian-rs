# 153 — N4 Query URR: on-demand mid-session usage reporting (G18, second slice)

**Status:** implemented
**Gap item:** [137](137-free5gc-422-gap-survey.md) §3.3 / §8 **G18** (N4 generic rule engine — second slice)
**Builds on:** [151](151-n4-qer-gate-status.md) (first G18 slice), the URR machinery in `crates/pfcp/src/lib.rs`

## Problem

Second self-contained G18 remnant. The UPF measured URR volume but could only
*report* it on two triggers: a volume threshold crossing (VOLTH) or session deletion
(TERMR). A **Query URR** in a Session Modification — the SMF asking "what is this URR's
usage right now?" (TS 29.244 §7.5.4.9) — was **unread**, and the Modification Response
carried **no usage reports at all** (both called out in §3.3). So the SMF had no way to
poll live usage mid-session; anything needing an on-demand read (a quota check, an
on-demand CHF update) had to wait for a threshold or the session's end.

This slice makes that read work, entirely within `crates/pfcp` (UPF handler + SMF
builders): **the SMF can query a URR mid-session and get its current usage back**.

## Design

Mirrors the existing deletion-time usage-report path (which already emits
`UsageReportWithinSessionDeletionResponse` IEs), one message earlier.

- **UPF (`handle_n4`, SessionModification):** after applying the modification, collect
  any `QueryUrr` IEs and answer each with a `UsageReportWithinSessionModificationResponse`
  IE carrying that URR's current usage. New `UpfState::query_urr_usage(up_seid, urr_id)`
  returns the **cumulative** usage for the session URR (`SESSION_URR_ID`) or a per-flow
  URR (`PER_FLOW_URR_BASE + qfi`). A query is an **immediate read**: it neither resets the
  measurement nor advances the threshold-report watermark, so a later VOLTH/TERMR report
  is unchanged. An unknown URR simply yields no report.
- **SMF (`pfcp`):** `session_urr_query_request(up_seid, seq, urr_ids)` builds a Session
  Modification carrying the Query URR IEs; `usages_from_modification_response(data)` parses
  the returned volume reports (the analogue of `usages_from_deletion_response`).

Scope: **volume** usage (reusing `UsageVolume` / `usage_report_for`), consistent with the
threshold and deletion reports. No consumer wires this yet — it is the building block the
online-charging quota loop (G14) needs; today it stands as a capability + test.

## Note

Reporting semantics are cumulative-and-non-resetting (the common immediate-read case).
The URR measurement-reset flag (a query that *does* reset), and the packet-count /
StartTime-EndTime / real-URSEQN fidelity the survey also flags, are separate G18
follow-ups — this slice deliberately reuses the existing volume-report shape unchanged.

## Tests

- `pfcp::query_urr_reports_live_usage_without_resetting` — establish a session with a
  per-flow (GBR) URR, push traffic split across the session URR and the per-flow URR,
  query both mid-session and assert each answers with its live cumulative usage; an unknown
  URR yields no report; and a subsequent deletion still reports the full totals (the query
  reset nothing).

`pfcp` tests + clippy clean; full workspace build; the change is confined to `crates/pfcp`.

## Follow-ups (rest of G18)

- Wire a consumer: SMF-side mid-session usage polling feeding the CHF (part of G14 online
  charging).
- URR measurement-reset on query; packet counts (TONOP/ULNOP/DLNOP), StartTime/EndTime,
  real per-URR URSEQN.
- The pivot-gated wire-fidelity half (generic PDR/FAR/QER/URR tables + IPFilterRule SDF) —
  still awaiting the §7 decision.
