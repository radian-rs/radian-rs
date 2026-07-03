# Converged Charging — Per-Flow URRs, Threshold Reporting, Nchf CHF

> Built 2026-07-03 on branch `feat/nchf-charging`. Design [54](54-gfbr-urr.md) left
> usage reporting at a single session-level volume URR reported **only at
> deletion**, with a real Nchf deferred. This completes the charging loop:
> **per-flow URRs** (per-rating-group measurement), **volume-threshold usage
> reporting** (the UPF's first UPF-initiated N4 message), and a real **CHF**
> (`nf-chf`, Nchf_ConvergedCharging) that keeps CDRs — so a PDU session is billed
> `create → update(usage) → release(final usage)`, end to end.

## What was built

### Per-flow URRs + volume threshold (pfcp / UPF)

- Each GBR flow's classifier PDR now links a **per-flow volume URR**
  (`PER_FLOW_URR_BASE(2000) + qfi`) besides its QER — the flow's usage is
  measured separately (its charging **rating group**). Session deletion reports
  the session URR **plus** one report per flow URR.
- **Partitioned counting** (TS 29.244 semantics — a URR measures what its own
  PDRs carry): each forwarded byte is counted under exactly *one* URR — the
  matched flow's, else the session-level one — so a charging system summing all
  rating groups sees the true total. (Caught live: the first cut counted flow
  bytes under both, double-billing on summation.)
- The session URR takes an optional **volume threshold** (`VOLTH` reporting
  trigger + `VolumeThreshold`, from `session_establishment_request`'s new
  `usage_threshold_bytes`). Crossing it flags a due report;
  `UpfState::take_due_report()` yields the **delta since the last report** and
  advances the watermark. Deletion then reports only the **unreported
  remainder** — again, no double-billing.
- New wire helpers: `session_report_request` (header SEID = the **SMF's**
  F-SEID, now stored per session), `parse_session_report_request`,
  `session_report_response` (accepted; header SEID = the UPF's), and
  `usages_from_deletion_response` (all URRs).
- **nf-upf** learns the SMF's N4 address from its requests and runs a reporter
  task (100 ms poll): each due report goes out as a **Session Report Request** —
  the first UPF-initiated PFCP message in this core. The SMF's ack lands back in
  the N4 loop.

### SMF: N4 reader task + CTF role

- The SMF's N4 transport was rebuilt for full-duplex PFCP: a **reader task**
  (spawned by `SmfState::connect`) owns the socket's receive side, routing
  responses to their waiting transaction by sequence number (a `pending` map of
  oneshots — replacing the lock-the-socket-and-poll transact) and steering
  **UPF-initiated Session Report Requests** onto a channel. Without this, an
  unsolicited report arriving between transactions was silently eaten.
- `handle_usage_reports` (spawned alongside the SBI server) consumes that
  channel: looks the session up by CP F-SEID, **acks** toward the UPF, and
  relays the usage to the CHF as an **Nchf update**.
- On `CreateSMContext` the SMF (as **CTF**) discovers the CHF via the NRF and
  opens a charging data session (best-effort — no CHF ⇒ the session runs
  unbilled, mirroring the PCF fallback); on release it closes the charging
  session with the final used-unit containers.
- Rating-group mapping: session URR → rating group **0**; per-flow URR → the
  flow's **QFI**. Threshold via `RADIAN_SMF_USAGE_THRESHOLD_BYTES`.

### CHF (`sbi_core::nchf` + `nf-chf`)

- `Nchf_ConvergedCharging` (TS 32.290/32.291, trimmed): `ChargingDataRequest`
  (subscriber + PDU-session info + used-unit containers) against
  `POST /nchf-convergedcharging/v3/chargingdata` (create → `201` + `Location`),
  `…/{ref}/update`, `…/{ref}/release`, plus a non-standard read-only
  `GET /{ref}` for observability. In-memory **CDR store** accumulating usage per
  rating group; update after release → `409`.
- **`nf-chf`** — a new NF on **:8007**: NRF-registered (nf-type `CHF`), served
  over the design/57 mTLS mesh when `RADIAN_SBI_TLS_DIR` is set (`radian-pki`'s
  default NF set now includes `chf`). The BDD e2e core starts it too.

## Boundaries / notes

- **No quota management** — the CHF grants no units and never gates traffic
  (reporting-only charging; Requested/Granted-Service-Unit deferred).
- **Threshold rides the session URR only** — per-flow thresholds deferred; flow
  usage reaches the CHF at release.
- Reports are sent **once**, best-effort (no retransmission timer); the
  watermark advances at pickup regardless of the ack.
- CDRs are in-memory (no export/rollover); rating groups come from the QFI
  convention, not PCC rules.

## Verification

- `cargo test --workspace --exclude bdd` — green (**123** tests). New:
  - pfcp `per_flow_urrs_measure_and_report_at_deletion` (partitioned counting),
    `volume_threshold_triggers_a_session_report` (delta reports + wire
    round-trip + watermark reset).
  - nchf `charging_session_lifecycle_accumulates_the_cdr`.
  - nf-smf `charging_bills_threshold_reports_and_final_usage` — the whole loop
    in-process: create opens the CDR; a UPF-sent Session Report Request is acked
    and billed; release closes the CDR at **exactly** the moved volume
    (threshold report + remainder, no double-billing).
- **BDD 2 features / 5 scenarios / 25 steps green** — the e2e core now includes
  `nf-chf`, so every live @sim PDU session opens/releases a real charging session.
- **Live (real binaries)** — core up with a 500-byte threshold; curl plays the
  AMF; crafted G-PDUs play the gNB:
  - CreateSMContext → CHF CDR opened (`GET …/chargingdata/0`);
  - 4×200 B off-flow → UPF logs `Session Report Request sent` → SMF
    `usage relayed to the CHF` → CDR shows the mid-session volume;
  - 3×180 B matching the GBR filter (UDP :5005) → billed under **rating group
    2**;
  - release → CDR closed with rating group 0 = **800** and rating group 2 =
    **540** — exactly the bytes that moved, each counted once.

## Known limitations / next steps

- **Quota management** (granted units, traffic gating on quota exhaustion) and
  Requested-Service-Unit flows.
- **Per-flow volume thresholds** + time-based/periodic reporting (`PERIO`).
- Report **retransmission/reliability** (PFCP timer + N1N2 retry semantics).
- CDR **export** (files/streaming) and PCC-rule-driven rating groups (TS 23.503).
