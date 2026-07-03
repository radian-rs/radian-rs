# Paging + Downlink Buffering — Network-Initiated Resume

> Built 2026-07-03 on branch `feat/paging`. **Idle-mode arc slice 3 — the arc is
> now complete.** Slices 1–2 gave *UE-initiated* resume (AN release → Service
> Request). This adds the **network-initiated** half: downlink data arriving for a
> CM-IDLE UE is buffered at the UPF, which reports it to the SMF, which asks the
> AMF to **page** the UE (TS 23.502 §4.2.3.3). The UE answers with a Service
> Request (slice 2), and the buffered data is flushed onto the restored tunnel.

## What was built

### UPF downlink buffering (`pfcp` / `n6` / UPF)

- AN release now sets the downlink FAR to **BUFF** (+ `NOCP`) instead of DROP
  (`session_deactivate_request`), so the UPF holds downlink for the CM-IDLE UE.
- A buffering session holds packets in a bounded queue (`DL_BUFFER_CAP` = 64,
  oldest dropped when full). `n6::downlink` routes a packet with no installed
  tunnel to `UpfState::buffer_downlink` → the new `Downlink::Buffered`; the first
  buffered packet raises a **Downlink Data Report** (`take_dl_data_report`).
- Re-activation (`set_downlink`, from the Service Request N4 modify) stops
  buffering and **flushes** the held packets onto the new gNB tunnel — drained by
  the N4 loop via `take_flush` and GTP-U-encapsulated onto N3.

### DL Data Report → SMF → AMF paging

- pfcp: `session_report_request_dldr` (report type *downlink data report*) +
  `parse_dl_data_report`. The UPF reporter task (from design/59) now also sends
  DL data reports; the SMF N4 reader routes them (alongside usage reports).
- **SMF** `handle_dl_data_report`: ack the UPF, discover the AMF, and POST
  `Namf_Communication_N1N2MessageTransfer` (`…/n1-n2-messages`) to page.
- **AMF** paging surface: the endpoint resolves the SUPI to its retained CM-IDLE
  5G-TMSI and broadcasts a `UeCmd::Page(tmsi)` to every live gNB association via a
  new **`GNB_LINKS`** registry (each `serve_gnb` registers its channel; closed
  ones are swept on broadcast). Each association builds a non-UE-associated
  **NGAP Paging** (`ngap::paging`: `UEPagingIdentity` = 5G-S-TMSI + a
  `TAIListForPaging`) and sends it to its gNB.

## Boundaries / notes

- **Single tracking area** — paging goes to *all* gNBs with a fixed `AMF_TAC`; a
  real AMF filters by the UE's registration-area TAI list and honours DRX.
- **No paging retransmission / T3513** — one Paging is sent; if the UE doesn't
  answer, nothing retries (and the retained context isn't evicted yet).
- **Bounded buffer, no BAR tuning** — a fixed 64-packet queue; a real UPF uses a
  Buffering Action Rule (BAR) with the CP-configured buffering parameters.
- **Not driven by free-ran-ue** — the sim implements neither idle mode, Service
  Request, nor paging response, so the end-to-end network-initiated resume is
  unit/integration-tested; the live datapath is covered by the BDD e2e (which
  confirms normal N6 forwarding still works through the buffering-aware path).

## Verification

- `cargo test --workspace --exclude bdd` — green (**143** tests). New:
  - pfcp `an_release_buffers_downlink_reports_and_flushes_on_resume` (buffer →
    one DL data report → flush both packets to the new tunnel on resume) and
    `dl_data_report_wire_round_trips`.
  - ngap `paging_roundtrips`.
  - nf-amf `downlink_data_pages_a_cm_idle_ue` — the SMF's N1N2 transfer resolves
    the SUPI to its retained 5G-TMSI and a `Page` reaches the gNB link; an unknown
    UE → 404.
- **BDD 2 features / 5 scenarios / 25 steps green** — including the live @sim N3/N6
  datapath ping, confirming the buffering-aware downlink path forwards normally
  for a CM-CONNECTED UE.
- **Live (real binaries)** — create → activate → **deactivate** drives the real
  UPF's BUFF Update FAR (4 N4 messages handled, SMF logs *downlink buffered at the
  UPF*). The end-to-end page (which needs a gNB that releases + answers paging)
  isn't @sim-driveable, matching the design/50/63/64 precedent.

## Idle-mode arc: complete

CM-CONNECTED ⇄ CM-IDLE now works both ways:

- **AN release** (63): gNB releases → CM-IDLE, UP deactivated.
- **Service Request** (64): UE returns → context restored, UP re-activated.
- **Paging** (65): downlink data → buffer → report → page → the UE returns via the
  Service Request path, and the buffer flushes.

## Known limitations / next steps

- **Retained-context eviction** — a **T3512** periodic-registration / mobile-
  reachable timer so a UE that never answers paging is implicitly deregistered
  (and its `RETAINED` entry + buffered packets freed).
- **Paging retransmission (T3513)** and DRX / registration-area-scoped paging.
- **BAR-configured buffering** (CP-driven buffer size / DL Buffering Duration).
