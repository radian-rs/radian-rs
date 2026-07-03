# Session-AMBR onto the User Plane — QER + Policing — Implementation Notes

> Built 2026-07-02 on branch `feat/upf-ambr-qer`, the follow-up to
> [48](48-pcf-udr-policy.md). That slice re-authorized a mid-session policy change
> in the SMF's record but did not touch the datapath. This slice **propagates the
> session AMBR onto the user plane**: the SMF installs it as an N4 **QER**, the UPF
> **polices** the session's aggregate rate, and a mid-session change re-rates the
> policer live.

## What was built

### N4 — the session-AMBR QER (`pfcp`)

- **`SessionAmbr { uplink_bps, downlink_bps }`** — the enforced aggregate rate.
- **`session_establishment_request(.., ambr: Option<SessionAmbr>)`** — when an
  AMBR is authorized, provisions a session-level **Create QER** (open gate + MBR)
  and binds both PDRs to it (`qer_id`), so the UPF meters uplink and downlink.
- **`session_qer_update_request(up_seid, seq, ambr)`** — a Session Modification
  carrying an **Update QER** with the new MBR (the mid-session re-rate).
- **`handle_n4`** parses the Create QER at establishment and the Update QER at
  modification, recording/re-rating the session's AMBR. It now takes `now_nanos`
  (the UPF's monotonic clock) so the control path and the datapath share one clock.

### Enforcement — a token-bucket policer (`pfcp` + `n6`)

- **`TokenBucket`** (in `pfcp`) — a pure, **clock-injected** bits token bucket
  (capacity ≈ 1 s of rate, floored at one jumbo frame; `rate == 0` ⇒ unlimited).
  Deterministically unit-testable — the caller passes `now_nanos`.
- **`UpfState`** gains a per-session uplink/downlink bucket sized from the AMBR,
  `ambr_for(up_seid)`, and `admit_uplink` / `admit_downlink(now, bytes)`.
- **`n6::uplink` / `n6::downlink`** now take `&mut UpfState` + `now_nanos` and, after
  the existing TEID/anti-spoof/route checks, meter the packet — a new
  `Uplink::RateLimited` / `Downlink::RateLimited` outcome (dropped) when the
  session AMBR is exceeded. **`nf-upf`** supplies the shared monotonic clock
  (`now_nanos()` off a process-start `Instant`) to both the N4 loop and the N3/N6
  datapath, and logs policed drops.

### Control — SMF drives it (`nf-smf`)

- **CreateSMContext** converts the authorized session AMBR (`npcf::SessionAmbrPolicy`,
  a TS 29.571 BitRate string) to bps via the new `SessionAmbrPolicy::to_bps` and
  passes it into the establishment, so the QER is installed up front.
- **`refresh-policy`** ([48](48-pcf-udr-policy.md)'s mid-session trigger) now, when
  the re-authorized session AMBR **differs**, runs an N4 Session Modification
  (`session_qer_update_request`) to re-rate the UPF's QER — closing the loop from a
  UDR policy edit all the way to the user plane.

## Where the boundary now sits

The **session AMBR** — the aggregate non-GBR rate — is enforced end to end in the
core user plane, and a mid-session change takes effect live. Still deferred:

- **Per-flow GBR/MBR enforcement** — only the session AMBR is policed; per-QoS-flow
  GBR is signalled but not enforced (each flow would need its own QER + a flow
  classifier). No buffering (no QER gate-close/hold).
- **RAN/UE signalling of a change** — a mid-session QoS change is applied at the UPF
  but not yet pushed to the gNB/UE (**N2 PDU Session Resource Modify** + **N1 PDU
  Session Modification Command / Complete**); the access side keeps its original
  QoS until the next setup.
- **Policer tuning** — burst is a simple ~1 s of rate; not configurable, and the
  gate is always open (no explicit QER gating).

## Verification

- `cargo test --workspace --exclude bdd` — green (101 tests). New:
  - `pfcp::token_bucket_admits_burst_then_throttles_then_refills` — the policer
    admits a full burst, throttles, and refills with elapsed (injected) time;
    `rate == 0` is unlimited.
  - `pfcp::establishment_qer_sets_session_ambr_and_update_re_rates_it` — a Create
    QER records the AMBR; an Update QER re-rates it.
  - `n6::session_ambr_polices_uplink_and_refills` / `…_downlink` — a QER-provisioned
    session admits a burst then drops (`RateLimited`) in both directions, refilling
    over time.
  - `pdu_session::refresh_policy_applies_a_mid_session_udr_change` (extended) — now
    asserts the **UPF's `ambr_for`** goes from the v1 (200/400 Mbps) to the v2
    (50/100 Mbps) rate across the refresh: the mid-session change reached the user
    plane.
  - Existing pfcp/n6/nf-upf datapath tests carried through the `&mut`/`now_nanos`
    signature change.
- **BDD, 5 scenarios / 25 steps green**, incl. the live **`@sim`** e2e — the demo
  session now installs a 1/2 Gbps AMBR QER and the free-ran-ue ping (tiny, far under
  the limit) still round-trips: policing doesn't disturb the datapath.

## Known limitations / next steps

- **N2/N1 modify** to push a mid-session QoS change to the RAN/UE.
- **Per-flow GBR** enforcement (per-flow QERs + classification) and buffering.
- **Configurable policer** (burst/gate) and downlink/uplink asymmetry beyond MBR.
