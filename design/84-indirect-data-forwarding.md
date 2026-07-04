# Indirect Data Forwarding During N2 Handover

> Built 2026-07-04 on branch `feat/indirect-data-forwarding`. Design
> [82](82-handover-data-forwarding.md) handled **direct** forwarding (Xn-U between
> the gNBs); when the source signalled no direct path, in-flight downlink packets
> still dropped. This adds **indirect forwarding** (TS 23.502 §4.9.1.3.3): the SMF
> establishes a **UPF forwarding tunnel** per session, and the source forwards
> in-flight downlink to the UPF, which relays it to the target — **source → UPF →
> target**. This is the first handover path where the core's user plane carries
> the forwarded traffic.

## What was built

### `pfcp`

`session_establishment_request_indirect_forwarding(cp_seid, seq, smf_ip,
target_teid, target_addr)` — a forwarding-only PFCP session: one PDR matching a
UPF-allocated Access-facing ingress F-TEID, and a FAR forwarding to the **target**
gNB with Outer Header Creation set at establishment. The existing UPF `handle_n4`
establishment path allocates and returns the ingress F-TEID unchanged (it's
session-shape-agnostic) — no UPF code change; the pfcp test drives the real
handler.

### `nf-smf`

- `SmContext.indirect_fwd: Option<u64>` — the forwarding session's UP-SEID.
- New route `POST …/sm-contexts/{sm_ref}/indirect-forwarding`: with a target
  F-TEID it establishes the UPF forwarding session and returns the UPF's ingress
  F-TEID (`fwdN3Teid` / `fwdN3Addr`); with `{release: true}` it deletes the
  session (idempotent — `204` when there's none).

### `nf-amf`

- `AmfSmf::{setup_indirect_forwarding, release_indirect_forwarding}` — the Nsmf
  client calls; `AmfSmf` / `NrfClient` now derive `Clone` (the expiry timer owns
  one).
- `PendingHandover` gained `direct_forwarding`, `sessions` (the `(psi, (sm_ref,
  smf_base))` map — the ack lands on the *target* association where the UE context
  isn't reachable), and `indirect_active`.
- `on_handover_request_ack` is now async: with a direct path the Handover Command
  carries the **target's** forwarding F-TEIDs (design/82); otherwise, per admitted
  session offering forwarding, it calls the SMF to set up a UPF tunnel and puts the
  **UPF's ingress** F-TEID in the command instead.
- Teardown: the tunnels are released on completion (Handover Notify), on a source
  **cancel** after admission, and on **TNGRELOCoverall expiry** — release is
  idempotent and skipped when nothing was set up (a pre-admission failure never
  sets up a tunnel).

## Boundaries / notes

- **No forwarding drain timer.** The tunnel is released the instant the UE arrives
  (Notify); TS keeps it briefly to drain in-flight packets. In-flight data still in
  the source at that instant may be lost.
- **Per-session, not per-QoS-flow** forwarding (matches the design/82 shape).
- The UPF *datapath* execution of the forwarding FAR (GTP-U in on the ingress
  F-TEID, OHC out to the target) is not exercised end to end here — there's no
  two-gNB live data path; the control-plane setup and the UPF's establishment of
  the rule are covered.
- GTP-U end-marker handling is a UPF/RAN concern, not modelled.

## Verification

- `cargo test --workspace --exclude bdd` — green (**173** tests). New:
  - pfcp `indirect_forwarding_session_allocates_an_ingress_fteid` — the **real
    UPF `handle_n4`** establishes the forwarding session, allocates a non-zero
    ingress F-TEID, returns it, and deletes the session on a Session Deletion.
  - nf-amf `n2_handover_sets_up_indirect_forwarding` — a handover with no direct
    path: the AMF sets up exactly one indirect tunnel at the mock SMF, the source's
    Handover Command carries the **UPF's** ingress F-TEID (`000000cc / 10.0.9.9`),
    not the target's `0xBB`, `indirect_active` is set, and the tunnel is released
    once the UE arrives.
- `cargo clippy --workspace --exclude bdd` — clean.
- **BDD 2 features / 5 scenarios / 25 steps green** — the normal datapath (@sim
  register + ping) is unaffected.
- Not sim-drivable end to end (two gNBs; design/64/65 precedent); the SMF↔UPF
  forwarding establishment runs the real UPF handler in the pfcp test.

## Known limitations / next steps

- **Forwarding drain timer** — hold the tunnel briefly after Notify.
- **Per-QoS-flow forwarding** granularity.
- Exercising the UPF forwarding datapath against a real two-gNB topology.
