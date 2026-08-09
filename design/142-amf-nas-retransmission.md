# AMF NAS retransmission timers + Service Reject on failed resume (design/137 G7)

> Built 2026-08-09 on branch `free5gc`. Closes **G7** from
> [137](137-free5gc-422-gap-survey.md) §8 (Moderate — *a lost downlink stalls a
> registration permanently*).

## The gap

The AMF's registration exchanges four downlink NAS messages that each expect an
uplink reply — **Identity Request**, **Authentication Request**, **Security Mode
Command**, **Registration Accept**. radian sent each once and armed no timer, so
a single lost downlink (or lost uplink reply) left the UE and the AMF waiting
forever: the registration never completed and never failed. free5gc/open5gs both
guard these with the TS 24.501 §10.2 timers **T3570 / T3560 / T3550**.

Separately, a **CM-IDLE resume** (Service Request) whose NAS couldn't be verified
against the retained security context was **silently dropped** and the context
re-retained (`on_service_request`) — the UE got nothing back and hung.

## What this slice does

### Retransmission timers (T3570 / T3560 / T3550)

A **uniform, single-slot** mechanism. Registration runs its four messages
strictly in sequence, so at most one is outstanding at a time — one
`UeContext.pending_retx: Option<PendingNasRetx>` holds whichever it is:

```
struct PendingNasRetx { kind: RetxKind, nas_bytes: Vec<u8>, attempts: u8 }
enum RetxKind { IdentityRequest, AuthRequest, SecurityModeCommand, RegistrationAccept }
```

- **Send** → after building each downlink, store the exact bytes + arm the timer
  (`arm_nas_retx` spawns a sleep posting `UeCmd::NasRetxExpiry { amf_ue_id, kind }`
  onto the UE's association channel — the same pattern as T3555/T3522).
- **Expiry** (`on_nas_retx_expiry`) → if `kind` is still the outstanding one and
  sends remain, **resend the exact bytes verbatim** and re-arm; at the send cap
  (`NAS_RETX_MAX_SENDS` = 5) abort the registration (`implicit_deregister`:
  release the RAN context + drop ours).
- **Cancel** → each uplink reply clears (or supersedes) `pending_retx`, so a
  stale expiry finds nothing matching and no-ops. The handoffs:
  Identity Response → sets AuthRequest; Auth Response → clears, then sets SMC;
  SMC Complete → clears, then sets RegistrationAccept; Registration Complete →
  clears.

`RADIAN_AMF_T35{5,6,7}0_SECS` override the 6 s default (the BDD suite can shrink
them).

### Service Reject on failed resume

`on_service_request`'s failed-verification path now sends a **Service Reject**
with cause **#10 (implicitly de-registered)** — which sends the UE back to
registration — plus a **UEContextReleaseCommand**, and discards the retained
context (coherent with #10) rather than silently re-retaining it. New nas-crate
builder `nas::service_reject(cause)` + `mm_cause::{UE_IDENTITY_CANNOT_BE_DERIVED,
IMPLICITLY_DEREGISTERED}` (`oxirush-nas` already had the `NasServiceReject` type).

## Decisions

- **D1 — verbatim retransmission.** A NAS retransmission reuses the same
  message/COUNT; radian's `unprotect` aligns to the received sequence number (no
  strict replay check), so resending the exact sent bytes is correct and lets
  the mechanism store a single `Vec<u8>` for every message type (plaintext or
  protected) with no re-protection. (This is *more* spec-faithful than T3555's
  re-protect-with-fresh-COUNT approach, which predates this slice.)
- **D2 — one `pending_retx` slot, keyed by `RetxKind`.** Registration is
  sequential, so a single slot suffices and the reply→next-message handoff is a
  clear/set on that slot. The expiry checks the kind still matches, so a stale
  timer for a superseded message no-ops. (T3555's separate
  `pending_config_update` field is untouched — the config update is sent *after*
  Registration Complete, so the two never overlap.)
- **D3 — give-up aborts via `implicit_deregister`.** At the send cap the UE is
  unreachable; releasing the RAN context and dropping ours matches how T3522/
  T3555 exhaustion already behaves.
- **D4 — Registration Accept retransmits as a plain DownlinkNASTransport.** Its
  first send rides an Initial Context Setup Request (it establishes the AS
  context); once that context exists, a retransmission is a plain DL NAS
  transport of the same protected bytes.
- **D5 — Service Reject cause #10, context discarded.** #10 tells the UE to
  register afresh, so keeping the (unverifiable) context would be contradictory;
  sending it unprotected is permitted for this cause (TS 24.501 §4.4.4.2).

## Tests

- `crates/nas`: `service_reject_roundtrips` — the builder encodes the cause and
  round-trips through the codec.
- `nf-amf`:
  - `nas_retx_retransmits_then_aborts` — each expiry resends the exact bytes up
    to the cap (verified verbatim), incrementing `attempts`, then aborts with a
    UEContextReleaseCommand and drops the context; a later stale expiry no-ops.
  - `nas_retx_expiry_no_ops_when_superseded_or_cleared` — an expiry for a
    superseded kind, and any expiry after the reply cleared the slot, no-op.
  - `failed_resume_sends_service_reject` — an unverifiable CM-IDLE resume yields
    `[ServiceReject, UEContextReleaseCommand]` and discards the retained context.
- nas 40, nf-amf 60 green; clippy clean; BDD `scripted_reg` (22 scen / 253 steps)
  and `scripted_datapath` (7 / 97) pass with the timers armed through every
  registration.

## Follow-ups

- **Security Mode Reject** has no AMF handler today; when one is added it should
  also clear `pending_retx`. (The SMC's T3560 still aborts on timeout regardless.)
- The retransmission timers cover **initial registration**; the mobility/periodic
  registration-update accept (`on_service_request`) is not yet T3550-guarded.
- Re-protect-with-fresh-COUNT (`pending_config_update`, T3555) could adopt the
  same verbatim-bytes model for consistency.
