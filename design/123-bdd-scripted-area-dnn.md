# BDD Scripted Registration Area + Unsubscribed DNN (D9/D10)

> Built 2026-07-09 on branch `feat/bdd-scripted-area-dnn`. Sixth BDD slice of the design/116
> plan — the **last two `scripted_registration` scenarios**: D9 (the registration area is the
> serving gNB's TA list ∪ the UE's TAI, designs 74/75) and D10 (a PDU session for an
> unsubscribed DNN is rejected with 5GSM cause #27 + a T3396 back-off, designs 28/29/30). Both
> are control-plane only; no crate behaviour changed — pure test coverage over existing AMF
> logic.

## What was built

### `nas`

- **`pdu_session_reject_info(container) -> Option<(cause, Option<t3396>)>`** — the UE-side
  reader for a 5GSM PDU Session Establishment Reject (cause octet + the optional T3396
  back-off timer).

### `bdd` (`ScriptedUe` + steps)

- **`ScriptedUe::pdu_session_request_for_dnn(psi, dnn)`** — a NAS-protected PDU session request
  naming a specific DNN; **`read_pdu_session_reject(dl_nas)`** — unprotect the relayed DL NAS
  Transport and pull `(cause, T3396)` out of the reject.
- **Scenario D9**: the gNB completes NG Setup serving TAC `000001`; the UE registers arriving
  from a **different** TAC `000002`; the Registration Accept's 5GS TAI list is the **union**
  `[000001, 000002]`.
- **Scenario D10**: a registered UE requests a PDU session for the unsubscribed DNN
  `corporate`; the AMF answers a **PDU Session Establishment Reject, 5GSM cause #27** (missing
  or unknown DNN) with a **T3396** back-off — no N2 setup, no session.

## Verification

- `cargo test -p nas` — green (35; the new reject-info roundtrip passes).
- **`cargo test -p bdd` — 2 features / 14 scenarios / 137 steps GREEN** (deterministic across
  reruns): D9 and D10 drive their flows against the live core; the rest of the suite is
  unaffected.
- `cargo test --workspace --exclude bdd` — green (30 test binaries).
- `cargo clippy -p nas -p bdd --tests` — no net-new warnings (6 sites before == after).

## The scripted registration feature is now complete

`scripted_registration.feature` covers the full D-series plus the session/idle scenarios:
D1 (5G-AKA), D3 (GUTI re-registration), D4 (Identity Request), D5 (AUTS resync), D6 (auth
reject), D7 (#62 slice reject), D8 (NSSAI intersection), D9 (registration area union), D10
(DNN reject) — plus 116c (PDU session) and 116d (CM-IDLE resume). **14 scenarios / 137 steps**
against the live core, all CI-runnable, and the tier drove two real AMF fixes along the way
(designs 119 and 122).

## Next

The registration front is done. The remaining design/116 fronts are the **datapath echo**
(scripted-tier `datapath_e2e` — real GTP-U user traffic through the signalled stack, needs the
UPF in a namespace so gNB and UPF don't both bind `:2152`) and the rest of the **idle arc**
(paging + DL buffering, design/65; T3513 retransmission, design/74). Beyond those: the
handover and lifecycle features (design/116 phases 116d–e in the original plan's numbering).
