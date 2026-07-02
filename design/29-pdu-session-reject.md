# PDU Session Establishment Reject — Implementation Notes

> Built 2026-07-02 on branch `feat/pdu-session-reject`. Closes the first "next
> step" of [28](28-requested-dnn.md): a UE whose PDU-session request fails now
> gets a proper 5GSM answer instead of silence.

With the requested DNN parsed (design/28) and authorized at the SMF (design/27),
a refusal previously died as a warning in the AMF log while the UE waited out its
timer. This slice completes the failure leg: TS 24.501 §8.3.3 **PDU Session
Establishment Reject**, NAS-protected, down a plain DL NAS Transport (no N2
resource setup — no session exists).

## What was built

- **`nas::pdu_session_establishment_reject(psi, pti, cause)`** — the 5GSM header
  (message type 0xC3) plus the mandatory cause octet; `nas::sm_cause` holds the
  values this stack emits (#27 *missing or unknown DNN*, #31 *request rejected,
  unspecified*).
- **`AmfSmf::create_sm_context` returns a typed error** — `CreateSmError::
  Forbidden` for the SMF's 403 (subscription refusal) vs `Other` for
  discovery/transport/upstream failures.
- **AMF failure leg** — maps `Forbidden` → cause #27, everything else → #31,
  builds the reject echoing the request's PSI/PTI, NAS-protects it with the UE's
  security context, and sends it via DownlinkNASTransport.
- **New negative BDD scenario** (`datapath_e2e.feature`): after the happy-path
  ping, the UE is stopped and restarted from `ue_unsubscribed_dnn.yaml` (same
  demo subscriber, `dnn: corporate`) — registration succeeds, the PDU session is
  refused, and `ueTun0` must never appear.

## Verification

- `cargo test --workspace --exclude bdd` — green. New/updated: reject-builder
  byte assertions; the AMF mock-SMF test now returns 403 for a non-subscribed
  DNN and asserts the typed `Forbidden` error.
- **BDD, 5 scenarios / 25 steps green** (with `FREE_RAN_UE_BIN`), including the
  new reject scenario, with clean teardown.
- **Wire-level confirmation** (manual loopback run, all NFs + gNB/UE on
  127.0.0.1): SMF logs `PDU session rejected: DNN not in smf-selection
  subscription data … dnn=corporate`; AMF logs `sending Establishment Reject
  (5GSM cause #27)`; and the free-ran-ue UE **deciphers and identifies the
  incoming `PDUSessionEstablishmentReject`** (it then errors only because the
  simulator hasn't implemented reject handling — proof the message arrived
  intact through NAS security).

## Known limitations / next steps

- **No back-off timer IE** — a rejected UE may immediately retry; TS 24.501's
  T3396/back-off IE is future work.
- **PTI echo is heuristic** — the PTI is read from byte 2 of the opaque 5GSM
  container, same as the accept path; real NAS-SM parsing arrives with an SMF
  N1 leg.
- **Requested S-NSSAI still ignored**; per-subscriber default DNN still fixed
  (carried over from design/28).
