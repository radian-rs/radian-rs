# UE-Requested S-NSSAI — Implementation Notes

> Built 2026-07-02 on branch `feat/requested-snssai`. Closes the remaining
> request-side gap from [28](28-requested-dnn.md)/[30](30-reject-backoff-timer.md):
> the UE's requested slice (UL NAS Transport IEI **0x22**) is now parsed,
> forwarded, and validated — instead of the network always serving whichever
> subscribed slice happened to carry the DNN.

## What was built

- **`nas::requested_snssai_from_ul_nas_transport`** — extracts the 0x22 IE as
  `(SST, optional SD)` (`oxirush-nas` models the IE; `NasSNssai::parse` decodes
  it). `ul_nas_transport_sm` (UE side/tests) gains the matching builder arg.
- **AMF** — forwards the requested slice as TS 29.502 `sNssai` in
  CreateSMContext (alongside `servingNetwork` and the requested DNN).
- **SMF slice-aware authorization** (`fetch_session_subscription`):
  - with a requested slice: the smf-select-data `subscribedSnssaiInfos` entry
    for that slice must exist (else **403 `SNSSAI_DENIED`**) and list the DNN
    (else **403 `DNN_DENIED`**); the sm-data entry is selected by that slice
    (SD compared case-insensitively) instead of first-DNN-match.
  - without one: previous behaviour (any subscribed slice listing the DNN).
  - The serving `sNssai` in the response is now the *validated requested* slice.
- **ProblemDetails on SBI errors** — Nsmf error responses now carry RFC 7807
  bodies with TS 29.502-style causes (`SNSSAI_DENIED`, `DNN_DENIED`,
  `MANDATORY_IE_MISSING`, `UPF_NOT_RESPONDING`, `UDM_UNREACHABLE`) instead of
  bare status codes.
- **5GSM cause #70** — when the UE requested a slice and the pair is refused,
  the reject now carries **#70 *missing or unknown DNN in a slice*** (still with
  the T3396 back-off); #27 remains for the no-slice-requested case. The AMF maps
  locally (it knows whether it forwarded a slice) — no response-body parsing.

## Verification

- `cargo test --workspace --exclude bdd` — green. New/updated:
  - `nas::ul_nas_transport_round_trips` — S-NSSAI IE round trip (with SD,
    SST-only, and omitted).
  - `nf-smf::unsubscribed_dnn_is_rejected_without_n4_state` — asserts the
    ProblemDetails causes: wrong slice → `SNSSAI_DENIED`; subscribed slice but
    DNN not in it → `DNN_DENIED`; no-slice cases and 400 unchanged; still zero
    N4 sessions.
  - The happy-path SMF test sends `sNssai` and gets the validated slice back;
    the AMF mock test asserts the slice is forwarded.
- **BDD, 5 scenarios / 25 steps green** (with `FREE_RAN_UE_BIN`): free-ran-ue
  sends the S-NSSAI IE (sst=1/sd=010203, `ue/nas.go` sets `ulNasTransport.SNSSAI`),
  so the live e2e now exercises the slice-keyed validation; the negative
  unsubscribed-DNN scenario rides the requested-slice path (→ cause #70).

## Known limitations / next steps

- **No allowed-NSSAI at registration** — slice admission per TS 23.501 happens
  at 5GMM level (Registration Accept carries the allowed NSSAI from am-data);
  we only enforce at session establishment. am-data remains unread.
- **AMF-side SMF selection** by (S-NSSAI, DNN) is still future (design/27 note).
- **One slice provisioned** — the demo subscriber has a single slice; multi-slice
  sm-data arrays are handled by the lookup but not demo-provisioned.
