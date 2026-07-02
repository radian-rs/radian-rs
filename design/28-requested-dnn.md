# UE-Requested DNN — Implementation Notes

> Built 2026-07-02 on branch `feat/nas-requested-dnn`. Closes the first
> "next step" of [27](27-smf-subscription-data.md): the AMF no longer hardcodes
> `internet` — it parses the UE's requested DNN and drives the session with it.

With subscription authorization in place (design/27), the missing piece was the
*request* side: per TS 24.501 §8.2.10 the UE's requested DNN rides as an optional
IE (**0x25**) of the 5GMM **UL NAS Transport** — not inside the opaque 5GSM
container — so the AMF can honor it without parsing NAS-SM.

## What was built

- **`nas::requested_dnn_from_ul_nas_transport`** — extracts the 0x25 IE from a
  decoded UL NAS Transport and converts its RFC 1035 label form to a dotted
  string (`oxirush-nas` already modeled the IE; `NasDnn::as_string` does the
  label decode). `None` when the UE omitted it.
- **`nas::ul_nas_transport_sm`** (UE side / tests) gains an optional `dnn`
  parameter so the round-trip is testable.
- **AMF** — on UL NAS Transport it now uses the UE's requested DNN for
  `CreateSMContext` *and* echoes it in the N1 PDU Session Establishment Accept.
  A UE that omits the IE gets **`DEFAULT_DNN` = `internet`** (TS 23.501
  default-DNN selection, simplified to one network-wide default). The SMF's
  subscription gate (design/27) then authorizes whatever was requested.

## Verification

- `cargo test --workspace --exclude bdd` — green. `ul_nas_transport_round_trips`
  now asserts a multi-label DNN (`ims.corp`) survives the encode/decode round
  trip and that omission yields `None`.
- **BDD, both features green** (with `FREE_RAN_UE_BIN`): the live free-ran-ue UE
  *does* set the DNN IE in its UL NAS Transport (`ue/nas.go` sets
  `ulNasTransport.DNN`), so the e2e exercises the real parse path — the UE's
  configured `internet` flows through authorization to the accept. 4 scenarios /
  21 steps, teardown clean.

## Known limitations / next steps

- **No 5GSM reject** — a UE requesting an unsubscribed DNN gets silence (the AMF
  logs the SMF's 403 and drops); it should get a PDU Session Establishment
  Reject with cause #27 *missing or unknown DNN*. Natural next slice.
- **Requested S-NSSAI ignored** — the UL NAS Transport's 0x22 IE is decoded by
  the codec but unused; the network always serves the subscribed slice.
- **One default DNN** — per-subscriber default-DNN selection (from sm-data's
  `defaultDnnIndicator`) is future work.
