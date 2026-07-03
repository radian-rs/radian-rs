# AMF-Side SMF Selection by (S-NSSAI, DNN) — Implementation Notes

> Built 2026-07-03 on branch `feat/smf-selection`. The AMF stopped taking "the
> first SMF the NRF returns" ([16](16-amf-pdu-session-leg.md)) and now selects an
> SMF that actually serves the requested `(S-NSSAI, DNN)` (TS 23.501 §6.3.2), via
> NRF discovery filtered on the SMF's advertised capabilities.

## What was built

- **NRF profile gains `smfInfo`** (`sbi_core::nnrf`, TS 29.510 §6.1.6.2.10,
  trimmed): `sNssaiSmfInfoList` of `{sNssai, dnnSmfInfoList:[{dnn}]}`, with
  `SmfInfo::serves(snssai, dnn)` and a `from_served(&[(sst, sd, dnn)])`
  constructor. NF discovery accepts an optional `snssai-sst` / `snssai-sd` /
  `dnn` filter (trim: the spec's `snssais` is a JSON array; we take scalars) and
  keeps only SMF profiles whose `smfInfo` matches — a profile without `smfInfo`
  can't be slice/DNN-matched, so it's excluded from a *filtered* query but still
  returned by an unfiltered `discover`. `NrfClient::discover_for(...)`.
- **The SMF advertises what it serves** (`nf-smf`): its NRF profile carries
  `smfInfo` from `SERVED_SLICES` (the demo `(1/010203, internet)`, config in
  production).
- **The AMF selects and remembers** (`nf-amf`): `AmfSmf::select_smf(snssai, dnn)`
  returns the chosen SMF's base URL; `create/update/release_sm_context` now take
  that base **explicitly**, and `UeContext.sm_refs` stores `(sm_ref, smf_base)`
  per PDU session — so **UpdateSMContext and ReleaseSMContext reach the same SMF
  that created the session** (previously each re-discovered, latently wrong with
  more than one SMF). No SMF serves the pair → the AMF sends a 5GSM Establishment
  Reject (#70 with a requested slice, else #27) with a back-off, *before* any
  SMF round trip.

Layering that falls out: **selection** ("is there an SMF for this DNN at all?")
is the AMF's, then **authorization** ("may *this* subscriber use it?", the SMF's
`403` from design/27). An unserved DNN is now refused at selection; a served-but-
unsubscribed DNN still hits the SMF's subscription check.

## Verification

- `cargo test --workspace --exclude bdd` — green (26 suites). New/updated:
  - `nnrf::discovery_filters_smf_by_snssai_and_dnn` — filter by (slice, DNN),
    by DNN only, unserved DNN → empty, wrong slice → empty, unfiltered → all.
  - `nf-amf` discover/create test now `select_smf`s (asserting the advertised
    SMF is chosen), threads the base through create/update, and checks selection
    fails for an unserved DNN.
  - The deregistration test stores `(sm_ref, smf_base)` per session.
- **Live BDD `@sim`**: the SMF advertises `smfInfo`; the AMF selects it by
  `(1/010203, internet)`, the PDU session completes and the datapath ping
  round-trips (5 scenarios / 25 steps green). The AMF log shows the happy-path
  "SM context created … sending N2 setup". The unsubscribed-DNN scenario (dnn
  `corporate`, which no SMF advertises) now rejects at AMF selection rather than
  the SMF's `403` — still no `ueTun0`, so the scenario passes unchanged.

## Known limitations / next steps

- **Served slices/DNNs are a const** — real SMFs derive this from config/DNN
  pools; here one demo triple.
- **First match wins** — no load-balancing / priority / capacity weighting among
  equally-matching SMFs.
- **Scalar discovery filter** — `snssais` isn't the spec's JSON-array encoding;
  fine for one slice per query.
- Per-flow QoS and SBI security hardening (TLS/OAuth2) remain the big open items.
