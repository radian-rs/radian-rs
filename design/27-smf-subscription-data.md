# SMF Subscription Data over Nudm_SDM — Implementation Notes

> Built 2026-07-02 on branch `feat/smf-sm-data`. Follows [26](26-udr-nudr-relocation.md)'s
> "nobody reads the AM/SM documents yet": the SMF now authorizes and parameterizes
> PDU sessions from the subscriber's UDR-provisioned sm-data / smf-selection data.

Until now the SMF accepted any DNN and the N1 PDU Session Establishment Accept
carried hardcoded S-NSSAI/AMBR bytes. This slice wires the TS 23.502 data path —
SMF → UDM (**Nudm_SDM**, TS 29.503) → UDR (Nudr) — so session establishment is
driven by what's actually provisioned.

## What was built

- **`sbi_core::nudm` gains Nudm_SDM** — `GET /nudm-sdm/v2/{supi}/sm-data` and
  `…/smf-select-data` (query `plmn-id`, concatenated MCC+MNC), proxying the UDR's
  provisioned-data documents verbatim; `NudmClient::get_sm_data` /
  `get_smf_select_data` (404 ⇒ `Ok(None)`).
- **SMF subscription check** (`nf-smf`) — `CreateSMContext` now, *before touching
  the UPF*: discovers the UDM via the NRF, requires the DNN to be listed in
  **smf-select-data** (`subscribedSnssaiInfos → dnnInfos`), and pulls the serving
  **S-NSSAI** + **session AMBR** from the matching **sm-data** DNN configuration.
  Unsubscribed DNN / unknown subscriber → **403** with no N4 state; NRF/UDM
  unreachable → **502** (fail closed). The subscribed `sNssai` and `sessionAmbr`
  ride back in the CreateSMContext response.
- **AMF passes the serving PLMN** — `servingNetwork {mcc, mnc}` in
  CreateSMContext (TS 29.502), from the AMF's configured PLMN; and builds the N1
  accept from the response's subscribed values.
- **`nas::pdu_session_establishment_accept` parameterized** — takes the S-NSSAI
  (SST + optional SD) and a `SessionAmbr`; `session_ambr_from_bitrates` converts
  TS 29.571 BitRate strings ("2 Gbps") to the TS 24.501 §9.11.4.14 unit/value
  encoding (integers only; fall back to the old 10 Mbps default if unparseable).
- **`nf-udr` demo provisioning** adds the smf-selection document
  (`1-010203 → dnn internet`), so the demo subscriber's authorization chain is
  complete.

Division of labour note: in TS 23.502 the *AMF* consumes smf-selection data to
pick an SMF. Our AMF still picks the first NRF-discovered SMF; the SMF using
smf-select-data as its authorization gate is the pragmatic interim, documented
here as a deviation.

## Verification

- `cargo test --workspace --exclude bdd` — green. Notable:
  - `nf-smf::pdu_session_create_then_update_drives_n4` now runs against a real
    NRF + UDR + UDM chain and asserts the subscribed S-NSSAI/AMBR in the response.
  - New `unsubscribed_dnn_is_rejected_without_n4_state` — unknown DNN and unknown
    subscriber both 403 **with zero N4 sessions created**; missing servingNetwork
    is 400.
  - `nas::session_ambr_bitrate_parsing` + accept-encoding assertions (AMBR DL/UL
    order, S-NSSAI IE with/without SD).
  - `nf-amf` mock-SMF test asserts the servingNetwork is sent and the subscribed
    values are parsed into NAS wire form.
- **BDD, both features green** (with `FREE_RAN_UE_BIN`): the live UE's PDU
  session now passes the smf-selection authorization gate and its accept carries
  the UDR-provisioned S-NSSAI (1/010203) and session AMBR (1/2 Gbps) — 4
  scenarios / 21 steps, teardown clean.

## Known limitations / next steps

- **Requested DNN still fixed at the AMF** — the AMF doesn't parse the UE's
  requested DNN out of the UL NAS Transport yet; it always asks for `internet`.
  NAS-SM request parsing is the natural next slice.
- **AMF-side SMF selection** — smf-select-data should eventually drive *which*
  SMF the AMF picks (per S-NSSAI/DNN), not just gate at the SMF.
- **QoS from sm-data** — only session AMBR is consumed; 5QI/ARP per-DNN QoS
  profiles remain the default match-all rule.
- **AM data still unread** — UE-AMBR / registration-area policy from am-data is
  the AMF's future consumption.
