# N2 / NGAP Slice (AMF) — Implementation Notes

> Built 2026-06-29 on branch `feat/n2-ngap-amf`. First real protocol slice past the scaffold.

De-risks the project's hardest, most telecom-specific surface: the **N2 path**
(NGAP ASN.1 + NAS). Everyone can do JSON REST; the differentiator is the ASN.1 +
SCTP signalling plane. This slice proves that path end to end in Rust.

## What was built

`nf-amf` now terminates **N2** (TS 38.412 / 38.413):

1. **SCTP transport** — binds an SCTP listener on `0.0.0.0:38412`, one task per gNB
   association, NGAP PPID 60.
2. **NGAP decode/dispatch** — every inbound PDU is APER-decoded and routed by
   procedure.
3. **NG Setup** — answers `NGSetupRequest` with a valid `NGSetupResponse`
   (AMFName, ServedGUAMIList, RelativeAMFCapacity, PLMNSupportList).
4. **UE registration surfaced** — extracts the `NAS-PDU` IE from `InitialUEMessage`
   and decodes it (→ `RegistrationRequest`), logging the NAS contents.

## Crate wiring (matches the encoding boundaries in `design/02`)

| Crate | Backed by | Role |
|---|---|---|
| `ngap` | [`oxirush-ngap`](https://crates.io/crates/oxirush-ngap) 0.3 (APER, TS 38.413) | re-exports NGAP types + macros; adds AMF builders (`ng_setup_response`, `initial_ue_message_with_nas`) |
| `nas` | [`oxirush-nas`](https://crates.io/crates/oxirush-nas) 0.2 (TLV, TS 24.501) | re-exports `decode_nas_5gs_message` etc. |
| `nf-amf` | `sctp-rs` 0.3 (kernel SCTP) + `ngap` + `nas` | the N2 server |

The ASN.1 dependency stays isolated behind the `ngap` crate boundary — `nf-amf`
never names `oxirush-ngap` directly. `oxirush-ngap` regenerates its codec from the
3GPP ASN.1 at build time (pin the crate version to pin the TS 38.413 release).

> Macro note: `oxirush-ngap`'s `build_ngap!` expands to a bare `paste::paste!` and
> unqualified type names, so the builders live in the `ngap` crate (which has the
> `paste` dep + a `use oxirush_ngap::ngap::*` glob in scope). Callers just use
> `ngap::ng_setup_response(...)`.

## Verification

- `cargo test -p ngap -p nf-amf` — green:
  - `ng_setup_response_roundtrips` — build → APER encode → decode → equal; procedure
    `NGSetup`, `SuccessfulOutcome`.
  - `initial_ue_message_nas_decodes_to_registration` — build `InitialUEMessage`
    carrying a NAS `RegistrationRequest`, APER encode, **decode the way the AMF does
    off the wire**, extract NAS-PDU, decode → `RegistrationRequest`.
- Runtime: `nf-amf` binds the N2 SCTP listener on `:38412` (kernel SCTP confirmed
  working).

## How to test with a real gNB/UE (UERANSIM)

The codec + transport are proven by tests; full over-the-wire validation needs a
gNB simulator and is run outside CI.

```sh
sudo modprobe sctp                 # ensure kernel SCTP is loaded
RUST_LOG=info cargo run -p nf-amf   # AMF: N2 listener on :38412

# UERANSIM (separate checkout) — set gNB amfConfigs.address to the AMF host and
# PLMN mcc=999 mnc=70 (the PLMN this AMF advertises), then:
./nr-gnb -c config/gnb.yaml         # → AMF logs "sent NGSetupResponse"
sudo ./nr-ue -c config/ue.yaml      # → AMF logs "NAS in InitialUEMessage: RegistrationRequest ..."
```

PacketRusher works equivalently as a combined gNB+UE load generator.

## Known limitations / next steps

- **PLMN is hard-coded** (999/70, SST 1). A real AMF should echo the gNB's
  `SupportedTAList` PLMN in NG Setup; mismatched PLMNs make the gNB reject setup.
- **No call-flow state machine** — registration is logged, not advanced
  (no Authentication / Security Mode / Registration Accept).
- **No SBI yet** — the AMF doesn't talk to AUSF/UDM/NRF (TS 29.518/509/503/510).
  Next slice candidates: (a) drive the registration flow far enough to send a NAS
  downlink (Identity/Authentication Request) back to the UE; (b) stand up the SBI
  spine so AMF↔AUSF↔UDM auth can run.
- **One NAS-PDU per InitialUEMessage** assumed; no SCTP message reassembly across
  `MSG_EOR` boundaries yet.
