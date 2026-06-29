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
4. **UE registration started** — extracts the `NAS-PDU` from `InitialUEMessage`,
   decodes it (→ `RegistrationRequest`), allocates an AMF-UE-NGAP-ID, and replies
   with a NAS **Identity Request** (SUCI) wrapped in `DownlinkNASTransport`.
5. **Uplink NAS surfaced** — decodes and logs the NAS in `UplinkNASTransport`
   (e.g. the UE's Identity Response).

## Crate wiring (matches the encoding boundaries in `design/02`)

| Crate | Backed by | Role |
|---|---|---|
| `ngap` | [`oxirush-ngap`](https://crates.io/crates/oxirush-ngap) 0.3 (APER, TS 38.413) | re-exports NGAP types + macros; AMF builders `ng_setup_response`, `downlink_nas_transport`, `initial_ue_message_with_nas` |
| `nas` | [`oxirush-nas`](https://crates.io/crates/oxirush-nas) 0.2 (TLV, TS 24.501) | re-exports `decode_nas_5gs_message`; builder `identity_request_suci` |
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
  - `downlink_nas_transport_roundtrips` — DownlinkNASTransport APER round-trip.
  - `initial_ue_message_nas_decodes_to_registration` — **decode the way the AMF does
    off the wire**, extract NAS-PDU, decode → `RegistrationRequest`.
  - `initial_ue_yields_identity_request_downlink` — driving the handler on a
    `RegistrationRequest` produces a `DownlinkNASTransport` carrying a NAS
    `IdentityRequest`.
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
- **One step only, stateless** — registration advances exactly one round (Identity
  Request). There is no per-UE context keyed by AMF/RAN-UE-NGAP-ID yet, so the UE's
  Identity Response is logged but not correlated, and there is no Authentication /
  Security Mode / Registration Accept (those need AUSF/UDM over SBI).
- **No SBI yet** — the AMF doesn't talk to AUSF/UDM/NRF (TS 29.518/509/503/510).
  Next slice candidates: (a) hold per-UE context and continue the flow toward
  authentication; (b) stand up the SBI spine so AMF↔AUSF↔UDM auth can run.
- **One NAS-PDU per InitialUEMessage** assumed; no SCTP message reassembly across
  `MSG_EOR` boundaries yet.
