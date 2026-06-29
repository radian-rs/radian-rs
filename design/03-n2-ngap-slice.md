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
4. **UE registration + per-UE context** — on `InitialUEMessage`, allocates an
   AMF-UE-NGAP-ID and stores a `UeContext` (keyed by it, per SCTP association). If
   the `RegistrationRequest` already carries a SUCI the UE is marked *Identified*;
   otherwise the AMF replies with a NAS **Identity Request** (`DownlinkNASTransport`).
5. **Uplink correlation** — `UplinkNASTransport` is correlated to its UE by
   AMF-UE-NGAP-ID; an Identity Response stores the SUCI and completes identification.
   Unknown UEs are rejected.

## Crate wiring (matches the encoding boundaries in `design/02`)

| Crate | Backed by | Role |
|---|---|---|
| `ngap` | [`oxirush-ngap`](https://crates.io/crates/oxirush-ngap) 0.3 (APER, TS 38.413) | re-exports NGAP types + macros; builders `ng_setup_response`, `downlink_nas_transport`, `uplink_nas_transport`, `initial_ue_message_with_nas` |
| `nas` | [`oxirush-nas`](https://crates.io/crates/oxirush-nas) 0.2 (TLV, TS 24.501) | re-exports `decode_nas_5gs_message` + SUCI accessors; builder `identity_request_suci` |
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
  - `uplink_nas_transport_roundtrips` — UplinkNASTransport APER round-trip.
  - `initial_ue_message_nas_decodes_to_registration` — decode off the wire → `RegistrationRequest`.
  - `registration_with_suci_identifies_without_identity_request` — a SUCI-bearing
    RegistrationRequest marks the UE *Identified* (SUCI MCC 999 / MNC 70), no downlink.
  - `unidentified_initial_ue_triggers_identity_request` — no SUCI → `DownlinkNASTransport`
    (Identity Request), state *IdentityRequested*.
  - `uplink_nas_correlates_to_known_ue_only` — uplink correlates by AMF-UE-NGAP-ID;
    unknown UE is rejected.
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
- **Context is per-association, in-memory** — `UeContext` lives in the gNB
  association task (no shared store, no persistence, NGAP IDs not reused across gNBs).
- **SUCI not deconcealed** — the SUCI is parsed and stored as text, not resolved to a
  SUPI (needs the home-network private key / UDM).
- **Registration stalls at identified** — no Authentication / Security Mode /
  Registration Accept yet; those need AUSF/UDM over SBI.
- **No SBI yet** — the AMF doesn't talk to AUSF/UDM/NRF (TS 29.518/509/503/510).
  Next slice: stand up the SBI spine so AMF↔AUSF↔UDM authentication can run.
- **One NAS-PDU per InitialUEMessage** assumed; no SCTP message reassembly across
  `MSG_EOR` boundaries yet.
