# N2: NGAP over SCTP

**N2** is the interface between the gNB and the AMF. It carries **NGAP**
(NG Application Protocol, TS 38.413) — the control plane that sets up the gNB,
relays NAS signalling to and from the UE, and manages PDU session resources on
the radio side. NGAP is ASN.1, APER-encoded, and runs over **SCTP**.

In radiant-rs the AMF (`nf-amf`) terminates N2. The `ngap` crate wraps
`oxirush-ngap` and exposes exactly the messages the AMF and SMF build.

## The transport

The AMF listens on **SCTP port 38412** with NGAP's payload protocol identifier
(**PPID 60**, TS 38.412). It binds all interfaces:

```
N2 (NGAP/SCTP) listener up addr=0.0.0.0:38412 ppid=60
```

Each gNB opens one SCTP association; the AMF spawns a task per association that
owns that gNB's UE contexts. NGAP messages are `sctp_recv`'d, APER-decoded, and
dispatched by procedure.

## NG Setup

Before any UE can attach, the gNB and AMF exchange **NG Setup**. The gNB sends an
`NGSetupRequest` (its Global RAN Node ID, name, supported TAs, PLMN); the AMF
replies with an `NGSetupResponse` carrying its name, served GUAMI list, relative
capacity, and PLMN support list.

```
gNB → AMF   NGSetupRequest
AMF → gNB   NGSetupResponse
```

The `ngap` crate builds the response with a single helper:

```rust
pub fn ng_setup_response(amf_name: &str, mcc: &str, mnc: &str) -> NGAP_PDU
```

radiant-rs's AMF accepts NG Setup from any gNB; it does not enforce the gNB's
advertised PLMN against its own served PLMN. That is deliberate — it keeps the
core interoperable with simulators and lab gNBs whose PLMN may differ from the
subscriber's.

## Relaying NAS

Once N2 is up, NGAP becomes the courier for **N1 (NAS)** messages between the UE
and the AMF. The messages that matter for attach and session setup:

- **`InitialUEMessage`** — the gNB's first uplink for a UE, wrapping the UE's
  NAS Registration Request. The AMF pulls the RAN UE NGAP ID and the NAS PDU out
  of it.
- **`DownlinkNASTransport`** — the AMF sends NAS down to the UE (Authentication
  Request, Security Mode Command, Registration Accept, …).
- **`UplinkNASTransport`** — the UE's subsequent NAS up (Authentication Response,
  Security Mode Complete, the PDU session request, …).

The AMF keys each UE context by its **AMF-UE-NGAP-ID** and correlates uplink by
the RAN-UE-NGAP-ID the gNB assigned. Everything the UE says after the initial
message flows through these transport messages until the UE is registered.

## PDU Session Resource Setup

When a PDU session is established, the AMF sends a **PDU Session Resource Setup
Request** to the gNB carrying the UPF's N3 tunnel endpoint (F-TEID) and the N1 SM
container for the UE; the gNB replies with its own N3 F-TEID. This is the deepest
ASN.1 in the core — the "N2 SM information" is a set of separately APER-encoded
sub-PDUs (transfer-IEs) embedded as octet strings inside the NGAP message. The
[PDU session](ch-03-00-pdu-session.md) chapter covers this leg in full.

## Codec compatibility

radiant-rs's NGAP (via `oxirush-ngap`) is wire-compatible with the free5GC NGAP
library used by [free-ran-ue](ch-04-00-free-ran-ue-interop.md): NG Setup,
`InitialUEMessage`, the full downlink/uplink NAS transport exchange, and PDU
Session Resource Setup all interoperate. That is the first thing the interop
test proves.

## Verification

With the AMF running, point a gNB at `<amf-ip>:38412`. The AMF logs the
association and the setup:

```
gNB associated peer=127.0.0.1:38413
recv InitiatingMessage NGSetup (code=21)
sent NGSetupResponse
```
