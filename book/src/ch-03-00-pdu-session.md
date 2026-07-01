# The PDU Session Call Flow

A **PDU session** is what gives a registered UE actual connectivity — an IP
address and a path to a data network. Establishing one is the most cross-cutting
flow in the core: it touches **N1** (the UE's session request), **SBI** (the AMF
asking the SMF), **N4** (the SMF programming the UPF), and **N2** (the AMF telling
the gNB where the tunnel ends are). This chapter is the map; the
[N4](ch-03-01-n4-pfcp.md), [N3](ch-03-02-n3-gtpu.md), and
[N6](ch-03-03-n6-forwarding.md) chapters zoom into each leg.

## The flow

```
UE  → AMF   UL NAS Transport (PDU Session Establishment Request)   [N1]
AMF → SMF   Nsmf_PDUSession_CreateSMContext                        [SBI]
SMF → UPF   N4 Session Establishment                               [N4]
            ⇒ UPF allocates the uplink N3 F-TEID + records the UE IP
AMF → gNB   PDU Session Resource Setup Request (UPF F-TEID + N1 SM) [N2]
gNB → AMF   PDU Session Resource Setup Response (gNB F-TEID)        [N2]
AMF → SMF   Nsmf_PDUSession_UpdateSMContext (gNB F-TEID)           [SBI]
SMF → UPF   N4 Session Modification (Outer Header Creation → gNB)   [N4]
            ⇒ both tunnel ends installed
```

Walking it through:

1. The UE sends a **PDU Session Establishment Request** (a 5GSM message) inside a
   5GMM **UL NAS Transport**. The AMF pulls out the PDU session id and the N1 SM
   container.
2. The AMF **discovers the SMF** via the NRF and calls
   **`CreateSMContext`**, passing the SUPI, the PDU session id, and the DNN.
3. The SMF runs an **N4 Session Establishment** with the UPF. The UPF **allocates
   the uplink N3 F-TEID** and records the **UE IP** the SMF assigned. The SMF
   returns the UPF's N3 F-TEID and the UE IP to the AMF.
4. The AMF builds an **N2 PDU Session Resource Setup Request** carrying the UPF's
   N3 F-TEID and a NAS-protected **N1 PDU Session Establishment Accept**, and
   sends it to the gNB.
5. The gNB sets up its side of the N3 tunnel and replies with **its own N3
   F-TEID**.
6. The AMF hands the gNB's F-TEID to the SMF via **`UpdateSMContext`**; the SMF
   runs an **N4 Session Modification** that installs an **Outer Header Creation**
   toward the gNB. Now the downlink tunnel is complete too.

After this, both tunnel endpoints exist and the UPF can forward.

## The N1 SM Accept

The **PDU Session Establishment Accept** is the 5GSM message the UE reads to
configure its stack — it carries the **assigned IP** (the PDU address), the
authorized **QoS rules**, the **session AMBR**, the **S-NSSAI**, and the **DNN**.
radiant-rs builds it as a proper TS 24.501 message (`nas::pdu_session_establishment_accept`),
wraps it in a 5GMM **DL NAS Transport**, NAS-protects it, and places it as the
NAS-PDU in the N2 setup. The gNB relays it to the UE, which then brings up its
own tunnel interface with the assigned IP.

## UE IP allocation

The **SMF** allocates the UE IP (from a simple pool, e.g. `10.45.0.2` and up) and
carries it into the N4 session establishment so the UPF can route downlink
traffic back to the right session. The UPF keys sessions by UE IP for the
[downlink datapath](ch-03-03-n6-forwarding.md). The UE learns the same address
from the N1 Accept above.

## What the SMF is

`nf-smf` is a real NF: an SBI **server** (the AMF calls its `Nsmf_PDUSession`
service on **:8002**) and a PFCP **client** (it drives the UPF over N4). On
startup it PFCP-**associates** with the UPF and **registers** with the NRF so the
AMF can find it.

## Verification

The AMF and SMF narrate the flow:

```
# AMF
UE 1: PDU session 4 SM context created (UE IP 10.45.0.2); sending N2 setup
sent PDUSessionResourceSetupRequest
recv SuccessfulOutcome PDUSessionResourceSetup (code=29)
UE 1: PDU session 4 downlink installed (gNB F-TEID 0x1)

# SMF
created SM context; N4 session established up_seid=1 n3_teid=1 ue_ip=10.45.0.2
updated SM context; N4 downlink installed gnb_teid=1
```

## Limitations

One PDU session per UE, IPv4 only, DNN `internet`, a single default QoS rule.
Architecturally the **SMF** should build the N1 SM container (TS 29.502
multipart); today the AMF assembles it from the SMF's returned UE IP. These are
documented simplifications, not hidden ones.
