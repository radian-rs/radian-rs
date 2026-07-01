# Registration and 5G-AKA

Registration is how a UE attaches to the network and proves who it is. In
radiant-rs it joins two planes — the binary **N2/N1** signalling the AMF speaks
to the gNB and UE, and the JSON **SBI** the AMF speaks to the AUSF and UDM — into
a single flow that ends with the UE **REGISTERED** and holding a NAS security
context.

## The cast

- **AMF** (`nf-amf`) drives the flow and acts as the **SEAF** (the security
  anchor in the serving network).
- **AUSF** (`nf-ausf`) runs `Nausf_UEAuthentication`: it fetches an
  authentication vector, challenges the UE, and confirms the result.
- **UDM** (`nf-udm`) holds the subscription and, behind the ARPF boundary,
  computes the vector from the subscriber's long-term key **K**.
- **`aka`** is the crypto crate: Milenage (f1–f5) and the TS 33.501 key
  derivations, validated against the TS 35.208 test vectors.

## The flow

```
UE  → AMF   Registration Request (SUCI)
AMF → AUSF  Nausf_UEAuthentication          (discovers AUSF via the NRF)
AUSF→ UDM   Nudm_UEAuthentication → 5G HE AV (RAND, AUTN, HXRES*, K_AUSF)
AMF → UE    Authentication Request (RAND, AUTN)
UE  → AMF   Authentication Response (RES*)
AMF → AUSF  confirm RES*                    → K_SEAF
```

Step by step:

1. The UE's **Registration Request** carries a **SUCI** (the concealed
   subscriber identity). The AMF deconceals it to a SUPI — see
   [SUCI to SUPI](ch-01-03-suci-deconcealment.md).
2. The AMF **discovers the AUSF** through the NRF and calls
   `Nausf_UEAuthentication`, passing the SUPI and the serving-network name.
3. The AUSF asks the UDM for a **5G Home Environment Authentication Vector**. The
   UDM reads the next **SQN** for the subscriber and asks the ARPF layer to
   generate the vector: `RAND`, `AUTN`, `HXRES*`, and `K_AUSF`, derived from **K**
   with Milenage. **K never leaves the ARPF boundary** — it is never returned,
   serialized, or logged.
4. The AMF sends a NAS **Authentication Request** (`RAND`, `AUTN`) to the UE. The
   UE checks `AUTN`, computes `RES*`, and replies with an **Authentication
   Response**.
5. The AMF (SEAF) verifies the response with the AUSF, which on success returns
   **K_SEAF** — the root of the NAS keys.

From K_SEAF the AMF derives **K_AMF** and the NAS keys, then moves on to
[NAS security](ch-01-02-nas-security.md).

## The key ladder

```
        K  (in the UDM/ARPF only)
        │  Milenage f2..f5
   CK, IK
        │  TS 33.501 KDF (FC=0x6A)
   K_AUSF
        │
   K_SEAF   ── returned to the AMF/SEAF on success
        │  KDF with SUPI + ABBA
   K_AMF
        │
   K_NASenc, K_NASint   ── the NAS security context
```

The `aka` crate implements each rung and is verified against the published test
sets, so a UE and the core derive identical keys.

## SQN and freshness

The UDM's store keeps a per-subscriber **sequence number** and hands out the next
value for each authentication. The UE checks that the network's SQN is fresh. If
the UE's stored SQN is ahead of the network's, real 5G-AKA recovers with a
resynchronisation (AUTS); radiant-rs does **not** yet implement AUTS/resync, so a
test UE should start from an SQN at or below the network's next value.

## Discovery, not configuration

The AMF does not hard-code the AUSF's address. It calls the NRF —
`discover("AUSF", "AMF")` — and uses the returned service endpoint. For this to
work the AUSF must be registered with the NRF; `nf-ausf` **self-registers** on
startup (as the SMF does), so no manual step is needed. See
[The SBI Spine and the NRF](ch-02-00-sbi-nrf.md).

## Verification

A completed authentication shows in the AMF log:

```
UE 1 identified (imsi-999700000000001); starting authentication
sent DownlinkNASTransport (AuthenticationRequest)
recv InitiatingMessage UplinkNASTransport (code=46)
UE 1 authenticated (imsi-999700000000001); establishing NAS security
```
