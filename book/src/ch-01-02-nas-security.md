# NAS Security

Once the UE is authenticated, every subsequent NAS message between the UE and the
AMF is **integrity-protected and (after the security mode exchange) ciphered**.
Setting that up is the **Security Mode** procedure, and it is what turns an
authenticated UE into a REGISTERED one.

## Deriving the NAS keys

From **K_SEAF** (the output of [5G-AKA](ch-01-01-registration-5g-aka.md)) the AMF
derives **K_AMF** using the SUPI and the ABBA parameter, then derives the two NAS
keys from K_AMF and the selected algorithm identifiers:

- **K_NASint** — integrity, used by **128-NIA2** (AES-CMAC).
- **K_NASenc** — ciphering, used by **128-NEA2** (AES-CTR).

radiant-rs selects **NIA2 / NEA2**. The `aka` crate provides `kamf` and
`nas_keys`; the `nas` crate holds the resulting `NasSecurityContext`, which
protects and unprotects messages and tracks the uplink/downlink NAS counts.

## The security mode exchange

```
AMF → UE   Security Mode Command   (integrity-protected, new context)
UE  → AMF   Security Mode Complete  (integrity + ciphered)
AMF → UE   Registration Accept      (integrity + ciphered, assigns a 5G-GUTI)
UE  → AMF   Registration Complete
```

The **Security Mode Command** carries the selected NAS algorithms, the key set
identifier, and a **replay of the UE's advertised security capabilities**. That
replay matters: the UE compares it against what it originally sent, and rejects
the command if they differ — a bidding-down defence (TS 24.501 §8.2.25).
radiant-rs therefore echoes the UE's *own* `ue_security_capability` from the
Registration Request, not a fixed value.

The Security Mode Command is integrity-protected under a *new* security context
(security header type "integrity protected with new 5G NAS security context");
everything after it is integrity-protected **and** ciphered.

## Registration Accept and the 5G-GUTI

On **Security Mode Complete**, the AMF sends a protected **Registration Accept**
that assigns the UE a **5G-GUTI** (a temporary identity so the SUCI need not be
sent again). The UE answers with **Registration Complete**.

radiant-rs then sends one more downlink — a **Configuration Update Command**. A
compliant UE waits for it after Registration Complete before it will start a PDU
session, so the AMF issues a minimal one to unblock the UE.

At this point the UE is **REGISTERED**:

```
UE 1: SecurityModeComplete — sending Registration Accept
sent DownlinkNASTransport (RegistrationAccept)
UE 1 REGISTERED (suci=Some("imsi-999700000000001"), state=Registered)
sent DownlinkNASTransport (ConfigurationUpdateCommand)
```

## The NAS security envelope

Protected NAS messages carry a 7-byte security header — extended protocol
discriminator, security header type, a 4-byte message authentication code, and a
1-byte sequence number — followed by the (optionally ciphered) inner NAS message.
The `nas` crate builds this envelope over `oxirush-security`'s `nas_mac` and
`nas_cipher`. The downlink and uplink NAS counts are tracked in the security
context so replay and ordering are enforced.

## Algorithm negotiation

radiant-rs currently fixes on **NIA2 / NEA2**. It does not yet negotiate the
strongest common algorithm from the UE's advertised set — it selects NIA2/NEA2
and replays the UE's capabilities for the bidding-down check. A UE that does not
support NEA2/NIA2 would need that negotiation, which is future work.
