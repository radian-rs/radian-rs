# SUCI to SUPI Deconcealment

A UE never sends its permanent identity (the **SUPI**, an IMSI) in the clear over
the air. Instead it sends a **SUCI** — the Subscription Concealed Identifier — in
its Registration Request. The AMF must turn that SUCI back into a SUPI to look
the subscriber up in the UDM. That step is **deconcealment**.

## Why it matters

Subscribers are keyed in the UDM by their SUPI (`imsi-999700000000001`). If the
AMF passed the SUCI straight through, the UDM lookup would miss and
authentication would fail. Getting deconcealment right is what lets a *real* UE —
one that sends a SUCI rather than a bare SUPI — authenticate at all. It was the
first gap the [free-ran-ue interop](ch-04-00-free-ran-ue-interop.md) surfaced.

## The null scheme

A SUCI carries a **protection scheme**. radian-rs implements the **null scheme**
(scheme 0), which is what a UE uses when no home-network public key is
provisioned. For the null scheme the "scheme output" is simply the **MSIN** in
BCD, and deconcealment is a direct decode:

```
SUPI = "imsi-" + MCC + MNC + MSIN
```

`nas::suci_to_supi` performs this: it reads the MCC/MNC digits and BCD-decodes the
scheme output (low nibble first, dropping the `0xF` filler). For example a SUCI
with MCC 999, MNC 70, and scheme output `00 00 00 00 10` deconceals to
`imsi-999700000000001`.

```rust
pub fn suci_to_supi(suci: &Suci) -> String
```

The AMF calls this while parsing the Registration Request, and from then on the
UE is identified by its SUPI throughout authentication and session management.

## ECIES schemes

The **Profile A / Profile B (ECIES)** protection schemes conceal the MSIN with
the home network's public key and require the operator's private key to
deconceal. radian-rs does not yet implement them; a non-null SUCI falls back to
a canonical string form (`suci-0-…`) that is inspectable but will not resolve to
a subscriber. Supporting ECIES is future work — the null scheme covers lab UEs
and simulators, which is what the interop flow uses.

## Verification

The AMF logs the deconcealed identity when it accepts the initial message:

```
recv InitiatingMessage InitialUEMessage (code=15)
UE 1 identified (imsi-999700000000001); starting authentication
```

The `imsi-…` form — rather than a `suci-…` string — confirms the SUCI was
deconcealed and the subscriber will be found in the UDM.
