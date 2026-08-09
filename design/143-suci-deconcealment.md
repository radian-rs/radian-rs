# SUCI deconcealment at the UDM (design/137 G2)

> Built 2026-08-09 on branch `free5gc`. Closes **G2** from
> [137](137-free5gc-422-gap-survey.md) §8 (Major — *a privacy-enabled UE cannot
> authenticate*). Companion to [19](19-suci-deconcealment-live-ue.md) (the
> AMF-side null-scheme stopgap); this moves deconcealment to its spec-correct
> home (the UDM) and adds the ECIES profiles.

## The gap

The UDM treated the `supiOrSuci` path segment of `generate-auth-data` as the
SUPI verbatim (`nudm.rs`: *"SUCI deconcealment is out of scope"*). It supported
**no** protection scheme — not even null at the UDM — and had no home-network
key store, so an ECIES-concealed SUCI (Profile A/B, the privacy-preserving
schemes a real UE uses) could never resolve to a subscriber.

Both reference stacks deconceal at the UDM (open5gs `ogs_supi_from_supi_or_suci`,
free5gc `udm/pkg/suci`). [138](138-open5gs-gap-survey.md) flagged this as *table
stakes* and noted open5gs's cheap shape: one library call keyed by a flat home-
network key list.

## What this slice does

### `crates/aka::suci` — the deconcealment library

`deconceal(input, keys) -> Result<String>`:
- A plain SUPI (`imsi-…`) passes through unchanged (the caller may pass either).
- A SUCI (`suci-<type>-<mcc>-<mnc>-<routing>-<scheme>-<keyId>-<output>`,
  TS 29.571) is parsed and resolved by scheme:
  - **Null** (0): the scheme output *is* the MSIN.
  - **Profile A** (1): ECIES over **X25519**.
  - **Profile B** (2): ECIES over **P-256** (compressed points).

Both ECIES profiles share the TS 33.501 C.3.2 construction, differing only in
the curve and ephemeral-public-key length:

1. ephemeral-static ECDH → shared secret `Z`;
2. **ANSI-X9.63 KDF** (SHA-256) over `Z ‖ counter ‖ eph_pub` → 64 octets =
   AES-128 key (16) ‖ initial counter block (16) ‖ HMAC key (32);
3. verify the trailing 8-octet **HMAC-SHA-256** tag over the ciphertext;
4. **AES-128-CTR** decrypt → TBCD-decode → the MSIN digits.

The home network's **private** key stays at the UDM (`HomeNetworkKeys`, keyed by
scheme + key id, so it can rotate). A `conceal` (UE-side) counterpart exists so
the round trip is unit-tested without external vectors.

### UDM wiring (`crates/sbi-core/src/nudm.rs`)

`generate_auth_data` now calls `aka::suci::deconceal` before the UDR lookup, uses
the resulting SUPI for `generate_av`, and returns the **deconcealed SUPI** in the
response (a deconcealment failure → `403`). The home-network keys load from the
environment in `router()` — `RADIAN_UDM_HNET_A_KEY` (64-hex X25519 private key,
id via `…_A_KEY_ID`, default 1) and `RADIAN_UDM_HNET_B_KEY` (P-256 scalar, id
default 2); absent ⇒ only null-scheme SUCIs and plain SUPIs resolve.

The **AUSF needs no change**: it already keys its context on the SUPI the UDM
returns (`nausf.rs` `supi: result.supi`), so the deconcealed SUPI now flows
AUSF→AMF automatically. And the AMF already forwards a protected SUCI as its
canonical `suci-…` string (`nas::suci_to_supi` returns the canonical string for
a non-null scheme), which is exactly the form the UDM parses — so Profile A/B
resolves end to end once a home-network key is configured.

## Decisions

- **D1 — deconceal at the UDM, keep the AMF null-scheme stopgap.** The UDM is
  the spec-correct place (it holds the home-network key). [19](19-suci-deconcealment-live-ue.md)'s
  AMF-side null-scheme conversion still runs, so a null-scheme SUCI reaches the
  UDM already as a SUPI (passthrough) — harmless, and the UDM's own null handler
  is the correct backstop. Moving null-scheme deconcealment entirely to the UDM
  (dropping the AMF stopgap) is a follow-up.
- **D2 — verbatim spec construction, round-trip tested.** Rather than depend on
  external test vectors, the crate implements both `conceal` and `deconceal` and
  round-trips them; the construction follows TS 33.501 C.3.2 exactly (KDF
  partition, MAC-over-ciphertext, TBCD MSIN) so it is interop-shaped.
- **D3 — env-configured keys, no signature churn.** `router()` loads the keys
  from the environment (radian's current config model), so no caller changes.
- **D4 — `ctr = "0.9"`.** `aes 0.8` uses `cipher 0.4`; `ctr 0.10` pulls the
  incompatible `cipher 0.5`. Pinning `ctr 0.9` keeps both on `cipher 0.4`.

## Tests

- `crates/aka::suci` (6): null + plain-SUPI passthrough; malformed / unknown-
  scheme / missing-key rejection; TBCD even/odd round trip; **Profile A** and
  **Profile B** conceal→deconceal round trips; a tampered ciphertext caught by
  the MAC.
- `crates/sbi-core` `generate_auth_data_deconceals_a_suci` — a null-scheme SUCI
  through the real UDM→UDR chain resolves to the provisioned SUPI, an AV comes
  back, and the response carries the deconcealed SUPI; a plain SUPI still works.
- aka 16, sbi-core suite green; clippy clean; BDD `scripted_reg` (22/253) passes
  (no regression to the existing identity path).

## Follow-ups

- **Live Profile A/B interop**: configure a home-network keypair whose public
  key matches free-ran-ue's SUCI config, then verify an ECIES `@sim` registration
  (the crypto + wiring are done; only matched keys + a scenario remain).
- **Move null-scheme deconcealment off the AMF** (retire [19](19-suci-deconcealment-live-ue.md)'s
  stopgap) so the AMF forwards every SUCI and the UDM is the sole deconcealer.
- **Config file** for `hnet` keys (pairs with [G5](137-free5gc-422-gap-survey.md)),
  replacing the env vars.
