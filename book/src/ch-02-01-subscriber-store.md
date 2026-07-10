# Subscriber Data (UDR) and Credentials

The **UDR** (Unified Data Repository) holds subscriptions, and behind it sits the
subscriber's long-term secret **K**. Everything about how radian-rs stores that
secret is shaped by one rule: **K must never escape**. This chapter covers the
store, the traits that enforce that boundary, and encryption at rest.

The **UDM** is a thin, stateless front end: the AUSF and AMF/SMF talk `Nudm` to
it, and it relays `Nudr` to the UDR. It holds no persistent state and never sees
K — only derived authentication vectors cross the UDM↔UDR wire.

## The ARPF boundary

The **ARPF** (Authentication credential Repository and Processing Function) is
the only component allowed to touch K. It is co-hosted in the UDR, and that
boundary is a trait, not a convention:

- **`ArpfKeyStore::generate_he_av(...)`** takes a SUPI, SQN, RAND, and serving
  network, and returns a 5G HE authentication vector. **K is an input to the
  computation, never an output.** It is not returned, not serialized, and not
  logged.
- **`SubscriberDb`** exposes subscriber existence and the mutable SQN.
- **`ProvisionedDataStore`** exposes the per-subscriber JSON documents (access &
  mobility data, session-management data, SMF-selection data, policy data).

`SubscriberStore` combines all three. When the AUSF authenticates a UE, the
request travels AUSF → `Nudm` (UDM) → `Nudr` (UDR); inside the UDR the store reads
the next SQN and calls `generate_he_av`, returning only the vector. K is recovered
solely in the UDR's memory, and only inside that computation — it never crosses
the SBI.

## Two backends

`crates/subscriber-db` provides two implementations of the store traits:

- **`InMemoryStore`** — a `HashMap`, for tests.
- **`RedbStore`** — persistent, backed by [redb](https://docs.rs/redb) (an
  embedded ACID key-value store). This is what `nf-udr` uses.

The `RedbStore` keeps distinct tables — encrypted `credentials`, the mutable
`auth_state` (the SQN), and the provisioned `am_data` / `sm_data` /
`smf_selection` / `policy_data` documents. Splitting the **SQN out of the
encrypted credentials** means each authentication can advance the sequence number
without touching (or re-encrypting) the record that holds K.

## Encryption at rest

The `RedbStore` does not write K in the clear. Each credential record is
**AES-256-GCM** encrypted with a per-record nonce, using the **SUPI as additional
authenticated data**, under a **key-encryption key (KEK)** injected at open time:

```rust
RedbStore::open(path, kek)   // kek: [u8; 32]
```

So the on-disk file contains only ciphertext; K is recovered only in memory, only
inside the ARPF computation, and only when the correct KEK is supplied. Reading
the file with the wrong KEK fails; K never appears as plaintext on disk.

The file itself is created **owner-only (0600)** without a TOCTOU window (the mode
is set at `open` time via the redb builder), so even before encryption the raw
bytes are not world-readable.

## Where the KEK comes from

`nf-udr` sources the KEK from `RADIAN_UDR_MASTER_KEY` (64 hex characters):

```
RADIAN_UDR_MASTER_KEY=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
```

If it is unset, the UDR generates an **ephemeral** KEK and warns loudly —
persisted records become unreadable after the next restart. The KEK injection
point is the **HSM/KMS seam**: today the key comes from the environment; wiring it
to a hardware security module or a KMS is a drop-in change at that one boundary.
Key rotation is not yet implemented.

## Provisioning

The demo subscriber (a public TS 35.208 test key) is provisioned **only** when
`RADIAN_UDR_PROVISION_DEMO=1`, so a production build never ships a known-key
account. Alongside the credentials it seeds the matching AM/SM/SMF-selection and
policy documents. There is no general provisioning CLI yet; the demo subscriber is
the one [Building and Running](ch-00-02-building-and-running.md) and the interop
flow use.

## A note on layering

The 3GPP split places subscription data in the **UDR** (Nudr) with the **UDM** as
a stateless front end, and radian-rs follows it: the store and the ARPF live behind
`nf-udr`, and `nf-udm` proxies to it without holding state or seeing K. The trait
boundary above is what made that split clean — the ARPF contract does not change
whether the store is called in-process or across the `Nudr` interface.
