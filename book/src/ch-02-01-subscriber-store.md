# Subscriber Data (UDM) and Credentials

The **UDM** holds subscriptions, and behind it sits the subscriber's long-term
secret **K**. Everything about how radian-rs stores that secret is shaped by one
rule: **K must never escape**. This chapter covers the store, the traits that
enforce that boundary, and encryption at rest.

## The ARPF boundary

The **ARPF** (Authentication credential Repository and Processing Function) is
the only component allowed to touch K. In radian-rs that boundary is a trait, not
a convention:

- **`ArpfKeyStore::generate_he_av(...)`** takes a SUPI, SQN, RAND, and serving
  network, and returns a 5G HE authentication vector. **K is an input to the
  computation, never an output.** It is not returned, not serialized, and not
  logged.
- **`SubscriberDb`** exposes subscriber existence and the mutable SQN.

`SubscriberStore` combines them. The UDM's SBI front end
([`sbi_core::nudm`](ch-02-00-sbi-nrf.md)) reads the next SQN and calls
`generate_he_av` — it never sees K.

## Two backends

`crates/subscriber-db` provides two implementations of the store traits:

- **`InMemoryStore`** — a `HashMap`, for tests.
- **`RedbStore`** — persistent, backed by [redb](https://docs.rs/redb) (an
  embedded ACID key-value store). This is what `nf-udm` uses.

## Encryption at rest

The `RedbStore` does not write K in the clear. Each record is **AES-256-GCM**
encrypted with a per-record nonce, using the **SUPI as additional authenticated
data**, under a **key-encryption key (KEK)** injected at open time:

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

`nf-udm` sources the KEK from `RADIAN_UDM_MASTER_KEY` (64 hex characters):

```
RADIAN_UDM_MASTER_KEY=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
```

If it is unset, the UDM generates an **ephemeral** KEK and warns loudly —
persisted records become unreadable after the next restart. The KEK injection
point is the **HSM/KMS seam**: today the key comes from the environment; wiring it
to a hardware security module or a KMS is a drop-in change at that one boundary.
Key rotation is not yet implemented.

## Provisioning

The demo subscriber (a public TS 35.208 test key) is provisioned **only** when
`RADIAN_UDM_PROVISION_DEMO=1`, so a production build never ships a known-key
account. There is no general provisioning CLI yet; the demo subscriber is the one
[Building and Running](ch-00-02-building-and-running.md) and the interop flow use.

## A note on layering

Architecturally the subscription data belongs in the **UDR** (Nudr), with the UDM
as a stateless front end. radian-rs currently keeps the store directly behind the
UDM; relocating it behind `nf-udr` is future work. The trait boundary above is
what makes that move safe — the ARPF contract does not change.
