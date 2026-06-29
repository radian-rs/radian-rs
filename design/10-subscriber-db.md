# Subscription Store — Traits + Persistent Backend

> Built 2026-06-29 on branch `feat/subscriber-db-store`. Moves the subscriber DB off an in-memory map onto a real seam.

The UDM's subscriber data — including the **root key K** of the whole system — was a
plain in-memory `HashMap`. This slice puts it behind traits with a persistent
backend, and isolates the secret material so K never crosses the store boundary.

## What was built

- **`subscriber-db` crate** — two traits and two backends:
  - `SubscriberDb` — `exists` + `next_sqn` (atomic post-increment).
  - `ArpfKeyStore` — `generate_he_av(...)`: holds K/OPc and computes the
    authentication vector internally. **K never returns across the trait** — only
    RAND/AUTN/XRES*/K_AUSF leave.
  - `InMemoryStore` (tests/dev) and `RedbStore` (persistent, [redb](https://crates.io/crates/redb) — embedded, ACID, pure-Rust).
- **`sbi_core::nudm`** — refactored to a **stateless front-end** over
  `Arc<dyn SubscriberStore>`: it reads the next SQN and asks the store for a vector.
  The UDM module no longer touches K at all.
- **`nf-udm`** — opens a persistent `RedbStore` and provisions the demo subscriber
  (TS 35.208 key) once; the SQN survives restarts.

## Why this shape (the design)

| Data class | Examples | Concern |
|---|---|---|
| Auth credentials | K, OPc, AMF | **root secret** — behind `ArpfKeyStore`; never serialized to the wire/logs; encrypt-at-rest / HSM in prod |
| Auth state | SQN | hot, atomic per-auth updates (a redb write txn) |
| Subscription profile | NSSAI, DNN, QoS | (not modeled yet) mostly-read, provisioned rarely |

Per TS 23.501 / 29.504 this data belongs in the **UDR** (Nudr), with the UDM as a
stateless front-end. We already match the "front-end" half; relocating the store
behind `nf-udr` is a later slice. The `ArpfKeyStore` seam is where an **HSM / PKCS#11
/ vault** plugs in — and where the SUCI home-network private key will live.

## Verification

- `cargo test` — green (22 tests workspace-wide):
  - `subscriber-db`: `in_memory_sqn_increments_and_av_generates`;
    `redb_persists_across_reopen` (subscriber + advanced SQN survive a close/reopen).
  - The full registration / 5G-AKA flows (`nf-amf`, `nausf`) still pass through the
    new trait store unchanged.
- Runtime smoke of `nf-udm` (persistent redb): two auth-data calls return **different
  AUTNs** (SQN advanced and persisted); unknown subscriber → `404`; the response
  carries only RAND/AUTN/XRES*/K_AUSF — **never K**. The `.redb` file is gitignored.

## Known limitations / next steps

- **Not encrypted at rest** — `RedbStore` persists K/OPc in the clear. Production
  needs encryption-at-rest or, better, an HSM behind `ArpfKeyStore` (K never on disk
  in the clear). Tracked.
- **Not behind the UDR yet** — still a UDM-local store; the Nudr relocation is future.
- **Profile data not modeled** — only the authentication subscription (K/OPc/AMF/SQN);
  NSSAI/DNN/QoS come with session management.
- **Re-provision resets SQN** only if you delete the DB; normal restarts preserve it.
