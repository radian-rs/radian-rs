# Encryption-at-Rest for Credentials (behind ArpfKeyStore)

> Built 2026-06-29 on branch `feat/udm-encryption-at-rest`. Closes the last cheap item from the PR #11 review — K/OPc are no longer plaintext on disk.

The persistent subscriber store wrote K/OPc in the clear. This slice **AEAD-encrypts
records at rest** with a key-encryption key (KEK) injected at startup — the seam where
an HSM / KMS plugs in. The `ArpfKeyStore` boundary is unchanged: K still never crosses
the trait, and now never sits on disk in plaintext either.

## What was built

- **`subscriber-db` (`RedbStore`)** — each record is encrypted with **AES-256-GCM**:
  `nonce(12) || ciphertext+tag`, with a fresh random nonce per write and the **SUPI as
  AAD** (so a blob can't be moved to another subscriber). `RedbStore::open(path, kek)`
  takes the 32-byte KEK; the KEK is never persisted. Reads/`next_sqn` decrypt, mutate,
  re-encrypt (new nonce). The whole record — including SQN — is integrity-protected.
- **`nf-udm`** — sources the KEK from `RADIAN_UDM_MASTER_KEY` (64 hex chars); if
  unset, generates an **ephemeral** key with a loud warning (persisted records become
  unreadable after restart — so there is never plaintext-at-rest, even in dev).
- Helpers `subscriber_db::parse_kek_hex` / `random_kek`.

## The HSM seam

KEK injection is the boundary. Today the KEK lives in process memory (from env); the
next hardening step is sourcing it from an **HSM / KMS** (or having the HSM hold K
itself, so it never enters process memory). The interface doesn't change — only where
`master_key()` gets its bytes. SUCI deconcealment's home-network private key belongs
here too.

## Verification

- `cargo test` — green (30 tests workspace-wide). New:
  - `redb_wrong_kek_cannot_read` — a store opened with a different KEK can't decrypt
    (GCM tag fails) → `exists` false, `next_sqn`/`generate_he_av` `None`.
  - `redb_key_is_not_plaintext_on_disk` — after provisioning + an SQN write, the raw
    file contains **neither K nor OPc** as a byte substring.
  - `redb_persists_across_reopen` still passes (same KEK → records survive).

## Known limitations / next steps

- **KEK in process memory** — from env, not yet an HSM. A real HSM (K never leaving
  the HSM, or KEK held in the HSM) is the further step; the seam is in place.
- **No key rotation** — a KEK change can't re-encrypt existing records yet.
- **In-memory store is plaintext in RAM** — unavoidable (K must be in RAM to compute
  vectors); at-rest encryption applies to the persistent backend only.
- **Ephemeral-key default** trades dev convenience (no config) for losing persistence
  across restarts; set `RADIAN_UDM_MASTER_KEY` for a stable store.
