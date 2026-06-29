# Credential Store Hardening (PR #11 security review)

> Built 2026-06-29 on branch `feat/subscriber-db-hardening`. Addresses the commit security review on the subscriber store.

A push/commit security review of PR #11 flagged three issues on the new subscriber
store. This slice fixes the two cheap ones and documents the deferred one.

## Findings & fixes

| Finding | Fix |
|---|---|
| **Hard-coded demo subscriber** (nf-udm) — a known-key account was auto-provisioned, i.e. a backdoor in any deployment | The demo subscriber (a **public** TS 35.208 test key) is now provisioned **only** when `RADIANT_UDM_PROVISION_DEMO=1` — never by default. The DB path is also configurable (`RADIANT_UDM_DB`). A production build ships **no** known-key account. |
| **Insecure file permissions** on the credential store | The redb file is created **mode 0600** (owner-only) at creation time via `OpenOptions.mode(0o600)` + `redb::Builder::create_file` — no chmod-after-create **TOCTOU** window. |
| **Plaintext K/OPc at rest** | **Acknowledged, deferred.** Documented at the persistence site; the real fix is encryption-at-rest / an HSM **behind `ArpfKeyStore`** (the key never on disk in the clear). The seam already exists. |

## Verification

- `cargo test` — green (28 tests workspace-wide). New:
  - `redb_unknown_subscriber_is_none` — a fresh store returns `None` for an
    unprovisioned subscriber (so with the demo OFF, the UDM returns **404** — no
    backdoor account).
  - `redb_credential_file_is_owner_only` — the persisted file is mode **0600**.
- Behavior confirmed: with `RADIANT_UDM_PROVISION_DEMO` unset, the UDM logs
  "demo subscriber disabled" and an unprovisioned SUPI 404s; with it set, the demo
  subscriber is provisioned and authenticates.

> Note: an HTTP smoke of two `nf-udm` instances was unreliable in the sandbox
> (backgrounded long-running servers are torn down at command teardown); the unit
> tests above are the authoritative check, and an earlier `stat` directly showed `600`.

## Still outstanding (deferred, tracked)

- **Encryption-at-rest / HSM** for K/OPc behind `ArpfKeyStore` — the headline remaining
  credential-security item (and where SUCI deconcealment's home-network key will live).
- **SBI / N4 network hardening** — TLS + OAuth2 (TS 33.501) for NRF/UDM/AUSF; IPsec /
  bind-to-address for PFCP & GTP-U. Same deferred posture as the earlier reviews.
