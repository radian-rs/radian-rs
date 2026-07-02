# UDR Relocation over Nudr — Implementation Notes

> Built 2026-07-02 on branch `feat/udr-nudr-store`. Step 1 (UDR half) of the DB
> design study ([24](24-db-subscriber-nf.md)): the subscriber store moves behind
> `nf-udr`, the SQN leaves the encrypted credential blob, and provisioned
> subscription data gets its document-shaped tables.

Since [10](10-subscriber-db.md) the subscriber store was UDM-local ("relocating it
behind `nf-udr` is a later slice"). This is that slice. The UDM is now a stateless
Nudm front-end over the UDR; `nf-udr` owns the redb store; and the store layout is
the document-shaped partitioning from doc 24, ready for a mechanical move to
Postgres JSONB (or a document DB) when scale demands it.

## What was built

- **`subscriber-db` schema v2** — data partitioned by class (doc 24 §model):
  - `credentials`: AEAD(K ‖ OPc ‖ AMF) under the injected KEK — the cold ARPF
    partition. **The SQN is no longer in this blob**, so the per-auth hot path
    stops re-encrypting the long-term keys.
  - `auth_state`: plaintext 6-byte SQN (not secret), atomic post-increment in a
    redb write txn. `next_sqn` still refuses subscribers whose credentials don't
    decrypt under our KEK (wrong-KEK ⇒ store unusable, as before).
  - `am_data` / `sm_data` / `smf_selection`: TS 29.505-shaped **JSON documents**
    keyed `(SUPI, serving PLMN)`, behind the new `ProvisionedDataStore` trait
    (`DataSet::{Am, Sm, SmfSelection}`). Same layout in `InMemoryStore`.
- **`sbi_core::nudr`** — Nudr_DataRepository (TS 29.504/29.505), trimmed:
  `GET`/`PUT` on `/{ueId}/{servingPlmnId}/provisioned-data/{am-data,sm-data,
  smf-selection-subscription-data}`, plus `POST …/authentication-data/generate-av`.
  `UdrClient` for the front-ends (404 ⇒ `Ok(None)`).
- **Deviation — the ARPF stays with the store**: TS 29.505's
  `authentication-subscription` resource would put **K on the (cleartext h2c)
  wire** to the UDM. Instead the UDR co-hosts the ARPF compute: `generate-av`
  advances the SQN and derives the vector next to the credentials; only
  RAND/AUTN/XRES*/K_AUSF ever leave. Documented in the module; this seam is where
  TLS + HSM plug in later.
- **`nf-udr`** — opens the persistent `RedbStore` (`RADIAN_UDR_DB`,
  `RADIAN_UDR_MASTER_KEY`), owns the env-gated demo provisioning
  (`RADIAN_UDR_PROVISION_DEMO=1`, TS 35.208 key + demo AM/SM documents for PLMN
  99970), serves the Nudr router on :8005, registers with the NRF (`UDR`,
  `nudr-dr`) via `register_and_maintain` ([25](25-nrf-heartbeat-expiry.md)).
- **`nf-udm`** — holds **no state and no KEK** anymore: a `UdrClient` front
  (`RADIAN_UDM_UDR`, default `http://127.0.0.1:8005`) serving the unchanged Nudm
  surface, now also NRF-registered (`UDM`, `nudm-ueau`). The AUSF and AMF needed
  **zero changes**.
- **BDD** — `start_core` launches `nf-udr` (with the store envs, fresh
  `/tmp/<tag>_udr.redb` per run) before the stateless `nf-udm`.

## Verification

- `cargo test --workspace --exclude bdd` — green. New/updated tests:
  - `subscriber-db`: SQN-split semantics preserved (`redb_persists_across_reopen`,
    `redb_wrong_kek_cannot_read` — wrong KEK still can't advance SQNs;
    `redb_key_is_not_plaintext_on_disk` now exercises an SQN write too);
    provisioned-doc roundtrips per data set / per PLMN, persisting across reopen.
  - `sbi-core::nudr` (real h2c): `generate_av_advances_sqn_and_hides_k` — two AVs
    differ (SQN advanced), the response JSON cannot contain K; unknown SUPI ⇒
    `None`. `provisioned_data_roundtrip_over_h2c`.
  - The 5G-AKA and full-registration tests (`nausf`, `nf-amf`) now spin the full
    **UDR → UDM → AUSF** chain over h2c and still pass.
- **BDD, both features green** (`cargo test -p bdd`, with `FREE_RAN_UE_BIN`):
  the `@sim` live-UE e2e registers (5G-AKA now AMF → AUSF → UDM → **UDR**),
  establishes a PDU session, and pings the DN — 4 scenarios / 21 steps passed,
  teardown clean.

## Known limitations / next steps

- **No migration from v1 stores** — pre-split `.redb` files (single `subscribers`
  table) read as empty; dev-only data, re-provision (BDD always starts fresh).
- **Nobody reads the AM/SM documents yet** — the SMF still uses request-supplied
  DNN and a hardcoded IP pool; wiring session management to
  `sm-data`/`smf-selection` is the natural next slice.
- **AUSF → UDM target still hardcoded** — UDM and UDR now register with the NRF,
  so switching the AUSF (and UDM → UDR) to NRF discovery is unblocked.
- **KEK from env** — the HSM/KMS seam (`ArpfKeyStore`) is unchanged and waiting.
- **PCF** — still a scaffold; policy data would be the fourth document family.
