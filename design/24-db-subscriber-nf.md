# DB Design — Subscriber Data (UDR) and NF Profiles (NRF)

> Written 2026-07-02 on branch `docs/db-design`. Design study only — no code changes.
> Evaluates RDB vs NoSQL (and the options that framing misses) for the two
> persistent data classes in the core, and sets a staged migration path.

## Where the code stands today

- **Subscriber data** = only the authentication subscription (K/OPc/AMF/SQN), in
  `crates/subscriber-db` behind the `SubscriberDb` / `ArpfKeyStore` traits, with an
  `InMemoryStore` (tests) and a `RedbStore` (embedded, ACID, AES-256-GCM at rest,
  KEK injected — see [10](10-subscriber-db.md), [13](13-encryption-at-rest.md)).
  Profile data (subscribed S-NSSAIs, UE-AMBR, per-DNN QoS) is **not modeled
  anywhere**; `nf-udr` is a health-router scaffold.
- **NF profiles** live in the NRF's `Arc<Mutex<HashMap<String, NfProfile>>>`
  (`sbi_core::nnrf::NrfStore`) — in-memory, no persistence, and **no heartbeat
  expiry**: a dead NF stays discoverable forever ([04](04-sbi-spine-nrf.md)).

## The core design decision: these are opposite workloads

| | Subscriber (UDR) | NF profiles (NRF) |
|---|---|---|
| Cardinality | thousands → millions | tens → hundreds |
| Lifetime | durable, provisioned once, lives for years | soft state, refreshed by heartbeat every few seconds |
| Loss on restart | catastrophic — subscribers vanish | harmless — NFs re-register |
| Consistency | strong (SQN must never repeat) | eventual is fine; staleness bounded by TTL |
| Query shape | point lookup by SUPI (+ serving PLMN) | filtered scans: nf-type, S-NSSAI, DNN, service |

This mirrors 3GPP's own data-storage architecture (TS 23.501 §4.2.5): the **UDR**
holds structured subscription data; the **UDSF** holds unstructured/ephemeral NF
state. NRF registry state is firmly in the second category — persisting it buys
nothing and costs a durable write per heartbeat. **So: no single DB for both.**

## Subscriber data model

Partition by data class — each has a different security and write profile:

| # | Class | Examples | Profile |
|---|---|---|---|
| 1 | ARPF credentials | K, OPc, auth method | cold; encrypted under KEK or replaced by an HSM key reference |
| 2 | Auth state | SQN | hot; atomic read-modify-write per authentication |
| 3 | Provisioned data | AM data (subscribed S-NSSAIs, UE-AMBR), SM data (per-DNN QoS, session-AMBR, SSC modes), SMF selection | read-mostly documents; the surface grows every 3GPP release |
| 4 | Dynamic registration | serving AMF, SMF registrations (Nudr `*-3gpp-access`) | write-heavy, largely rebuildable |

Two structural rules:

1. **Split SQN (2) out of the encrypted credential blob (1).** Today both live in
   one 40-byte AEAD `Record`, so every authentication re-encrypts the long-term
   credentials. Separated, the ARPF partition becomes genuinely cold data and the
   hot path touches only a plaintext-safe counter.
2. **Store classes 3–4 as JSON documents keyed by the Nudr resource path**
   (TS 29.505: `{supi}/{servingPlmnId}/provisioned-data/am-data`, `…/sm-data`, …).
   The Nudr API is itself a JSON resource tree, so document storage makes the UDR
   handler a thin GET/PUT mapping instead of an ORM — and makes any later backend
   swap nearly mechanical.

In redb this is just more tables with `serde_json` values:

```text
subscribers   : supi → AEAD(K ‖ OPc ‖ auth_method)   // ARPF partition (cold)
auth_state    : supi → SQN                            // hot, plaintext OK
am_data       : (supi, plmn) → JSON                   // TS 29.505 documents
sm_data       : (supi, plmn, dnn?) → JSON
smf_sel_data  : (supi, plmn) → JSON
amf_3gpp_reg  : supi → JSON                           // dynamic
```

The same shape ports directly to PostgreSQL later:

```sql
CREATE TABLE subscriber        (supi TEXT PRIMARY KEY, plmn TEXT, created_at TIMESTAMPTZ);
CREATE TABLE auth_subscription (supi TEXT PRIMARY KEY REFERENCES subscriber,
                                enc_key BYTEA, enc_opc BYTEA,   -- or hsm_key_ref TEXT
                                auth_method TEXT, sqn BIGINT);  -- UPDATE … RETURNING = atomic next_sqn
CREATE TABLE provisioned_data  (supi TEXT REFERENCES subscriber, serving_plmn TEXT,
                                data_type TEXT, payload JSONB,
                                PRIMARY KEY (supi, serving_plmn, data_type));
```

Architecturally the store relocates behind `nf-udr` (already flagged in
[10](10-subscriber-db.md)): UDM/AUSF/PCF consume it over Nudr, and the backend
choice stays invisible to every other NF.

## RDB vs NoSQL

### RDB (PostgreSQL / MySQL / SQLite)

**Pros**

- ACID transactions: atomic SQN increment; provisioning subscriber + credentials
  + profile in one transaction, so no half-provisioned state is ever observable.
- Constraints and foreign keys catch provisioning bugs (orphan auth records,
  duplicate SUPIs) at the database rather than in code.
- Ad-hoc SQL for operator tooling: "all subscribers on slice sst=1/sd=010203",
  counts, audits, billing extracts.
- The most mature ops story available — backups, PITR, replication, monitoring.
- Postgres **JSONB** dissolves the classic schema-mismatch objection: documents
  *inside* the relational engine, indexable with GIN.

**Cons**

- The 3GPP data model is deeply nested JSON with a large optional-field surface
  that changes every release. Fully normalized it becomes dozens of join tables
  and a migration per release upgrade. (JSONB is the escape hatch — but then it
  is partly a document store anyway.)
- Scales up more naturally than out; multi-region active-active is genuinely hard.
- A server to deploy, secure, and back up — real cost for a core that today ships
  as self-contained binaries exercised in netns BDD runs.

### NoSQL

**Document (MongoDB)** — the closest NoSQL fit:

- Pros: TS 29.505 / 29.510 resources map 1:1 to documents; schema-flexible across
  3GPP releases; single-document atomic ops (`findAndModify`) cover SQN; strong
  precedent — **Open5GS and free5GC both keep subscriber data in MongoDB**, so
  provisioning tooling and examples exist.
- Cons: cross-document transactions are weaker/costlier; heavier ops footprint
  than Postgres for most teams; SSPL licensing; relational-style reporting is
  clumsier.

**Wide-column (Cassandra / ScyllaDB)** — the carrier-grade UDR answer:

- Pros: linear horizontal scale, multi-datacenter active-active, tunable
  consistency. This is what production telco UDRs actually run on.
- Cons: eventual consistency makes SQN dangerous (needs lightweight
  transactions, which are expensive); serious operational weight; overkill below
  millions of subscribers.

**Key-value / in-memory (Redis / Valkey)**:

- Pros: native TTL expiry and pub/sub — an almost exact semantic match for NRF
  heartbeats and NFStatusSubscribe notifications; ideal for session/UE-context
  state (the UDSF role).
- Cons: not a durable system of record; wrong tool for subscription data.

## Options the RDB-vs-NoSQL framing misses

- **Embedded stores (redb — current; SQLite; RocksDB/sled).** For this project's
  stage, embedded beats both server-DB camps: zero ops, in-process, ACID (redb,
  SQLite), pure Rust in redb's case, and perfect for BDD suites that create and
  destroy namespaces per scenario. If SQL queryability is ever wanted while
  staying embedded, **SQLite is the halfway house** — but redb is proven here and
  point-lookups by SUPI don't need SQL yet.
- **etcd / consul for the NRF**: lease-based TTL + watch map 1:1 onto NF
  heartbeats and status subscriptions. Only worth it in a Kubernetes-shaped
  deployment where a cluster already exists.
- **HSM / KMS / Vault** — orthogonal to the DB choice but the most important
  security decision: in production, K should never sit in the general DB even
  encrypted. The `ArpfKeyStore` trait already isolates this; keep that seam
  intact whatever backend changes.

## NF profile (NRF) design

**No database.** Keep the in-memory `NrfStore` and add what is actually missing:

- Record `last_heartbeat` per profile; evict (or mark `SUSPENDED`) when a profile
  exceeds its heartbeat interval — today's genuine correctness gap.
- Return the `heartBeatTimer` in the registration response (TS 29.510) so NFs
  know the contract.
- Discovery filters beyond `target-nf-type` (S-NSSAI, DNN, service-names) are a
  query-logic change, not a storage change.
- If the NRF ever becomes redundant/multi-instance, back it with Redis/Valkey
  (TTL + pub/sub), not a durable DB.

## Staged recommendation

1. **Now** — stay on redb. Extend it with the document-shaped tables above; move
   the store behind `nf-udr` over Nudr; split SQN out of the encrypted blob. Add
   heartbeat-TTL expiry to the in-memory NRF.
2. **Multi-instance UDR / operator provisioning tooling needed** — PostgreSQL +
   JSONB with the same document layout (relational spine for identity, SQN, and
   provisioning integrity; JSONB for the 3GPP payloads). Choose MongoDB instead
   only if ecosystem alignment with Open5GS/free5GC-style tooling outweighs
   Postgres's transactional and operational advantages.
3. **NRF stays DB-less** until redundancy is required; then Redis/Valkey.
4. **Carrier scale** (millions of subscribers, multi-site active-active) — only
   then does Cassandra/ScyllaDB enter the conversation.

Because everything sits behind the `SubscriberStore` traits and (after step 1)
the Nudr SBI boundary, each later move is a backend swap invisible to the other
NFs — that seam is the real design decision, and it is already in place.
