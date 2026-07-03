# SQN Resynchronisation (AUTS)

> Built 2026-07-03 on branch `feat/sqn-resync`. Registration-lifecycle audit
> slice 2. Authentication Failure was previously **unhandled** — a UE whose USIM
> sequence number had drifted (it authenticated elsewhere, or the network's SQN
> fell behind) could never register, which is why the BDD UE fixture pins
> `sequenceNumber: 0`. This adds the **synchronisation-failure** path (TS 33.102
> §6.3): the UE returns an **AUTS**, and the network adopts the UE's SQN and
> re-challenges.

## What was built

The full AMF → AUSF → UDM → UDR/ARPF resync chain, mirroring the AV path:

### Crypto (`aka`)

- **`compute_auts(sub, rand, sqn_ms)`** — the USIM side:
  `AUTS = (SQNms ⊕ AK*) ‖ MAC-S`, with `AK* = f5*(RAND)` and
  `MAC-S = f1*(SQNms ‖ RAND ‖ AMF*)` where **AMF\* = 0x0000** (the resync AMF).
- **`sqn_ms_from_auts(sub, rand, auts)`** — the ARPF side: recompute `AK*`,
  recover `SQNms`, and **verify MAC-S** — `None` on mismatch, so an AUTS that
  isn't from this subscriber's USIM (or is for a different RAND) never moves the
  stored SQN.

### Store (`subscriber-db`)

`ArpfKeyStore::resync_sqn(supi, rand, auts)` verifies the AUTS and, on success,
**adopts the UE's SQN** (the next generated vector advances past it — fresh
again from the UE's viewpoint). Both backends implement it; the redb store
persists the new SQN. K/OPc never leave the impl.

### SBI plumbing

- **`nudr`** — `POST …/authentication-data/resync` (`{rand, auts}` hex):
  `204` adopted, `403` MAC-S mismatch (never moves the SQN), `404` unknown
  subscriber. `UdrClient::resync_av`.
- **`nudm`** — `POST /nudm-ueau/v1/{supi}/auth-events/resync` relays to the UDR
  (`NudmClient::resync`).
- **`nausf`** — the resync rides in the *authenticate* request's
  **`resynchronizationInfo`** (TS 29.509 §6.1), not a separate call: the AUSF
  relays the AUTS to the UDM (SQN adopted) **before** fetching the fresh AV, so
  the new challenge is in sync in one round trip. `AusfClient::authenticate_resync`.

### AMF (`nf-amf` + `auth`)

- nas: `authentication_failure_synch(auts)` / `authentication_failure_info`
  (build/parse the NAS Authentication Failure, cause #21 + AUTS).
- `AmfAuth::resync(pending, supi, auts)` — re-runs Nausf with the AUTS + the
  RAND of the failed challenge (from `pending`) on the same AUSF, returning a
  fresh challenge.
- A new dispatcher arm `on_authentication_failure`: on a synch failure it
  resynchronises **once** (a `resync_attempted` guard on the UE context caps it
  at one per procedure, so a persistent mismatch can't loop) and sends the fresh
  Authentication Request; any other cause — or a second synch failure — aborts
  (drop the context, release it at the gNB).

## Boundaries / notes

- **One resync per procedure** — a second synch failure aborts rather than
  looping (TS 33.501 §6.1.3.2.2 allows at most one).
- **Not driven by free-ran-ue** — its USIM silently adopts the network's SQN
  (no AUTS), so the live sim can't exercise resync; the paths are pinned by unit
  + integration tests and a real-binary endpoint smoke instead.
- The resync AMF field is fixed at `0x0000` (the standard value); AMF separation
  bits aren't used.

## Verification

- `cargo test --workspace --exclude bdd` — green (**132** tests). New:
  - aka `auts_round_trips_and_rejects_tampering` (AUTS verifies + yields SQN;
    tampered AUTS / wrong RAND / wrong K all refused).
  - subscriber-db `resync_adopts_the_ue_sqn_and_rejects_forgeries` (the next
    vector advances past the UE's SQN; a forged AUTS moves nothing; redb persists
    the adopted SQN).
  - nas `authentication_failure_synch_round_trips`.
  - nf-amf `resync_recovers_from_a_synch_failure` — end to end through **real**
    NRF/UDR/UDM/AUSF SBI servers: a UE-side AUTS drives a fresh challenge that
    authenticates and confirms; `repeated_synch_failure_aborts` — a second synch
    failure drops the context and releases it.
- **BDD 2 features / 5 scenarios / 25 steps green** — the SUCI/SQN-0 path is
  unchanged.
- **Live (real binaries)** — NRF/UDR/UDM/AUSF up; a bogus `resynchronizationInfo`
  on the AUSF authenticate is refused **403** (the AUTS reached the ARPF through
  AUSF→UDM→UDR and MAC-S was rejected — the UDR logs "SQN resync refused"); the
  UDM resync endpoint likewise **403**; a resync for an unknown subscriber at the
  UDR is **404**.

## Known limitations / next steps

- **The BDD fixture can drop its SQN pin** now that drift is recoverable (a
  follow-up once the sim is taught to send AUTS, or via a crafted-AUTS scenario).
- **Algorithm negotiation + security-context reuse** (ngKSI) — the next audit
  slice (NEA/NIA are still hardcoded).
- **Periodic/mobility registration** (T3512, TAI list) and the idle-mode arc
  remain from the audit.
