# Subscriber provisioning CLI: `radian-dbctl` (design/137 G23)

> Built 2026-08-09 on branch `free5gc`. Closes **G23** from
> [137](137-free5gc-422-gap-survey.md) §8 (Moderate/ops — *the sharpest
> operational gap: no way to provision a subscriber*), taking the re-scoped
> shape from [138](138-open5gs-gap-survey.md)'s **G40**.

## The gap

A subscriber could only enter the UDR store two ways: `RADIAN_UDR_PROVISION_DEMO=1`
(the one hard-coded TS 35.208 test subscriber) or an in-process `RedbStore::provision_hex`
call — i.e. recompiling. There was **no operator provisioning path** at all.

## Why a CLI, not a Nudr API

The survey's G23 named "UDR `authentication-subscription` CRUD (+ a UI/CLI)". But a
Nudr `authentication-subscription` route **serialises the long-term key K over
HTTP** — exactly what radian's ARPF boundary is built to avoid (K never crosses a
trait or the wire; the UDR co-hosts the ARPF and only derived AVs leave). open5gs's
own `open5gs-dbctl` provisions by **writing the datastore directly**, not through a
Nudr API. [138](138-open5gs-gap-survey.md) G40 recalibrated G23 to that shape: a CLI
over the store keeps K off every wire.

## What this slice does

A new workspace binary **`tools/radian-dbctl`** that opens the UDR's redb store
directly (the same `RADIAN_UDR_DB` path + `RADIAN_UDR_MASTER_KEY` KEK, overridable
with `--db`/`--key`) and provisions subscribers:

- **`add --supi --k --opc [--amf] [--plmn] [--sst] [--sd] [--dnn] [--ambr-up]
  [--ambr-down]`** — provisions the encrypted credentials **plus a working profile**:
  Nudm_SDM `am-data` (subscribed slice + UE-AMBR), `sm-data` (one slice, one DNN,
  IPv4-default/IPv4v6-allowed, a default non-GBR 5QI-9 flow), and
  `smf-selection-data` (the DNN authorized under the slice). That is exactly the
  subset a UE needs to **register and establish a basic PDU session** (PCF policy /
  AM-policy documents are optional — the SMF/AMF fall back to sm-data / the
  subscribed values).
- **`remove --supi`** — deletes the subscriber and all of its data.
- **`list`** — the provisioned SUPIs (new `RedbStore::list_subscribers`, which reads
  only the plaintext SUPI keys — it never touches K, preserving the ARPF boundary).

K/OPc/AMF go straight into the AES-256-GCM-at-rest credential partition under the
injected KEK — never over any wire.

## Decisions

- **D1 — direct-to-store, ARPF-preserving.** The CLI is the deliberate alternative
  to a Nudr credential API; K stays in-process → encrypted store. (§Why above.)
- **D2 — a stable KEK is mandatory for writes.** `add`/`remove` refuse without
  `--key`/`RADIAN_UDR_MASTER_KEY`: an ephemeral or wrong KEK would write credentials
  the UDR can never decrypt. `list` needs no key (SUPI keys are plaintext).
- **D3 — `add` provisions a usable profile, not just credentials.** Bare credentials
  authenticate but can't get a PDU session; the default AM/SM/SmfSelection documents
  make the subscriber immediately registrable + session-capable, parameterised by a
  few flags (PLMN/slice/DNN/AMBR).
- **D4 — offline provisioning.** redb takes an exclusive file lock, so `radian-dbctl`
  runs while the UDR is **stopped** (documented in `--help` / the module docs). This
  is the redb analogue of open5gs's live-MongoDB dbctl; a concurrent-access story is
  a follow-up.

## Tests

- `tools/radian-dbctl/tests/cli.rs` (runs the built binary):
  - `add_list_remove_round_trips_through_the_store` — provision via the CLI, then a
    `RedbStore` opened with the **same KEK** reads it back (credentials decrypt,
    am/sm/smf-selection present); a **wrong KEK cannot decrypt** (encryption-at-rest
    holds through the CLI); `list` shows the SUPI; `remove` drops the subscriber and
    its profile.
  - `add_requires_a_key` — a write without a key is refused with a clear message.
- `subscriber-db` 13 green (incl. `list_subscribers`); full workspace builds; clippy
  clean.

## Follow-ups

- **A live-registration BDD** using a CLI-provisioned subscriber (the store round-trip
  + the demo-matching profile shape already prove usability; an `@sim`/scripted
  scenario would prove it end to end).
- **A thin admin UI** over the same store operations (G23's optional half).
- **Concurrent provisioning** (provision without stopping the UDR) — needs either a
  UDR-hosted admin endpoint that keeps K in-process, or a store that allows a second
  writer.
- **Richer profile flags** (multiple DNNs/slices, GBR flows, static UE IP once
  [G6](137-free5gc-422-gap-survey.md)'s static pools land).
