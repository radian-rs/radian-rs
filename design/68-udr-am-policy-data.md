# UDR am-policy-data — Per-Subscriber AM Policy

> Built 2026-07-03 on branch `feat/udr-am-policy-data`. Design [67](67-npcf-am-policy.md)
> served AM policy from the PCF's **local config** (one policy for everyone). This
> makes the PCF source it **per subscriber** from the UDR (Nudr am-policy-data,
> TS 29.519), mirroring the SM-policy-data wiring ([48](48-pcf-policy-from-udr.md)):
> an operator provisions RFSP / UE-AMBR per subscriber, and the AMF's AM policy
> association reflects it.

## What was built

The AM analogue of the SM policy-data path, across the same four layers:

### Store (`subscriber-db`)

A new `DataSet::AmPolicy` (redb table `am_policy_data`, keyed `(SUPI, "")` — not
serving-PLMN-scoped), swept by `remove_subscriber` and cleared on withdrawal like
the other data sets.

### `nudr` (Nudr_DataRepository)

`GET|PUT /nudr-dr/v2/policy-data/ues/{ueId}/am-data` (the TS 29.519 am-data
resource, keyed by ueId) + `UdrClient::{get,put}_am_policy_data`.

### PCF (`sbi_core::npcf_am`)

`AmPcfState::with_udr(udr)` + `decide_for(supi)`: fetch the subscriber's UDR
am-policy-data and deserialize it straight into `AmPolicyConfig` (the document
*is* a serialized config — `{rfsp, ueAmbr}`), falling back to the local config
when a subscriber has none provisioned (or the UDR is unreachable / the doc is
malformed). Re-read on every association create.

### Provisioning (`nf-pcf` / `nf-udr`)

- `nf-pcf` passes its existing UDR client to `AmPcfState::with_udr` (the same
  client the SM side already uses).
- `nf-udr` provisions the demo subscriber's am-policy-data (`rfsp: 5`,
  UE-AMBR `300 Mbps / 600 Mbps`) — distinct from the local default so the source
  is observable.

## Boundaries / notes

- **Read-through, no caching** — the PCF re-reads the UDR on every association
  create (an `UpdateNotify` would let the PCF push changes; not modelled, from
  design/67).
- **am-data resource, keyed by ueId** — not serving-PLMN-scoped, matching the SM
  policy-data shape; a fuller TS 29.519 am-policy-data model (per-slice / per-area)
  is out of scope.
- The applied effect is unchanged from design/67 (the UE-AMBR override at the gNB
  + logged RFSP); this slice only changes *where the policy comes from*.

## Verification

- `cargo test --workspace --exclude bdd` — green (**147** tests). New:
  - npcf_am `am_policy_sourced_from_udr` — a provisioned subscriber gets the UDR
    policy (RFSP 7 / 100-200 Mbps), an unprovisioned one falls back to the local
    demo (RFSP 3). Drives a real in-process UDR + PCF over h2c.
- **BDD 2 features / 5 scenarios / 25 steps green** — the live @sim registration
  now sources the demo subscriber's AM policy from the UDR and still pings.
- **Live (real binaries)** — NRF + demo-provisioned UDR + PCF: the AM policy
  create for the **demo** subscriber returns the UDR policy
  (`{rfsp: 5, ueAmbr: {300 Mbps / 600 Mbps}}`); for an **unprovisioned** subscriber
  it returns the local fallback (`{rfsp: 3, ueAmbr: {500 Mbps / 1 Gbps}}`).

## Known limitations / next steps

- **Npcf_AMPolicyControl_UpdateNotify** — PCF-initiated AM policy changes on a
  trigger (the AM analogue of the SM policy Update path).
- **Richer am-policy-data** (service-area restrictions, per-slice policy) + wiring
  those outputs (Service Area List IE, RFSP to the RAN) from design/67's list.
