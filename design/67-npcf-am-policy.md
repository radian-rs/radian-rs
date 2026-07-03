# Npcf_AMPolicyControl — Access-and-Mobility Policy at Registration

> Built 2026-07-03 on branch `feat/npcf-am-policy`. The PCF was **SM-only**
> (Npcf_SMPolicyControl, design/47–48): it drove per-session QoS but had no say
> over mobility/access. This adds **Npcf_AMPolicyControl** (TS 29.507): the AMF
> opens an **AM policy association** at registration and the PCF returns AM policy
> data — an **RFSP** index and a policy **UE-AMBR** the AMF enforces at the gNB.
> The association is deleted at deregistration.

## What was built

### `sbi_core::npcf_am` (new module) + PCF

- DTOs: `PolicyAssociationRequest` (SUPI + serving PLMN, from the AMF),
  `PolicyAssociation` (the PCF's answer: `rfsp`, `ueAmbr`, triggers), and `Ambr`
  (TS 29.571 bitrate strings).
- `AmPolicyConfig` engine (`demo()` = RFSP 3 + a 500 Mbps / 1 Gbps UE-AMBR,
  deliberately tighter than the subscribed 1/2 Gbps so the override is
  observable), `AmPcfState` (in-memory associations), and a `router`
  (create → `201` + `Location`; delete → `204`).
- `AmPolicyClient` for the AMF.
- **`nf-pcf`** serves it alongside the SM router
  (`npcf::router(sm).merge(npcf_am::router(am))`) and advertises the
  `npcf-am-policy-control` service in its NRF profile.

### AMF (`nf-amf`)

- At **Security Mode Complete** (part of registration, alongside the Nudm_SDM
  am-data fetch), `create_am_policy` discovers the PCF and opens the association.
  The PCF's **UE-AMBR overrides** the subscribed am-data UE-AMBR the AMF sends to
  the gNB in the N2 PDU Session Resource Setup; the RFSP is logged. Best-effort —
  no PCF ⇒ the subscribed policy stands.
- The association `(pcf_base, assoc_id)` is stored on the UE context and
  **deleted** on every teardown path (UE-initiated dereg, network dereg,
  T3522-exhaust abort, and implicit-deregistration eviction from design/66).

## Boundaries / notes

- **Local policy source** — the AM policy comes from the PCF's local
  `AmPolicyConfig`. Per-subscriber **UDR am-policy-data** sourcing (mirroring the
  SM side's Nudr wiring, design/48) is the natural follow-up.
- **Applied output = UE-AMBR (+ RFSP logged)** — the AM policy's other outputs
  (service-area restrictions → the Registration Accept's Service Area List IE,
  RFSP → the gNB over N2) aren't wired: we have no InitialContextSetup for RFSP,
  and the Service Area List IE is a heavier hand-encode. UE-AMBR is the faithful,
  wire-visible effect that fits the existing N2 setup.
- **No AM policy Update / UpdateNotify** — the PCF-initiated update on a policy
  trigger (Npcf_AMPolicyControl_UpdateNotify) isn't modelled; only Create/Delete.

## Verification

- `cargo test --workspace --exclude bdd` — green (**146** tests). New:
  - npcf_am `am_policy_association_lifecycle` (create → policy with RFSP + UE-AMBR;
    delete; unknown delete → 404).
  - nf-amf `am_policy_association_created_at_registration` — `create_am_policy`
    discovers the PCF, opens the association, and returns the policy whose UE-AMBR
    (500 Mbps / 1 Gbps) is the override the AMF applies; the delete closes it.
- **BDD 2 features / 5 scenarios / 25 steps green** — the live @sim registration
  now creates the AM policy association at the **real** `nf-pcf` and applies the
  UE-AMBR override to the gNB, and the UE still registers + pings (the ping is far
  under the policed rate).
- **Live (real binaries)** — the `nf-pcf` binary serves
  `POST /npcf-am-policy-control/v1/policies` → `201` + `Location`, body
  `{rfsp: 3, ueAmbr: {uplink: "500 Mbps", downlink: "1 Gbps"}}`, logging the
  created association.

## Known limitations / next steps

- **UDR am-policy-data sourcing** — per-subscriber AM policy provisioned in the
  UDR (a new `DataSet` + Nudr route), like SM policy-data.
- **Npcf_AMPolicyControl_UpdateNotify** — PCF-initiated AM policy changes on a
  trigger (e.g. location / RAT change).
- **Service Area List + RFSP application** — enforce service-area restrictions in
  the Registration Accept and relay RFSP to the RAN.
