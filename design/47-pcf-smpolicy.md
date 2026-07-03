# A Real PCF — Npcf_SMPolicyControl — Implementation Notes

> Built 2026-07-02 on branch `feat/pcf-smpolicy`. Replaces the 15-line PCF
> health-router scaffold with a real **Policy Control Function** serving
> **Npcf_SMPolicyControl** (TS 29.512). The SMF now asks the PCF for the SM
> policy at PDU-session establishment, making the PCF the authoritative source of
> QoS — the "real GBR flows come from the PCF" that [45](45-per-flow-qos.md)
> deferred to the sm-data stand-in.

## What was built

- **`sbi_core::npcf`** — the Npcf_SMPolicyControl service:
  - **Shared policy shapes** `QosFlowPolicy` / `GbrPolicy` / `SessionAmbrPolicy`
    — the authorized-flow + session-AMBR types, now used by **both** the PCF's
    decision and the SMF's CreateSMContext response (the SMF's private
    `QosFlowDto` / `SessionAmbrDto` / `GbrDto` are gone; it imports these). Same
    serde shape as before, so the wire toward the AMF is byte-identical.
  - **DTOs** `SmPolicyContextData` (what the SMF sends: supi, PDU session id, DNN,
    S-NSSAI) and `SmPolicyDecision` (session AMBR + QoS flows).
  - **Policy engine** `PolicyConfig` — a per-DNN decision map with a network-wide
    default (`demo()`: 1/2 Gbps AMBR + a default non-GBR flow 5QI 9 + a GBR flow
    5QI 1, GFBR 100 / MFBR 200 Mbps), plus `with_dnn` for per-DNN overrides.
  - **Router** — `POST /npcf-smpolicycontrol/v1/sm-policies` → 201 + the decision,
    the association id in the `Location` header; `POST .../{id}/delete` → 204. An
    in-memory association store (`PcfState`, id → context) for delete/auditing.
  - **`PcfClient`** — the SMF-side h2c client: `create_sm_policy` (returns the id
    parsed from `Location` + the decision) and `delete_sm_policy`.
- **`nf-pcf`** — the scaffold is now a real NF: builds `PcfState` from the demo
  policy, serves the Npcf router on `:8006`, and **registers with the NRF**
  (nf-type `PCF`, service `npcf-smpolicycontrol`) so the SMF can discover it.
- **SMF integration** (`nf-smf`): after the CreateSMContext subscription
  authorization, the SMF discovers a PCF via the NRF and calls
  `Npcf_SMPolicyControl_Create`. **When a PCF answers, its decision drives the
  session** (AMBR + QoS flows); the `(pcf_base, policy_id)` is stored on the
  `SmContext` and the association is **deleted at release**
  (`Npcf_SMPolicyControl_Delete`, best-effort, off the signaling path). With **no
  PCF registered** (or on any PCF error) the SMF **falls back to the sm-data
  policy** fetched over Nudm_SDM — behaviour is unchanged from [45](45-per-flow-qos.md).
- **BDD topology**: `nf-pcf` joins the e2e `start_core` (pointed at the NRF via
  `RADIAN_PCF_NRF`); teardown already sweeps all `nf-*` by path prefix.

## Why PCF-authoritative, with an sm-data fallback

TS 23.503 makes the PCF the policy decision point: the SMF is a policy
*enforcement* point that requests an SM policy at establishment. Modelling the
PCF as authoritative (when present) is the correct shape, and it's where dynamic
PCC rules / operator policy will live. But the core must still bring a PDU session
up when no PCF is deployed — so the SMF keeps the sm-data path as a fallback
rather than hard-failing. The demo PCF policy is deliberately identical to the
sm-data demo (same flows + AMBR), so **enabling the PCF changes the policy
*source*, not the resulting QoS** — the datapath is unchanged and the difference
is observable only in the SBI signalling (the SM policy association).

## Trust / scope (deliberate limits)

- **Local policy only.** The demo `PolicyConfig` is hard-coded per-DNN. A real PCF
  reads policy from the UDR (`Nudr` policy-data) and applies PCC rules /
  subscriber policy — a later slice; `with_dnn` is the config seam.
- **No update/notify.** Only Create + Delete of the SM policy association are
  modelled; `Npcf_SMPolicyControl_Update` and PCF-initiated policy updates
  (`SmPolicyUpdateNotification`) are not.
- **Unauthenticated SBI**, same posture as the rest of the core — the PCF is not
  yet behind `oauth::protect` (design [46](46-sbi-oauth.md)); wiring it in is
  mechanical follow-up.

## Verification

- `cargo test --workspace --exclude bdd` — green (11 suites, 95 tests). New:
  - `npcf::create_then_delete_sm_policy_over_h2c` — PcfClient ↔ router round trip:
    create returns an id + the demo decision (AMBR + 2 flows incl. GBR), the
    association is stored, delete removes it.
  - `npcf::per_dnn_override_wins_over_default` — `with_dnn` applies to its DNN;
    other DNNs get the default.
  - `pdu_session::pcf_drives_sm_policy_and_release_deletes_it` — the decisive one:
    with a PCF registered, CreateSMContext creates **one** PCF association
    (`association_count() == 1`) and the response carries the PCF's AMBR + GBR
    flow; release deletes it (`→ 0`). The association count — not the flow values,
    which match sm-data — is what proves the PCF path was taken, not the fallback.
  - `pdu_session::pdu_session_create_then_update_drives_n4` (existing) now covers
    the **fallback** path (no PCF registered) after the DTO unification: still
    returns the sm-data flows + AMBR.
- **BDD, 5 scenarios / 25 steps green** with `nf-pcf` in the topology — including
  the live **`@sim`** e2e (free-ran-ue registration + PDU session + ping
  round-trip). The PCF-in-topology run is unaffected because the PCF's demo QoS
  equals sm-data's; the SMF↔PCF create/delete is proven separately (and
  deterministically) by the integration test above, since the BDD harness
  discards NF stdio.

## Known limitations / next steps

- **Policy from the UDR** (`Nudr` policy-data) + PCC rules — the real policy source.
- **Npcf_SMPolicyControl_Update** + PCF-initiated notifications (QoS changes
  mid-session).
- **Npcf_AMPolicyControl** (access/mobility policy toward the AMF) and
  **UE policy** — the PCF's other services.
- **SBI auth** — put the PCF behind `oauth::protect` and give the SMF a
  PCF-audience token.
