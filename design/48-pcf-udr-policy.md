# PCF Policy from the UDR + Npcf_SMPolicyControl_Update — Implementation Notes

> Built 2026-07-02 on branch `feat/pcf-udr-policy`, continuing the PCF
> ([47](47-pcf-smpolicy.md)). Two things: the PCF now sources its SM policy from
> the **UDR** (`Nudr` policy-data, TS 29.519) per subscriber instead of a purely
> local table, and it exposes **`Npcf_SMPolicyControl_Update`** so a **mid-session
> policy change** (an operator/OAM edit landing in the UDR) can be re-authorized
> for a live session.

## What was built

### Policy from the UDR (Nudr policy-data)

- **`subscriber-db`**: a new `DataSet::Policy` data class (SM policy data). Unlike
  the AM/SM/SMF-selection documents it is **not serving-PLMN-scoped** — stored
  under an empty PLMN key. redb table `policy_data`; swept by `remove_subscriber`
  like the other classes.
- **`sbi_core::nudr`**: the TS 29.519 resource
  `GET|PUT /nudr-dr/v2/policy-data/ues/{ueId}/sm-data` (keyed by ueId only), plus
  `UdrClient::get_sm_policy_data` / `put_sm_policy_data`. Token-bearing like the
  rest of the UdrClient (the resource sits under the same `oauth::protect` layer).
- **`sbi_core::npcf`**: `PolicyConfig` is now `Serialize`/`Deserialize` — the UDR
  policy-data document *is* a serialized `PolicyConfig` (`{default, perDnn}`), so a
  provisioned doc deserializes straight into the engine. `PcfState::with_udr`
  attaches a UDR client; `decide_for(ctx)` fetches the subscriber's policy-data and
  `decide`s from it, **falling back to the local config** when a subscriber has no
  policy-data (or the UDR is unreachable / the doc is malformed).
- **`nf-pcf`**: sources policy from a configured UDR (`RADIAN_PCF_UDR`, default
  `:8005`), token-bearing when `RADIAN_SBI_SECRET` is set (stable `PCF_INSTANCE_ID`
  shared between the NRF profile and token requests — mirrors the UDM). **`nf-udr`**
  provisions demo SM policy-data equal to the demo sm-data QoS, so the PCF-driven
  session is byte-identical to the sm-data fallback.

### Npcf_SMPolicyControl_Update (mid-session)

- **PCF**: `POST /npcf-smpolicycontrol/v1/sm-policies/{id}/update` re-evaluates the
  stored association against the **current** UDR policy-data (so a mid-session
  change is reflected) and returns the fresh `SmPolicyDecision`; the association now
  stores `(context, decision)`. `PcfClient::update_sm_policy`.
- **SMF**: the `SmContext` holds its current authorized QoS
  (`SmPolicyDecision`), and a new trigger
  `POST /nsmf-pdusession/v1/sm-contexts/{ref}/refresh-policy` calls Npcf Update,
  refreshes that record, and returns the new decision. `204` when the session used
  the sm-data fallback (no PCF association); `404` for an unknown context.

## Scope of "apply" — and the deliberate boundary

`refresh-policy` re-authorizes the policy and updates the SMF's **authoritative QoS
record** for the session. It does **not yet propagate** a changed QoS onward:

- to the **UPF** — that needs a session-AMBR **QER** in the N4 session (the
  `QER/buffering` item still open since design/18); the UPF does not enforce AMBR
  today, so there is nothing to re-install.
- to the **RAN/UE** — that needs an **N2 PDU Session Resource Modify** +
  **N1 PDU Session Modification Command / Complete** (the modify analogue of the
  setup leg in design/17), a sizeable NGAP+NAS surface.

Both are follow-up slices. What this slice delivers is the **complete
control-plane path** for a mid-session policy change — UDR edit → PCF re-reads →
Npcf Update → SMF re-authorizes — which is the prerequisite for either propagation.
The trigger is modelled as an SMF SBI endpoint (an OAM/AF-driven refresh); the
standard automatic policy-control-request triggers (RAT/location change) and the
PCF-push `SmPolicyUpdateNotification` are not implemented.

## Verification

- `cargo test --workspace --exclude bdd` — green (97 tests). New/changed:
  - `npcf::pcf_sources_policy_from_udr_and_update_reflects_changes` — an in-process
    UDR provisioned with policy-data drives the PCF's decision (200/400 Mbps, not
    the local 1/2 Gbps demo); reprovisioning the UDR then calling **Update** returns
    the changed AMBR + an added GBR flow; Update of an unknown id → error.
  - `pdu_session::refresh_policy_applies_a_mid_session_udr_change` — end-to-end
    through the SMF: CreateSMContext yields the UDR's v1 policy; a UDR change + the
    SMF's `refresh-policy` returns v2 (changed AMBR, extra flow); unknown context →
    404.
  - `npcf::create_then_delete…` / `per_dnn_override…` and the SMF PCF-path /
    fallback tests still green.
- **BDD, 5 scenarios / 25 steps green**, including the live **`@sim`** e2e — the PCF
  now reads the demo subscriber's policy from the **UDR** and the full free-ran-ue
  registration + PDU session + ping still completes (demo policy-data == demo QoS).

## Known limitations / next steps

- **Propagate a mid-session change** to the UPF (session-AMBR QER) and to the
  RAN/UE (N2 PDU Session Resource Modify + N1 PDU Session Modification Command).
- **PCF-initiated** `Npcf_SMPolicyControl_UpdateNotify` (push) + an SMF
  notification callback, and the standard automatic update triggers.
- **PCC rules** (TS 23.503) and richer TS 29.519 policy-data (per-S-NSSAI /
  per-DNN structure, usage monitoring) — `perDnn` is the seam.
- **Npcf_AMPolicyControl** (access/mobility policy toward the AMF) + UE policy.
- **SBI auth for the PCF** — put the PCF behind `oauth::protect`; its UDR client is
  already token-ready.
