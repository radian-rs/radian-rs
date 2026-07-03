# Mid-session QoS change to the RAN/UE — N2/N1 PDU Session Modify — Implementation Notes

> Built 2026-07-02 on branch `feat/n2n1-pdu-modify`, the final leg of the
> QoS-change propagation arc ([48](48-pcf-udr-policy.md) re-authorized the SMF
> record, [49](49-upf-ambr-qer.md) enforced it on the user plane). This slice
> signals the change to the **access side**: the SMF drives the serving AMF, which
> sends an **N2 PDU Session Resource Modify** to the gNB carrying an **N1 PDU
> Session Modification Command** for the UE.

## The chain

```
refresh-policy (SMF)  ──Namf_Communication──▶  AMF  ──N2 PDU Session Resource Modify──▶  gNB
   │  (PCF Update, N4 QER re-rate — design 48/49)         │  (over the UE's SCTP association)   │
   └── discovers AMF via NRF, POSTs the new QoS           └── N1 Modification Command ──────────┘──▶ UE
                                                              gNB ──N2 Modify Response──▶ AMF (logged)
```

## What was built

### NGAP (`ngap`)

- **`pdu_session_resource_modify_request(amf_ue_id, ran_ue_id, psi, flows, session_ambr_dl_bps, session_ambr_ul_bps, nas)`** — the `PDUSessionResourceModifyRequest`. Its `ModifyRequestTransfer` carries `PDUSessionAggregateMaximumBitRate` (the new session AMBR) + `QosFlowAddOrModifyRequestList` (the updated flows); the `nas` N1 SM container rides in the item's `nAS_PDU`.
- **`pdu_session_resource_modify_response(...)`** (gNB side, for tests) + **`modify_response_result`** (parse `(amf_ue_id, ran_ue_id, [psi])`).
- **`nas_pdu_from_modify_request`** — extract the N1 the gNB relays to the UE.
- Refactor: the per-flow `QosFlowLevelQosParameters` builder is now shared by the setup and add-or-modify lists.

### NAS (`nas`)

- **`pdu_session_modification_command(psi, pti, ambr, flows)`** — the 5GSM **PDU Session Modification Command** (msg type `0xCB`) as raw N1 bytes: Session-AMBR (IEI `0x2A`) + Authorized QoS flow descriptions (IEI `0x79`, reusing the accept's encoder). `pti = 0` for a network-initiated procedure. Wrapped in `dl_nas_transport_sm` like the accept.

### AMF (`nf-amf`)

- The per-UE control channel command enum (was `DeregCmd`) is now **`UeCmd`** with a new **`ModifyPolicy`** variant (boxed — carries the parsed session AMBR + QoS flows).
- New callback route **`POST /namf-comm/v1/ue-contexts/{supi}/modify`** (`Namf_Communication` N1N2-transfer analogue): parses the SMF's QoS JSON (reusing `parse_qos_flows` + the bitrate helpers), looks up the UE in `UE_DIRECTORY`, and hands a `ModifyPolicy` to the owning association task. `202` reachable / `404` not.
- **`on_network_modification`** (in the `serve_gnb` select arm, sibling to `on_network_deregistration`): with the UE's NAS security context in hand, builds the **protected N1** modification command + the **N2** modify request and returns them for SCTP send. No-ops for an unknown UE, an unsecured UE, or a psi with no session.
- The NGAP dispatcher logs the gNB's `PDUSessionResourceModifyResponse`.

Why route it through the association task (not the SBI handler): the **NAS security context lives only inside `serve_gnb`'s per-UE map**, never shared — so a protected downlink must be built there. This mirrors the network-initiated deregistration blueprint exactly.

### SMF (`nf-smf`)

- `refresh-policy`, after re-rating the UPF QER, now — when the QoS actually changed — **notifies the serving AMF** (`spawn_amf_pdu_modify`, best-effort off the response path): discovers the AMF via the NRF and POSTs the re-authorized session AMBR + QoS flows to the `namf-comm` modify route.

## Boundaries / notes

- **AMF selection is single-AMF** (NRF discovery of nf-type `AMF`). A multi-AMF
  deployment would target the UE's *serving* AMF via the UECM `amf-3gpp-access`
  record — documented, not implemented.
- **Not live-verified against free-ran-ue.** The simulator never initiates a
  mid-session modification and has no hook to trigger `refresh-policy`, so — like
  several prior slices (multi-PDU, rejected-NSSAI) — the N2/N1 modify wire shapes
  are **pinned by unit/integration tests**, not interop. The N1 modification
  command's opcode semantics (create vs. modify) and full free5gc-UE compat are
  unverified; the `@sim` ping only confirms no regression.
- **Modify Complete** from the UE (its N1 acknowledgement) is accepted as an
  ordinary UL NAS Transport and not specifically tracked; no modification timer.

## Verification

- `cargo test --workspace --exclude bdd` — green (105 tests). New:
  - `ngap::modify_request_roundtrips` / `modify_response_yields_result` — APER round trips of the request (session AMBR + add-or-modify flows) and the response parse.
  - `nas::pdu_session_modification_command_layout` — header `0x2e/psi/0/0xCB`, Session-AMBR TLV, and the `0x79` flow-descriptions IE.
  - `nf-amf::network_modification_signals_ran_and_ue` — end to end through the AMF: builds the N2 modify, and the **UE verifies the embedded protected N1** and finds a `0xCB` modification command; unknown psi is a no-op.
  - `nf-smf::refresh_policy_applies_a_mid_session_udr_change` (extended) — a mock AMF registered with the NRF records the SMF's `Namf_Communication` post; the test asserts the SMF **notified the AMF** with the changed AMBR + flows (alongside the existing UPF-QER assertion).
- **BDD, 5 scenarios / 25 steps green**, incl. the live **`@sim`** e2e — the modify path fires only on `refresh-policy` (not exercised by the sim), so registration + PDU session + ping are unaffected.

## Known limitations / next steps

- **UECM-based serving-AMF selection** for multi-AMF deployments.
- **Modification Complete tracking** + a modification timer / retransmission.
- **Per-flow GBR enforcement** at the UPF (still session-AMBR only) and **QoS
  flow release** (remove a flow mid-session).
- Live interop for the modification procedure (a UE/gNB that drives or accepts it).
