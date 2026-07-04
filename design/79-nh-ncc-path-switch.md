# NH/NCC Key Chains — Xn Handover Path Switch

> Built 2026-07-04 on branch `feat/nh-ncc-path-switch`. Designs
> [77](77-initial-context-setup.md)/[78](78-ics-on-resume.md) hand the gNB a
> K_gNB but noted "key freshness, not key isolation" — there was no **NH chain**
> (TS 33.501 Annex A.10) and no procedure to consume it. This adds both: the AMF
> maintains the `{NH, NCC}` pair per UE, and the natural consumer — the **Xn
> handover path switch** (TS 38.413 §8.4.4) — rotates it: the target gNB's
> `PathSwitchRequest` gets a `PathSwitchRequestAcknowledge` carrying a fresh
> `{NCC, NH}` (Security Context IE) for vertical key derivation, and the UPF
> downlink is re-pointed to the target's new F-TEID.

## What was built

### `aka`

`nh(kamf, sync_input)` (TS 33.501 Annex A.10, FC=0x6F, via
`oxirush_security::derive_nh`): the sync input is the **initial K_gNB** for the
first NH and the **previous NH** for every one after.

### `ngap`

- `path_switch_request(source_amf_ue_id, ran_ue_id, mcc, mnc, tac, ue_sec_cap,
  sessions)` — the target gNB's request (test/sim side): the UE's new location
  (ULI), security capabilities, and per PDU session the new DL N3 F-TEID
  (`PathSwitchRequestTransfer`, QFI-1 accepted list).
- `path_switch_params` — the AMF-side parser: `(source_amf_ue_id, new_ran_ue_id,
  tac, [(psi, dl_teid, dl_addr)])`.
- `path_switch_request_acknowledge(amf, ran, ncc, nh, switched_psis)` — the AMF's
  answer: **Security Context `{NCC, NH}`** + the switched-session list.
- `path_switch_ack_security` — the gNB-side/test parser.

### `nf-amf`

- **`UeContext.nh_chain: Option<([u8; 32], u8)>`** — `(sync_input, NCC)`. Seeded
  wherever an Initial Context Setup delivers a K_gNB: at registration
  (design/77) and on every idle-resume (design/78, which re-seeds with NCC 0 —
  a resume derives a new initial AS key).
- **`on_path_switch`** (new `handle_ngap` arm): resolves the UE by the source
  AMF-UE-NGAP-ID, moves the context to the target (`ran_ue_id`, TAC refreshed
  from the ULI), rotates the chain — `NH = KDF(K_AMF, sync)`, `NCC = (NCC+1) mod
  8` (a 3-bit counter) — re-points each switched PDU session's UPF downlink via
  the existing `UpdateSMContext` (N4 modify), and acknowledges with the fresh
  pair plus the switched-session list. A path switch for an unknown UE or an
  unseeded chain is ignored (no acknowledge).

## Boundaries / notes

- **The source gNB is not released** (no UE Context Release toward it) — with a
  single N2 association registry per task, cross-association signalling for the
  source side is out of scope here.
- Sessions the SMF fails to re-point are omitted from the switched list (the
  proper `PDUSessionResourceReleasedListPSAck` is not built).
- `PathSwitchRequestFailure` is not sent for the ignored cases.
- The UE-side AS derivation from `{NH, NCC}` is the RAN/UE's job — nothing to do
  in the core beyond handing over a correct pair.

## Verification

- `cargo test --workspace --exclude bdd` — green (**166** tests). New:
  - aka `nh_chain_is_deterministic_and_hops_differ` — NH₁ from K_gNB, NH₂ from
    NH₁, all fresh and K_AMF-bound.
  - ngap `path_switch_roundtrips` — the request (ULI TAC + switched F-TEIDs) and
    the acknowledge (`{NCC, NH}` + switched PSIs) survive APER encode→decode.
  - nf-amf `xn_path_switch_rotates_nh_and_repoints_the_downlink` — a seeded UE
    (chain = initial K_gNB, NCC 0) is switched to a target gNB: the mock SMF
    receives the new F-TEID (`00000077` / `10.0.9.2`), the context follows
    (`ran_ue_id`, TAC), the acknowledge carries `{NCC 1, NH₁ = KDF(K_AMF,
    K_gNB)}`, and a **second** switch chains `{NCC 2, NH₂ = KDF(K_AMF, NH₁)}`;
    unknown UEs and unseeded chains are ignored.
  - The design/77/78 ICS tests now also assert the chain seeding (NCC 0 from the
    delivered K_gNB, re-seeded on resume).
- `cargo clippy --workspace --exclude bdd` — clean.
- **BDD 2 features / 5 scenarios / 25 steps green** — the live registration/ICS
  path (which seeds the chain) is unaffected.
- An Xn path switch needs **two gNBs** — free-ran-ue is single-gNB, so the
  procedure is integration-tested (design/64/65 precedent); the wire encoding is
  APER round-trip-tested.

## Known limitations / next steps

- **Release the source gNB** after a successful switch (cross-association UE
  Context Release).
- **PathSwitchRequestFailure** + `PDUSessionResourceReleasedListPSAck` for the
  error paths.
- **N2 handover** (Handover Required / Request / Command) — the inter-AMF or
  Xn-less handover, where `{NH, NCC}` rides the Handover Request.
