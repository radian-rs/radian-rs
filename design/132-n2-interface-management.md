# N2 Interface Management — NG Reset, RAN Configuration Update, Error Indication, Overload

> Research date: 2026-07-23. Branch `feat/132-n2-interface-mgmt`.
> Executes the **P1 "N2 interface management"** slice of [130-free5gc-functionality-gap.md](130-free5gc-functionality-gap.md) §2.1 — the remaining P1 item now that IPv6 ([131](131-ipv6-pdu-sessions.md)) has shipped.
> 3GPP: TS 38.413 §8.7 (Interface Management), §9.2.6 (message contents), §9.4 (criticality).

## TL;DR

- radian-rs implements the **UE-associated** NGAP surface deeply (registration, handover, paging, PDU sessions) but has **no interface-management procedures at all**: the AMF's dispatch falls through to `unhandled initiating message` for NG Reset, RAN Configuration Update, and Error Indication, and the AMF can never signal Overload. free5gc has all four.
- These are the procedures a real gNB exercises on **restart, reconfiguration, and error paths** — the highest-value interop hardening available for the effort (design/130 sized it **S–M**).
- **Decision: implement all four. The three RAN→AMF procedures (NG Reset, RAN Configuration Update, Error Indication) are driven and asserted end-to-end by the scripted gNB; Overload (AMF→RAN) gets an OAM trigger so it is testable too, rather than shipping dead code.**

**LANDED** (branch `feat/132-n2-interface-mgmt`). `crates/ngap`: `ng_reset_all`/`ng_reset_partial`/`parse_ng_reset` (a `ResetScope` enum)/`ng_reset_acknowledge`/`parse_ng_reset_acknowledge`; `ran_configuration_update`/`parse_ran_configuration_update`/`ran_configuration_update_acknowledge`; `error_indication`/`parse_error_indication`; `overload_start`/`overload_stop`/`overload_action`/`is_overload_stop` — plus a `supported_ta_list` helper now shared with `ng_setup_request`. `nf-amf`: extracted `release_ue_context` from `on_ue_context_release_request` (AN-release semantics: deactivate each PDU session at the SMF, drop the N2 association, retain the 5GMM context by 5G-TMSI) and reused it from a new `on_ng_reset`; dispatch arms for `Id_NGReset`, `Id_RANConfigurationUpdate` (mutates the `GnbLink` TAC list), and `Id_ErrorIndication` (logged only); a `broadcast_to_gnbs` helper (builds a fresh PDU per association — `NGAP_PDU` is not `Clone`) behind a new OAM route `POST /oam/v1/overload {"action":"start"|"stop"}`. `bdd` gained an `sbi-core` dep to drive that OAM route. **Tests:** ngap 25 (an APER round-trip over all eight messages), nf-amf 51; workspace `--exclude bdd` 44 bins green; **full `cargo test -p bdd` = 32 scenarios / 360 steps GREEN** — three new scripted scenarios (gNB restart → NG Reset → contexts released → Acknowledge; RAN Configuration Update → Acknowledge; Error Indication logged + OAM-triggered Overload Start/Stop received at the gNB); clippy no net-new.

## 1. What's missing (measured)

| Procedure | Direction | TS 38.413 | radian-rs today | free5gc |
|---|---|---|---|---|
| **NG Reset** / Acknowledge | RAN→AMF (and AMF→RAN) | §8.7.4 | ❌ falls through | ✅ |
| **RAN Configuration Update** / Ack / Failure | RAN→AMF | §8.7.2 | ❌ falls through | ✅ |
| **Error Indication** | both | §8.7.5 | ❌ falls through | ✅ |
| **Overload Start / Stop** | AMF→RAN | §8.7.6/7 | ❌ absent | ✅ |

`crates/ngap` has only `ng_setup_request`/`ng_setup_response` from the interface-management family; the AMF's `handle_ngap` (`nf/nf-amf/src/main.rs`) has no arms for any of the four.

## 2. Design decisions

**D1 — NG Reset releases, then acknowledges.** A gNB that restarted sends NG Reset; the AMF must drop the affected UE contexts *before* acknowledging (TS 38.413 §8.7.4.2). Two scopes:
- `ResetType::NG_Interface(ResetAll)` — release **every** UE context on that association.
- `ResetType::PartOfNG_Interface(list)` — release only the listed `(AMF-UE-NGAP-ID, RAN-UE-NGAP-ID)` pairs.

The release reuses the existing AN-release teardown (`on_ue_context_release_request`'s body, extracted into a helper): deactivate each PDU session at the SMF, drop the context, and clear the `UE_DIRECTORY` / `RETAINED` entries. **Gotcha:** the ack's `UE-associatedLogicalNG-connectionList` is `SIZE(1..65536)` — an empty list fails to APER-encode, so a full reset acknowledges with the IE **omitted**, not empty.

**D2 — RAN Configuration Update mutates the same link state NG Setup does.** The gNB may change its `RANNodeName` and `SupportedTAList` without re-running NG Setup; the AMF updates the `GnbLink` (the TAC list paging is scoped to, and the gNB id handover resolution keys on) and answers Acknowledge. Every IE is optional (§9.2.6.5), so absent fields leave the stored value untouched. Failure (with a `TimeToWait`) is built but not triggered — the AMF accepts any well-formed update.

**D3 — Error Indication is logged, not acted on.** Per §8.7.5 the receiver may take implementation-specific action. The AMF logs the cause and the UE ids; it does **not** tear the UE down (a spurious Error Indication shouldn't drop a working session). The AMF also *emits* one when it receives a UE-associated message for an AMF-UE-NGAP-ID it doesn't know — closing the "silently ignore" path the catch-all left.

**D4 — Overload gets an OAM trigger.** Overload Start/Stop are AMF→RAN with no natural trigger in a demo core (no load metric). Rather than ship unreachable builders, add an **OAM route** on the AMF's existing SBI router (`POST /oam/v1/overload {"action":"start"|"stop"}`) that broadcasts to every connected gNB. free5gc has the same shape (`amf/.../api_oam.go`). Broadcast reuses `UeCmd::Forward` over `GNB_LINKS` — **no new channel variant needed** — with the same `retain`-sweeps-closed-links idiom as `page_gnbs`. *Rejected:* a synthetic load metric (arbitrary and untestable).

## 3. Change surface

| Layer | File | Change |
|---|---|---|
| NGAP builders | `crates/ngap/src/lib.rs` | `ng_reset_all` / `ng_reset_partial` / `ng_reset_acknowledge`; `ran_configuration_update` / `..._acknowledge`; `error_indication`; `overload_start` / `overload_stop` |
| NGAP parsers | `crates/ngap/src/lib.rs` | `parse_ng_reset` → a `ResetScope` enum; `parse_ran_configuration_update` → (name, TACs); `parse_error_indication`; gNB-side `overload_action` |
| AMF dispatch | `nf/nf-amf/src/main.rs` | arms for `Id_NGReset`, `Id_RANConfigurationUpdate`, `Id_ErrorIndication`; extract `release_ue_context` from `on_ue_context_release_request` |
| AMF OAM | `nf/nf-amf/src/main.rs` | `POST /oam/v1/overload` on `namf_callback_router` + a `broadcast_to_gnbs` helper |
| BDD | `bdd/src/ran.rs`, `bdd/tests/…` | scripted gNB sends NG Reset (full + partial), RAN Configuration Update, Error Indication; an SBI poke drives Overload and the gNB asserts it arrives |

## 4. Risks & open questions

- **Reset vs. retained contexts.** A full reset must also clear `RETAINED` (CM-IDLE contexts) belonging to that gNB, or a later paging resolves a stale UE — the same class of bug design/126 hit. The AMF doesn't currently track which gNB a retained context came from; the conservative fix is to clear retained entries for the released UEs only.
- **Association scoping.** `GNB_LINKS` is global; a reset arriving on one association must not release another gNB's UEs. The handler works from the UE ids the reset names (partial) or the contexts the resetting association owns (full).
- **Overload is advisory.** The AMF does not itself throttle admissions when overloaded — it only signals the RAN. Making the AMF *act* on its own overload (reject registrations) is a follow-up.
- **AMF-initiated NG Reset** (AMF→RAN) is built but not triggered; the RAN-initiated direction is what a restarting gNB exercises.

## 5. Sources

- `crates/ngap/src/lib.rs` (builder/parser idiom, `build_ngap!`), `nf/nf-amf/src/main.rs` (`handle_ngap`, `GNB_LINKS`, `page_gnbs`, `on_ue_context_release_request`, `namf_callback_router`), `ran/gnb/src/lib.rs`, `bdd/src/ran.rs`.
- oxirush-ngap 0.3.1 generated types: `ResetType`, `ResetAll`, `UE_associatedLogicalNG_connectionList` (SIZE(1..)), `OverloadResponse`/`OverloadAction`, `RANNodeName`, `SupportedTAList`.
- TS 38.413 §8.7, §9.2.6, §9.4. Cross-refs: [130](130-free5gc-functionality-gap.md) §2.1 (the gap), [131](131-ipv6-pdu-sessions.md) (the other P1 item, shipped).
