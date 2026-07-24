# NSSF — Network Slice Selection Function (Nnssf)

> Research date: 2026-07-23. Branch `feat/133-nssf-slicing`.
> Executes the **P2 "NSSF + slicing"** item of [130-free5gc-functionality-gap.md](130-free5gc-functionality-gap.md) §3.1 — the first P2 slice, after P1 closed ([131](131-ipv6-pdu-sessions.md) IPv6, [132](132-n2-interface-management.md) N2 management).
> 3GPP: TS 23.501 §5.15 (network slicing), TS 29.531 (Nnssf_NSSelection, Nnssf_NSSAIAvailability).

## TL;DR

- design/130 §3.1 flagged NSSF as a **Major, missing whole NF**, but also asked the right question: *"confirm what genuinely needs a standalone NSSF vs. what the AMF already does, so P2.3 isn't over-scoped."* This doc answers it.
- The AMF **already** does slice admission locally and well: `compute_nssai(requested, subscribed)` (allowed = requested ∩ subscribed, rejected = the rest), rejected-NSSAI + **5GMM #62** registration reject, and per-session **5GSM #70** admission (designs 32/33/34/102/103). A network round-trip that returned the same answer would be pure ceremony.
- The one thing AMF-local logic **structurally cannot** do is **per-tracking-area slice availability**: the AMF's intersection is PLMN-global, so a slice that is subscribed but *not deployed in the UE's current TA* is wrongly allowed today. That is real, observable, and testable.
- **NSI selection** (one NSI here) and **AMF re-selection** (one AMF; multi-AMF is a separate design/130 gap) are degenerate in this deployment — their protocol shape is implemented, but they are not exercised, and this doc says so rather than pretending otherwise.
- **Decision: build a real `nf-nssf` whose value is per-TA availability. `Nnssf_NSSelection` becomes the slice decision (with the AMF's `compute_nssai` retained as the offline fallback, preserving the fail-open invariant), and `Nnssf_NSSAIAvailability` makes the availability table dynamic. The acceptance test is a UE whose requested slice is subscribed but unavailable in its TA — which the pre-NSSF AMF would have wrongly allowed.**

**LANDED** (branch `feat/133-nssf-slicing`). `crates/sbi-core/src/nnssf.rs`: `Snssai` wire type (+`from_parts`/`to_parts` against the AMF's `(SST, Option<SD>)` tuple, no `hex` dep), `NsSelectionRequest`/`Response`, `TaAvailability`, `NssfConfig::{demo,permissive}`, `NssfState::{select,set_availability,availability}`, `router`, `NssfClient`. `nf/nf-nssf`: new NF on **port 8008**, nf-type `NSSF`, two services (`nnssf-nsselection`, `nnssf-nssaiavailability`). `nf-amf`: `select_slices` discovers the NSSF and calls NSSelection with the UE's `ctx.tac`, read before the `&mut` borrow; the decision replaces `compute_nssai`, which stays as the offline fallback. **The demo availability table is deliberately behaviour-preserving** — TACs `000001`/`000002` (the ones every existing scenario uses) deploy the subscribed default slice, so the NSSF returns exactly what the local intersection did; `000007` deploys nothing and is where the new capability shows. **Tests:** sbi-core 5 new (incl. subscription-stays-authoritative and the fail-open unprovisioned-TA case), nf-amf 51, workspace `--exclude bdd` **45** bins green; **full `cargo test -p bdd` = 33 scenarios / 369 steps GREEN** — the new scenario refuses a *subscribed* slice in TAC `000007`, and D1/D7/D8/D9 all still pass unchanged with the NSSF in the path; clippy no net-new.

## 1. What exists today (measured)

| Capability | Where | Status |
|---|---|---|
| allowed = requested ∩ subscribed | `nf-amf/src/main.rs` `compute_nssai` | ✅ pure fn, unit-tested |
| rejected NSSAI + **5GMM #62** reject + back-off | `on_security_mode_complete` | ✅ |
| per-session slice admission → **5GSM #70** | the UL-NAS-Transport path | ✅ |
| subscribed NSSAI from Nudm_SDM am-data | `fetch_am_data` (`nssai.defaultSingleNssais`) | ✅ |
| Allowed NSSAI in Registration Accept + N2 InitialContext + handover | several | ✅ |
| **per-TA slice availability** | — | ❌ **the gap** |
| Nnssf_NSSelection / NSSAIAvailability | — | ❌ |
| NSI selection, AMF re-selection | — | ❌ (degenerate: one NSI, one AMF) |

**Fail-open invariant** (three sites encode it): a missing subscription must never reject the registration — `subscribed == None` ⇒ no NSSAI IEs and admission falls through to the SMF's own check. **The NSSF must not break this**: an unreachable NSSF has to degrade to the local intersection, not to a rejection.

## 2. Design decisions

**D1 — The NSSF's reason to exist here is per-TA availability.** `Nnssf_NSSelection` takes `(requested, subscribed, TAI)` and returns `(allowed, rejected)`. Its answer differs from the AMF's local one exactly when a subscribed slice is not available in the UE's tracking area. Everything else it returns matches `compute_nssai` — deliberately, so the migration is behaviour-preserving except where the new capability applies.

**D2 — The AMF keeps `compute_nssai` as its offline fallback.** The AMF discovers the NSSF via the NRF and calls it; if discovery or the call fails it falls back to the local intersection and logs. This preserves the fail-open contract and means an NSSF outage degrades slicing to today's behaviour rather than dropping registrations. *Rejected:* making the NSSF mandatory (turns a slicing NF into a single point of registration failure).

**D3 — `Nnssf_NSSAIAvailability` makes the table dynamic.** The NSSF starts from a configured per-TAC table (`NssfConfig::demo()`); a `PUT /nnssf-nssaiavailability/v1/nssai-availability/{nfId}` replaces the supported slices for a set of TAs, and a `GET` reads them back. Without this the NSSF is a static lookup and the "availability" story is untestable.

**D4 — Simplified request encoding, documented.** TS 29.531 models NSSelection as a `GET` with deeply-nested query parameters (`slice-info-request-for-registration`). This stack uses `POST` + a JSON body, as the SMF already does for `Nsmf_PDUSession` ("request/response bodies are simplified"). The *semantics* follow the spec; the encoding is pragmatic. Noted as an interop caveat against free5gc.

**D5 — Out of scope, explicitly.** **NSI selection** (`nsiInformation`) — one NSI per slice here, so selection is the identity function. **AMF re-selection** (`targetAmfSet` when the serving AMF can't serve the requested slices) — radian-rs runs one AMF; multi-AMF + NAS reroute is a separate design/130 gap. Both are called out so a later reader doesn't mistake their absence for an oversight.

## 3. Change surface

| # | File | Change |
|---|---|---|
| 1 | `Cargo.toml` | add `nf/nf-nssf` to workspace members |
| 2 | `nf/nf-nssf/{Cargo.toml,src/main.rs}` | **new** NF, SBI port **8008**, nf-type `NSSF`, services `nnssf-nsselection` + `nnssf-nssaiavailability` (two-service pattern from nf-pcf) |
| 3 | `crates/sbi-core/src/nnssf.rs` | **new** — `NssfConfig` (per-TAC supported slices) + `NssfState` + `router` + `NssfClient` |
| 4 | `crates/sbi-core/src/lib.rs` | `pub mod nnssf;` |
| 5 | `nf-amf/src/main.rs` | discover the NSSF and call NSSelection in `on_security_mode_complete`; keep `compute_nssai` as the fallback |
| 6 | `bdd` | spawn `nf-nssf`; a scenario proving per-TA availability rejects a subscribed-but-unavailable slice |

## 4. Acceptance

The test that justifies the NF: the demo subscriber is subscribed to slices `1:010203` and `2`, and the NSSF's availability table publishes slice `2` **only in TAC 000001**. A UE registering from **TAC 000002** requesting `2`:

- **before** — the AMF's local intersection allows it (subscribed ⇒ allowed);
- **after** — the NSSF rejects it as unavailable in that TA, and the accept carries it as a rejected S-NSSAI.

Plus: an NSSF outage falls back to the local intersection (fail-open preserved).

## 5. Risks & open questions

- **Latency on the registration path.** NSSelection adds an SBI round trip to every registration. Acceptable (the AMF already calls the PCF and UDM there), but it is on the critical path — hence the fallback rather than a retry loop.
- **Availability vs. subscription precedence.** A slice must be *both* subscribed and available; the NSSF intersects both. A slice available but not subscribed is still rejected — subscription remains authoritative.
- **Registration-area interaction.** The allowed NSSAI is computed for the UE's *current* TA, but the registration area may span several TAs (design/75 union). A UE moving within its area could hold an allowed slice unavailable in the new TA; strictly this needs re-evaluation on mobility registration update. Out of scope here, noted as a follow-up.
- **NSI/AMF-reselection remain degenerate** until there are multiple NSIs / AMFs (D5).

## 6. Sources

- `nf-amf/src/main.rs` (`compute_nssai`, `on_security_mode_complete`, `fetch_am_data`, `discover_nf`), `crates/sbi-core/src/{nchf,npcf_am,nnrf}.rs` (service + client + NRF idiom), `nf/nf-chf` (minimal NF template), `bdd/tests/cucumber.rs` (`start_core`).
- Prior slicing work: [31](31-requested-snssai.md), [32](32-allowed-nssai.md), [33](33-nssai-intersection.md), [34](34-registration-reject-62.md), [102](102-cuc-allowed-nssai.md), [103](103-narrowed-nssai-release.md).
- TS 23.501 §5.15, TS 29.531. Gap origin: [130](130-free5gc-functionality-gap.md) §3.1.
