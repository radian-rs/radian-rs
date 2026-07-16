# RRC UPER Codec Spike — Hampi vs rasn-compiler vs hand-rolled (design/128 Phase 1a)

> Research date: 2026-07-16, on branch `feat/design-rrc-codec-spike`.
> Executes **Phase 1a** of [128-gnb-ocudu-feasibility.md](128-gnb-ocudu-feasibility.md)
> and settles the one gap [01-asn1-rust-gap-analysis.md](01-asn1-rust-gap-analysis.md)
> called "project-sized": a Rust codec for **RRC (TS 38.331, UPER)**.
> This is a throwaway spike — no crate landed; the deliverable is this decision.

## TL;DR

The spike ran all three candidates over the **real TS 38.331 ASN.1** and round-tripped
**golden UPER PDUs from OCUDU's own test suite** (OCUDU's C++ codec is the oracle).
Result, with measured evidence below:

- **Hampi (`asn1-codecs` / `asn1-compiler` 0.7.2)** — the one already in our tree for
  NGAP transfer-IEs — **compiles the full 38.331 clean and offline**, and round-trips
  our hardest *encoded* message (RRCReconfiguration, 383 B) **byte-identical** to the
  oracle. Its one failure mode is **silently dropping ASN.1 extension-additions** (it
  warns at codegen exactly which types), which corrupts a re-encode of UECapability —
  a message design/128 already treats as an **opaque octet string**.
- **rasn-compiler 0.16** (design/01's "strategic" pick) **does not work for RRC yet**:
  its generated code has **12 compile errors in the core `NR-RRC-Definitions` module**
  (needs manual patching + network), and even after patching it **mis-encodes on the
  wire** — RRCReconfiguration differs from the oracle in the presence-preamble byte, and
  UECapability re-encodes with **162 of 236 bytes wrong**. design/01 flagged "rasn has
  rough edges on the gnarliest 3GPP modules; RRC is the gnarliest" — the spike confirms
  it empirically.
- **Hand-rolled minimal subset** — viable as a *targeted fallback*, not the base: the
  message set is small, but hand-encoding UPER SEQUENCE/CHOICE extension-preambles is
  exactly where subtle single-bit bugs live (rasn's byte-0 miss is that class of bug).

**Decision: build `crates/rrc` on Hampi**, generating from a pinned 38.331 release, with
a **mandatory per-message golden-PDU round-trip gate** in the crate's tests, and a
hand-rolled UPER escape hatch reserved for any single message where Hampi's
extension-addition dropping actually bites. rasn-compiler is **rejected for RRC now**;
revisit when its 3GPP-module codegen and UPER encoder mature. This refines design/01's
"rasn strategic" verdict for the **RAN/RRC** case specifically — it still holds for the
*AP protocols (APER), where oxirush-ngap already serves us.

---

## 1. The question and the exit criterion

design/128 Phase 1a: pick how `crates/rrc` gets its **UPER** codec for TS 38.331. The
three candidates were named there. The exit criterion was hard and behavioural, not a
matter of taste: **round-trip golden PDUs, with OCUDU's codec as the oracle** (encode
ours, decode theirs, byte-compare). This doc records the method and the measured result.

Why this is the load-bearing unknown: RRC's *procedures* are thin (OCUDU implements only
5 UE procedures, ~1k of logic), but the *codec* is ~320k of generated C++ in OCUDU. If a
Rust generator produces a correct UPER codec for our message subset, `crates/rrc` is
tractable; if not, the whole gNB control plane stalls here.

## 2. Method

**Oracle & golden PDUs.** OCUDU vendors no `.asn` source but ships a battle-tested C++
RRC codec *and* a unit-test corpus with known-good UPER byte vectors
(`tests/unittests/asn1/asn1_rrc_nr_test.cpp`). Two were used as golden PDUs:

- **RRCReconfiguration** — 383 B, a real message carrying a full secondary-cell-group
  config (the hardest message the gNB *builds*). OCUDU decodes it and asserts
  `rrc_transaction_id == 0`.
- **UE-NR-Capability** — 236 B, the caps of a real COTS 5G module (Simcom SIM8262E-M2)
  **with Rel-15.4 extension-additions** — deliberately exercises extension handling.

**ASN.1 source.** The TS 38.331 module is not in OCUDU (sourced from 3GPP per design/01).
The `gabhijit/hampi` repo vendors it: `examples/specs/rrc/rrc.asn`, 15,471 lines,
generated from **`38331-g50.docx` = TS 38.331 v16.5.0 (Rel-16)**. It contains our exact
P1 message set (RRCSetup(Request/Complete), SecurityModeCommand/Complete,
RRCReconfiguration/Complete, RRCRelease, UL/DL-CCCH/DCCH envelopes).

**Candidates & environment.** Hampi `asn1-compiler`/`asn1-codecs` 0.7.2 (already a
radian dependency, available offline); rasn-compiler 0.16 targeting the `rasn` 0.18
runtime (fetched from crates.io). All work done in a scratch tree; nothing committed to
the workspace. Reproduction in §7.

## 3. Results

### 3.1 Hampi (`asn1-compiler` 0.7.2)

- **Codegen:** compiled the full 38.331 to **~11k lines / 5,187 types** in seconds,
  offline. **128 warnings**, all one kind: *"Fields for some sequence additions may not
  be generated"* — i.e. it drops some SEQUENCE **extension-addition** fields.
- **Compiles clean:** the generated code built with only `asn1-codecs`,
  `asn1_codecs_derive`, `bitvec`, `log` — **zero code edits**.
- **RRCReconfiguration round-trip:** `uper_decode` → `rrc_transaction_identifier == 0`
  (matches the oracle) → `uper_encode` → **383 B, byte-identical to the golden PDU.**
  A lossless round-trip on the hardest message the gNB encodes.
- **UE-NR-Capability round-trip:** decodes, but re-encodes to **146 B vs 236 B** — the
  Rel-15.4 extension-additions are the fields the codegen warned it dropped. Loud
  (the warnings name the types), and lossy only on extensions.

### 3.2 rasn-compiler 0.16 (→ rasn 0.18)

- **Codegen:** generated **2.89 MB** of Rust, **0 warnings**, cleanly split into per-ASN.1
  modules (`nr_rrc_definitions`, `nr_inter_node_definitions`, sidelink, …).
- **Does not compile:** **12 errors in `nr_rrc_definitions`** — the module we need.
  Two bug classes: (a) 11 `Default`-impl functions *called* under one name but *defined*
  under another (`q_offset_range_list_…_default` vs `qoffset_range_list_…_default` — an
  inconsistent hyphen→identifier normalization between call site and definition); (b) an
  unresolved `SetupRelease` cross-module import (in the sidelink module).
- **After a bounded manual patch** (renamed the 11 calls, dropped the unused sidelink
  module) it compiled — and then **mis-encoded on the wire**:
  - **RRCReconfiguration:** re-encodes to 383 B but **differs at byte 0** (`08`→`01`) —
    the SEQUENCE optional/extension **presence-preamble** is wrong; bytes 1–382 match.
    A one-bit-class encoding bug.
  - **UE-NR-Capability:** re-encodes to 236 B but **162 of 236 bytes differ** — pervasive
    corruption (an early mis-encoding cascades through the bit stream).

rasn *preserves* the extension length that Hampi drops, but produces **wrong bytes** —
strictly worse for interop, where a peer must decode what we put on the wire.

### 3.3 Hand-rolled minimal subset

Not prototyped end-to-end (the spike's question — "does a generator work?" — was
answered affirmatively for Hampi). Assessment stands: our built messages are few and
structurally simple *at the envelope*, but their bodies (RRCReconfiguration's cell-group
config, measurement config) are deep, and hand-encoding UPER extensible-SEQUENCE and
CHOICE preambles by hand is precisely where a single wrong presence bit hides — the exact
failure rasn hit at byte 0. Verdict: **keep it as a surgical fallback** for a specific
message where the generator's extension-dropping is unacceptable, validated the same way
(golden round-trip). Not the base.

### 3.4 Head-to-head

| Criterion | Hampi 0.7.2 | rasn-compiler 0.16 |
|---|---|---|
| Fetch / offline | **in-tree, offline** | new stack, needs network |
| Full 38.331 compiles | **yes, no edits** | **no** — 12 errors in core RRC |
| RRCReconfiguration (383 B) round-trip | **byte-identical** | 383 B, **byte 0 wrong** |
| UE-NR-Capability (236 B, extensions) | decodes; drops ext (146 B) | decodes; **162/236 B wrong** |
| Failure mode | **loud** (codegen warns) & lossy-on-extensions only | **silent** & wire-wrong |
| UPER encode support | yes (derive emits `uper_encode`) | yes, but incorrect here |
| Already trusted in radian | **yes** (crates/ngap transfer-IEs) | no |

### 3.5 Release skew (design/128 risk #2), measured

Hampi's `rrc.asn` is **Rel-16 (v16.5.0)**; OCUDU's codec comments reference v15.x–**v17.0**.
Yet OCUDU's newer-codec golden RRCReconfiguration round-tripped **byte-identical** through
Hampi's **Rel-16** generated types. Reading: the **base messages are release-stable**;
drift lives in **extension-addition IEs** — the same place Hampi drops and where our risk
concentrates. This makes the mitigation concrete (below), not hypothetical.

## 4. Decision

**Build `crates/rrc` on Hampi (`asn1-codecs`), generating from a pinned TS 38.331 release.**

Rationale: it is the only candidate that (a) compiles our target module out of the box,
offline, with a dependency already in the tree, and (b) round-trips the message the gNB
most needs to *encode* correctly, **byte-exact against a real-world oracle**. Its one
weakness is bounded, loud, and aligned with the plan. rasn-compiler fails on both axes
that matter for RRC — it needs source patching to compile *and* mis-encodes the exact
modules we need; adopting it now would trade a known, narrow, warned limitation for
unknown, silent, wire-level bugs.

## 5. Consequences for Phase 1b (`crates/rrc`)

1. **Vendor + pin the 38.331 `.asn`** at the release our interop targets use (OCUDU's
   `odu` for the F1 rung; srsUE for the ZMQ rung). Record the release in the crate README
   (design/01's discipline). Regenerate rather than hand-edit generated output.
2. **Generate our subset with Hampi**, `--codec uper`. Keep generation scripted and the
   generated file checked in (like a vendored artifact), with the generator version pinned.
3. **A golden-PDU round-trip is a required test, per message.** For every message we
   build or parse (RRCSetup, SecurityModeCommand, RRCReconfiguration, RRCRelease,
   RRCSetupRequest/Complete, SecurityModeComplete), capture a golden UPER PDU (OCUDU test
   corpus first; OCUDU `gnb`/srsUE pcaps at the interop rungs) and assert decode→encode
   byte-identity in CI. This gate is what makes a "mostly-works" generator safe.
4. **Watch the extension-drop.** The 128 codegen warnings name the affected types. Before
   trusting any *built* message, confirm its round-trip is byte-exact (RRCReconfiguration
   already is for the tested PDU). If a message we must build needs a dropped
   extension-addition IE, that specific message gets the hand-rolled fallback (§3.3) — not
   the whole codec.
5. **UECapabilityInformation stays opaque** (design/128 already decided this). The spike
   makes it a *requirement*, not just an optimization: neither generator round-trips a
   real UE's caps, so the CU must forward the octet string, never re-encode it.
6. **`uper_encode` correctness is proven for RRCReconfiguration but "build-from-scratch"
   ergonomics are not yet exercised.** decode→re-encode tests the encoder; P1b must also
   construct one message (RRCSetup) from field values in the generated types and match a
   golden — the true test of the gNB's actual code path.

## 6. Risks / open questions

- **Only two golden vectors tested.** RRCReconfiguration (built) and UE cap (opaque)
  bracket the interesting cases, but P1b must expand the corpus to every message in the
  subset before relying on the codec.
- **Hampi maintenance cadence** is single-maintainer. We already depend on it for NGAP;
  this deepens that dependency. Mitigation: the generated file is a checked-in artifact —
  a stale upstream doesn't block us, and the golden gate catches any regeneration drift.
- **Extension-addition need in a built message.** Not yet observed for our subset at
  Rel-16 base, but a Rel-16/17 RRCReconfiguration IE we must set could hit the drop.
  Caught by the per-message golden gate; fixed per-message by the hand-rolled fallback.
- **rasn is still the right long-term ecosystem bet for APER** (design/01) — this doc
  narrows the "rasn strategic" claim to exclude RRC/UPER *today*, not to reverse it.

## 7. Reproducing the spike

Throwaway artifacts live under the session scratchpad (not committed). Outline:

1. `git clone --depth 1 https://github.com/gabhijit/hampi` → `examples/specs/rrc/rrc.asn`
   is TS 38.331 v16.5.0.
2. **Hampi:** `cargo build --release --bin rs-asn1c` (from the clone), then
   `rs-asn1c --module rrc_gen --codec uper -- rrc.asn`. Wrap the output in a crate with
   `asn1-codecs`, `asn1_codecs_derive`, `bitvec`, `log`; `RRCReconfiguration::uper_decode`
   then `.uper_encode` the golden bytes from `asn1_rrc_nr_test.cpp` and byte-compare.
3. **rasn:** a build using `Compiler::<RasnBackend,_>::new().add_asn_by_path("rrc.asn")
   .compile_to_string()`; compile the output against `rasn = "0.18"` (observe the 12
   errors), patch, then `rasn::uper::{decode,encode}` and byte-compare.
4. Golden bytes: `RRCReconfiguration` (asn1_rrc_nr_test.cpp lines 164–187) and
   `UE-NR-Capability` (line 342, hex comment).

## 8. Sources

- OCUDU `~/ocudu`: `tests/unittests/asn1/asn1_rrc_nr_test.cpp` (golden UPER vectors),
  `lib/asn1/rrc_nr/` + `include/ocudu/asn1/rrc_nr/` (the oracle codec).
- Hampi — https://github.com/gabhijit/hampi ; `asn1-codecs`/`asn1-compiler` 0.7.2
  (crates.io) ; bundled TS 38.331 `examples/specs/rrc/rrc.asn` (`38331-g50` = v16.5.0).
- rasn-compiler — https://github.com/librasn/compiler (0.16.0) → `rasn` 0.18 runtime.
- Companion designs: [01-asn1-rust-gap-analysis.md](01-asn1-rust-gap-analysis.md),
  [128-gnb-ocudu-feasibility.md](128-gnb-ocudu-feasibility.md).
- Specs: TS 38.331 (RRC, UPER); ITU-T X.691 (PER/UPER encoding rules).
