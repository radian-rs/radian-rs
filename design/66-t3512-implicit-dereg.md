# T3512 + Implicit Deregistration of Retained CM-IDLE Contexts

> Built 2026-07-03 on branch `feat/t3512-eviction`. The idle-mode arc (63–65) left
> `RETAINED` unbounded: a UE that went CM-IDLE and never came back lingered
> forever (context + buffered downlink). This adds the **mobile-reachable /
> implicit-deregistration timer** (TS 24.501 §5.3.7): the AMF sends the UE a
> **T3512** periodic-registration timer and evicts any retained context that stays
> silent past the deadline.

## What was built

### T3512 in the Registration Accept (`nas` / AMF)

- `registration_accept` now takes `t3512_secs` and sets the **T3512 value** IE
  (IEI `0x5E`, GPRS Timer 3, reusing `GprsTimer3`). The UE re-registers when it
  expires, so a UE that goes silent is genuinely unreachable.
- The AMF sends `T3512_SECS` (default 54 min, the TS 24.501 default).
  `t3512_octet_from_registration_accept` parses it back (tests).

### Implicit-deregistration sweep (`nf-amf`)

- `UeContext.retained_at` records when the context entered CM-IDLE (set when it's
  moved to `RETAINED` on AN release; cleared on a Service Request resume).
- `evict_stale_retained(amf_smf, max_idle)` removes retained contexts idle past
  `max_idle` and, for each, **releases every PDU session** at its SMF (freeing the
  UPF session and any buffered downlink) and **purges** its UECM serving-AMF
  registration + GUTI-directory entry. Collected under the lock, released off it.
- A background task sweeps every `RETAINED_SWEEP_SECS` (60 s) with the deadline
  `IMPLICIT_DEREG_SECS` = T3512 + 4 min, overridable via
  `RADIAN_AMF_IMPLICIT_DEREG_SECS`.

Together with the arc: a CM-IDLE UE either **resumes** (Service Request /
paging → taken out of `RETAINED`) or is **implicitly deregistered** once the
timer lapses — `RETAINED` no longer leaks.

## Boundaries / notes

- **Mobile-reachable = implicit-dereg (one deadline)** — TS 24.501 runs two
  chained timers (mobile-reachable, then implicit-dereg). Collapsed into a single
  `max_idle` window here; the two-stage split (and paging on the first) isn't
  modelled.
- **No periodic-registration re-arm on the AMF** — a UE doing periodic
  registration arrives as a fresh registration (a GUTI re-registration, design/60)
  which builds a new context; the sweep just stops seeing the old entry once it
  resumes/re-registers. (A stale entry from a UE that re-registers *without*
  resuming its old sessions would still wait out the deadline — acceptable.)
- **Not driven by free-ran-ue for the eviction** — the sim can't go CM-IDLE, so
  eviction is integration-tested; the T3512 IE *is* live-exercised (the @sim UE
  decodes the Registration Accept carrying it).

## Verification

- `cargo test --workspace --exclude bdd` — green (**144** tests). New:
  - nas `registration_accept_builds_and_decodes` extended — the T3512 octet
    (54 min) rides the accept and round-trips.
  - nf-amf `stale_retained_context_is_implicitly_deregistered` — a context idle
    past the deadline is evicted and its PDU session released at a mock SMF, while
    a freshly-idle context survives.
- **BDD 2 features / 5 scenarios / 25 steps green** — including the live @sim
  registration + ping, which now decodes a Registration Accept **carrying T3512**
  (proving the new IE is wire-valid to a real UE).

## Known limitations / next steps

- **Two-stage timer** (mobile-reachable → paging → implicit-dereg) and
  **T3513 paging retransmission**.
- **Periodic-registration handling** — treat a periodic Registration Update
  distinctly (re-arm rather than full re-auth) and reconcile it with any retained
  context for the same SUPI.
- **Registration-area-scoped paging / DRX** (from design/65's deferred list).
