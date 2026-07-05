# Session Rules as a Keyed Partial Map (sessRules)

> Built 2026-07-04 on branch `feat/sm-session-rules`. Continues the SM-policy keyed-map
> restructure (design/112 did `chgDecs`): move the session AMBR out of a top-level scalar
> into **session rules** (`sessRules`, TS 29.512 §5.6.2.7) — a keyed map conveyed in an
> Update as a partial map (present = install/modify, `null` = remove, absent = keep).

## What was built

### `sbi-core` (`npcf`)

- **`SessionRule`** (TS 29.512 §5.6.2.7, trimmed) — carries `auth_sess_ambr` (the
  session AMBR).
- **`SmPolicyDecision.session_rules: HashMap<String, SessionRule>`** (`sessRules`)
  replaces the old `session_ambr: Option<SessionAmbrPolicy>` field.
  - **`session_ambr()`** — a derived accessor reading the effective AMBR from the
    session rules, so the datapath doesn't need to know the rule ids.
  - **`session_rules_for(ambr)`** — builds a single `"default"` rule from a flat AMBR
    (convenience for construction).
- **`SmPolicyUpdate.session_rules: HashMap<String, Option<SessionRule>>`** — the keyed
  partial map (replaces the `FieldUpdate<SessionAmbrPolicy>` from design/108).
- `diff`/`apply` now share one keyed-map delta implementation for **both** session rules
  and charging decisions: `diff_keyed` / `apply_keyed` (a `HashMap<String, T>` →
  `HashMap<String, Option<T>>` delta with install/modify/remove).
- The Update wire is `sessRules: {"rule-id": {"authSessAmbr": {...}}}`; a removal is
  `{"rule-id": null}`.

### `nf-smf`

- All policy session-AMBR reads move from the `.session_ambr` field to the
  `.session_ambr()` accessor (`ambr_bps`, the CreateSmContext response, the AMF modify
  body, the retained-context copy). The datapath (UPF QER, AMF signalling) is otherwise
  unchanged.
- The sm-data fallback builds `session_rules` via `session_rules_for`.

## Boundaries / notes

- **Wire reshape**: the UDR SM policy-data doc and the PCF↔SMF decision now use
  `sessRules` (with `authSessAmbr`) instead of a flat `sessionAmbr`. This does **not**
  touch the SMF's *Nudm sm-data* DNN config (which keeps its own `sessionAmbr`), nor the
  SMF→AMF modify body (kept `sessionAmbr` — a separate wire the AMF reads).
- `session_ambr()` reads *a* rule's AMBR (`find_map`) — well-defined for the normal
  single-session-rule case; a policy with two AMBR-bearing rules is not modelled.
- `SessionRule` is trimmed to `authSessAmbr`; `authDefQos` / usage-monitoring refs are
  follow-ups.

## Verification

- `cargo test --workspace --exclude bdd` — green (**205** tests, +1). New/updated:
  - sbi-core `session_rules_partial_map_and_ambr` — `session_ambr()` reads the default
    rule; `diff` installs a re-rated rule + adds one, `apply` merges, the wire carries
    `authSessAmbr`; removing the rule → `null`, and the effective AMBR is then `None`.
  - sbi-core `sm_policy_partial_diff_and_apply`, `pcf_sources_policy_from_udr_…` — moved
    to the `sessRules` shape (the AMBR change is now a session-rule delta; the UDR docs
    use `sessRules`/`authSessAmbr`).
  - nf-smf `refresh_policy_…` / `charging_…` — the UDR policy-data docs use `sessRules`;
    the derived AMBR still reaches the UPF QER + AMF body unchanged.
- `cargo clippy --workspace --exclude bdd` — no new warnings (parity with baseline).
- **BDD 1 feature / 2 scenarios / 10 steps green** (N6 datapath, clean teardown). BDD
  provisions no policy docs, so the wire reshape doesn't touch it.

## Known limitations / next steps

- **`pccRules` + `qosDecs`** — the remaining half: flows as first-class keyed PCC rules
  (rule id + precedence + flowInfos) referencing a keyed `qosDecs` map (5QI/ARP/GBR) and
  `chgDecs` by id. This is the larger change — it ripples into the SMF's per-flow QER /
  GFBR programming and the AMF's QoS-flow signalling — so it's kept separate.
- `SessionRule.authDefQos` (default QoS for the session) + usage-monitoring references.
