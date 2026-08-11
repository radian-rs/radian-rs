# Per-NF YAML config files (design/138 G5)

> Built 2026-08-11 on branch `g5-config`. Opens **G5** from
> [138](138-open5gs-gap-survey.md) §3 (config surface): give each NF a single YAML
> file instead of scattered `RADIAN_*` env vars. This slice lands the shared
> foundation and converts the **SMF** as the reference NF. The other ten NFs are a
> mechanical follow-up (see §Rollout).

## The gap

open5gs configures every NF from one YAML file (`smf.yaml`, `amf.yaml`, …).
radian read its settings from **~69 scattered `RADIAN_*` env vars**, each parsed
inline at the top of a `main()`
([138](138-open5gs-gap-survey.md) §3). That works for a one-container demo but
has no answer for "what is this NF's full configuration?" — there is no single
artifact to review, diff, or ship. A deployment can't hand-edit a file; it must
know all ten-odd env names and set them on the process.

The env vars themselves are fine — they're the right override mechanism for a
container. The gap is the absence of a **file** underneath them.

## What this slice does

A `common::config` module with three functions, and the SMF rebuilt on top:

```rust
fn load<T: DeserializeOwned + Default>(env_var: &str) -> Result<T>   // the file (or default)
fn resolve<T: FromStr>(key, file_value: Option<T>, default: T) -> T  // one required setting
fn resolve_opt<T: FromStr>(key, file_value: Option<T>) -> Option<T>  // one optional setting
```

- `load` reads the YAML file named by `RADIAN_<NF>_CONFIG`; **unset ⇒
  `T::default()`** (pure env/default mode, byte-for-byte the old behaviour). A
  set-but-unreadable or unparseable path is a **hard error** — a misconfigured
  file fails loudly at boot rather than silently reverting to defaults.
- `resolve` / `resolve_opt` give one setting's effective value under the
  precedence **env var > file > default**. Every existing `RADIAN_*` var keeps
  working and still **wins** where set.

Each NF defines a `Deserialize + Default` struct with `Option<T>` fields (absent
⇒ fall through), `load`s it once, and replaces each `std::env::var(X)` read with
`resolve("RADIAN_..._X", cfg.x, default)`.

### The SMF, converted

`SmfConfig` (kebab-case keys, `deny_unknown_fields`) covers all ten SMF settings
— `nrf`, `upf-n4`, the optional multi-UPF trio (`iupf-n4`, `psa2-n4`,
`ulcl-prefix`), `topology`, `advertise-addr`, the optional charging pair
(`gfbr-budget-mbps`, `usage-threshold-bytes`), and `heartbeat-secs`. A sample
lives at [`configs/smf.yaml`](../configs/smf.yaml). Behaviour is unchanged when
`RADIAN_SMF_CONFIG` is unset; when set, the file supplies defaults that any
`RADIAN_SMF_*` var still overrides.

## Decisions

- **D1 — precedence is env > file > default**, not file > env. A config file is
  the deployment baseline; a single env var is the targeted, per-container
  override on top of it. Reversing it would make a file silently mask an
  operator's explicit `RADIAN_*` — the surprising direction. It also makes
  adoption incremental and non-breaking: existing env-only deployments are
  untouched, and a file can be introduced setting-by-setting.
- **D2 — `serde_yml`**, matching open5gs's YAML (not TOML/JSON). Kebab-case keys
  read like open5gs's (`upf-n4`), easing side-by-side comparison.
- **D3 — a set-but-bad file is fatal.** The alternative (warn + fall back to
  defaults) turns a typo'd path into a silently mis-running NF. Booting to a
  loud error is the safer failure.
- **D4 — `deny_unknown_fields` + a test that parses the shipped sample.** A
  mistyped key (`upf_n4` vs `upf-n4`) becomes a parse error, and
  `sample_config_matches_struct` fails CI if `configs/smf.yaml` ever drifts from
  the struct.
- **D5 — SMF first, not AMF.** The AMF's PLMN (`mcc`/`mnc`) is a pervasive
  hardcoded `const &str` woven through 7.6k lines; converting it safely is its
  own slice. The SMF's settings are all local to `main()`, making it the clean
  reference conversion.

## Tests

- `common::config` — `resolve_prefers_env_then_file_then_default`,
  `load_absent_env_is_default`, `load_parses_yaml_and_a_bad_path_errors` (the
  hard-error path). 3 green.
- `nf-smf` — `sample_config_matches_struct` (the shipped `configs/smf.yaml`
  deserializes; guards against key drift) and `env_overrides_file_value` (the D1
  precedence, through the SMF's own `HEARTBEAT_SECS` setting). `nf-smf` 38 green.
- `cargo build -p nf-smf` clean; SMF behaviour with no `RADIAN_SMF_CONFIG` is
  unchanged.

## Rollout (the rest of G5)

- **The other ten NFs.** Each is the same mechanical pattern: define `<Nf>Config`,
  `load` it, swap `env::var` → `resolve`, ship `configs/<nf>.yaml`. AMF's PLMN
  const is the one non-mechanical case (D5) and gets its own slice.
- **A workspace `configs/` set** + a compose/manifest that points each
  `RADIAN_<NF>_CONFIG` at its file, so the full core has a reviewable
  configuration surface.
- **Structured (non-scalar) settings** — e.g. per-DNN IP pools
  ([G6](138-open5gs-gap-survey.md) follow-up) — become nested YAML here rather
  than new env vars.
