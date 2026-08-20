# Per-NF config: UPF + AUSF on the design/147 foundation (G5)

> Built 2026-08-11 on branch `free5gc`. Extends **G5** — the per-NF YAML config
> foundation landed in [147](147-per-nf-config.md) (shared `common::config`, SMF
> as the reference NF) — to two more NFs: the **UPF** (datapath) and the **AUSF**
> (a simple SBI NF).

## Context

[147](147-per-nf-config.md) built the G5 base — `common::config::load(env_var)`
(reads the YAML file named by `RADIAN_<NF>_CONFIG`, hard-error on an unreadable/
unparseable file, `T::default()` when unset) plus `resolve(key, file, default)` /
`resolve_opt` for the **env > file > default** precedence — and converted the SMF
as the reference. The UPF and AUSF were still env-only; this slice brings them onto
the same base so the rollout pattern is proven on both NF shapes.

(This work was originally written against a separately-designed loader; on rebase it
was reworked onto [147](147-per-nf-config.md)'s foundation, which had landed in
parallel. The two are the same idea — this uses the merged one.)

## What this slice does

Each NF gains a flat `#[serde(rename_all = "kebab-case", deny_unknown_fields)]`
config struct of `Option<T>` fields, loaded via `common::config::load(CONFIG_ENV)`
and read with `resolve` — identical to the SMF pattern. Every existing `RADIAN_*`
env var still overrides its field, so nothing that relied on env config (the whole
BDD suite) changes.

- **UPF** — `UpfConfig`: `n3-addr`, `bind`, `max-sessions`, `n6-tun`, `n6-addr`,
  `n6-mask`, `n6-addr6`. The `n6-addr6: none` sentinel (a v4-only breakout anchor)
  works from the file as well as the env var. Because every `RADIAN_UPF_*` override
  is preserved, the multi-UPF / breakout BDD scenarios (which configure a second
  anchor entirely by env) are untouched.
- **AUSF** — `AusfConfig`: `sbi-port`, `nrf`, `udm`. Gains new
  `RADIAN_AUSF_{SBI_PORT,UDM}` overrides for values that were previously hard-coded
  constants — a small configurability win beyond parity.

Shipped sample files **`configs/upf.yaml`** and **`configs/ausf.yaml`** (same
`configs/` dir + kebab-case keys as `configs/smf.yaml`), each with a
`sample_config_matches_struct` test (`include_str!` + `serde_yml::from_str`) so
`deny_unknown_fields` catches any drift between the sample and the struct.

## Tests

- `nf-upf` / `nf-ausf` `sample_config_matches_struct` — the shipped `configs/*.yaml`
  parses into the struct with the expected values; a commented-out field stays absent.
- Live smoke: `RADIAN_AUSF_CONFIG=<file>` with `sbi-port: 8103` and
  `RADIAN_AUSF_SBI_PORT=8113` → the listener came up on **8113** (env > file > default).
- nf-upf / nf-ausf green; clippy clean; full build; BDD `n6_datapath`,
  `scripted_datapath`, `ulcl_breakout`, `ulcl_chain` pass (the env-override path is
  unchanged).

## Follow-ups (the rest of G5)

- The remaining NFs (UDR, NRF, UDM, PCF, CHF, NSSF, NEF) on the same pattern — each
  a `Config` struct + `configs/<nf>.yaml`, mechanical.
- **AMF is the deep one**: its PLMN / TAC / GUAMI / NAS-algorithm-order / T35xx values
  are compile-time `const`s used across ~7k lines; making them runtime config wants a
  `OnceLock`-initialised global, a larger refactor than the other NFs.
- Logger / metrics config blocks (pair with [G26](137-free5gc-422-gap-survey.md)).
