//! Per-NF configuration files (design/147, G5).
//!
//! open5gs configures each NF from a YAML file; radian read **69 scattered
//! `RADIAN_*` env vars** inline instead (137/138 §3). This module is the foundation
//! for moving to one YAML file per NF while keeping every existing env var working
//! as an **override** — the precedence is **env var > config file > built-in
//! default**, so a deployment can adopt a config file incrementally and any
//! `RADIAN_*` still wins where set.
//!
//! An NF defines a `Deserialize + Default` config struct (fields `Option<T>`, absent
//! ⇒ fall through to env/default), [`load`]s it from its `RADIAN_<NF>_CONFIG` path,
//! and reads each effective setting with [`resolve`].

use anyhow::Context;
use serde::de::DeserializeOwned;

/// Load a per-NF YAML config from the path in `env_var` (e.g. `RADIAN_SMF_CONFIG`).
/// Returns `T::default()` when the var is unset — pure env/default mode, unchanged
/// from before G5. A set-but-unreadable or unparseable path is a **hard error**: a
/// misconfigured file must fail loudly at boot, never silently fall back to defaults.
pub fn load<T: DeserializeOwned + Default>(env_var: &str) -> anyhow::Result<T> {
    match std::env::var(env_var) {
        Ok(path) => {
            let text = std::fs::read_to_string(&path)
                .with_context(|| format!("read config file {path} (from {env_var})"))?;
            let cfg = serde_yml::from_str(&text)
                .with_context(|| format!("parse YAML config {path} (from {env_var})"))?;
            tracing::info!(%path, "loaded config from {env_var}");
            Ok(cfg)
        }
        Err(_) => Ok(T::default()),
    }
}

/// The effective value of one setting under the G5 precedence **env > file >
/// default**: the env var `key` (parsed as `T`) if set and valid, else the config
/// file's `file_value` if present, else `default`. So every existing `RADIAN_*`
/// override keeps working after an NF adopts a config file.
pub fn resolve<T: std::str::FromStr>(key: &str, file_value: Option<T>, default: T) -> T {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .or(file_value)
        .unwrap_or(default)
}

/// Like [`resolve`] but for an **optional** setting with no default: the env var if
/// set/valid, else the file value, else `None`. For settings that are genuinely
/// absent-by-default (e.g. an optional intermediate UPF, a usage-report threshold).
pub fn resolve_opt<T: std::str::FromStr>(key: &str, file_value: Option<T>) -> Option<T> {
    std::env::var(key).ok().and_then(|v| v.parse().ok()).or(file_value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, Default, Deserialize)]
    struct Demo {
        nrf: Option<String>,
        budget: Option<u64>,
    }

    /// A unique env key per test-case avoids cross-test interference (env is global).
    #[test]
    fn resolve_prefers_env_then_file_then_default() {
        // env unset, file present → file value.
        assert_eq!(resolve("RADIAN_TEST_G5_A", Some(7u64), 0), 7);
        // env unset, file absent → default.
        assert_eq!(resolve::<u64>("RADIAN_TEST_G5_B", None, 42), 42);
        // env set → env wins over the file value.
        // SAFETY: single-threaded test, key is unique to this case.
        unsafe { std::env::set_var("RADIAN_TEST_G5_C", "99") };
        assert_eq!(resolve("RADIAN_TEST_G5_C", Some(7u64), 0), 99);
        assert_eq!(resolve_opt::<u64>("RADIAN_TEST_G5_C", Some(7)), Some(99));
    }

    #[test]
    fn load_absent_env_is_default() {
        let cfg: Demo = load("RADIAN_TEST_G5_NO_SUCH_CONFIG").unwrap();
        assert!(cfg.nrf.is_none() && cfg.budget.is_none());
    }

    #[test]
    fn load_parses_yaml_and_a_bad_path_errors() {
        let dir = std::env::temp_dir();
        let path = dir.join("radian_g5_test.yaml");
        std::fs::write(&path, "nrf: http://nrf:8000\nbudget: 500\n").unwrap();
        // SAFETY: single-threaded test.
        unsafe { std::env::set_var("RADIAN_TEST_G5_CONFIG", path.to_str().unwrap()) };
        let cfg: Demo = load("RADIAN_TEST_G5_CONFIG").unwrap();
        assert_eq!(cfg.nrf.as_deref(), Some("http://nrf:8000"));
        assert_eq!(cfg.budget, Some(500));
        let _ = std::fs::remove_file(&path);

        // A set-but-missing path is a hard error (fail loud on misconfig).
        unsafe { std::env::set_var("RADIAN_TEST_G5_CONFIG", "/no/such/radian/config.yaml") };
        assert!(load::<Demo>("RADIAN_TEST_G5_CONFIG").is_err());
        unsafe { std::env::remove_var("RADIAN_TEST_G5_CONFIG") };
    }
}
