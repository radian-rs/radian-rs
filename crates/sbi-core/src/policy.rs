//! Shared policy-update primitives. A PCF policy update — access-and-mobility
//! ([`crate::npcf_am`]) or session-management ([`crate::npcf`]) — is a **partial**
//! delta (TS 29.507 / TS 29.512): only the attributes that changed are present, and
//! an attribute sent as JSON `null` is *removed*. [`FieldUpdate`] captures that
//! three-way distinction so both services share one wire convention.

use serde::{Deserialize, Serialize};

/// One attribute in a **partial** policy update: absent from the notification
/// (**keep** the receiver's current value), present as JSON `null` (**clear** it), or
/// present with a value (**set** it). Distinguishing *absent* from *null* is what
/// makes an update a partial delta rather than a full replacement — the PCF signals
/// only the attributes it changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldUpdate<T> {
    /// The attribute was omitted — keep whatever the receiver already has.
    Keep,
    /// The attribute was sent as `null` — remove it (fall back to the default).
    Clear,
    /// The attribute carried a value — set it.
    Set(T),
}

// Not `#[derive(Default)]`: that would add a spurious `T: Default` bound, breaking
// `FieldUpdate<Ambr>::default()` (an `Ambr` isn't `Default`) — which the `Keep`
// default never needs, since it carries no `T`.
#[allow(clippy::derivable_impls)]
impl<T> Default for FieldUpdate<T> {
    fn default() -> Self {
        FieldUpdate::Keep
    }
}

impl<T> FieldUpdate<T> {
    /// Resolve the delta against the receiver's `current` value: `Keep` leaves it,
    /// `Clear` removes it, `Set` replaces it.
    pub fn apply(self, current: Option<T>) -> Option<T> {
        match self {
            FieldUpdate::Keep => current,
            FieldUpdate::Clear => None,
            FieldUpdate::Set(v) => Some(v),
        }
    }

    /// Whether the attribute was omitted (used to skip it when serializing / to tell
    /// "not changed" from "changed").
    pub fn is_keep(&self) -> bool {
        matches!(self, FieldUpdate::Keep)
    }
}

impl<T: Clone + PartialEq> FieldUpdate<T> {
    /// The delta that carries `prev` to `next`: `Keep` when unchanged, `Set` for a new
    /// value, `Clear` when a value was removed.
    pub fn diff(prev: &Option<T>, next: &Option<T>) -> Self {
        match (prev == next, next) {
            (true, _) => FieldUpdate::Keep,
            (false, Some(v)) => FieldUpdate::Set(v.clone()),
            (false, None) => FieldUpdate::Clear,
        }
    }
}

/// Deserialize a present attribute into `Clear` (JSON `null`) or `Set` (a value). Only
/// called when the key is present; an absent key uses `Default` (`Keep`).
pub fn de_field_update<'de, D, T>(d: D) -> Result<FieldUpdate<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Ok(match Option::<T>::deserialize(d)? {
        None => FieldUpdate::Clear,
        Some(v) => FieldUpdate::Set(v),
    })
}

/// Serialize `Clear` as JSON `null` and `Set` as the value. `Keep` is never reached
/// here — `skip_serializing_if = "FieldUpdate::is_keep"` omits the key entirely.
pub fn ser_field_update<S, T>(v: &FieldUpdate<T>, s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
    T: Serialize,
{
    match v {
        FieldUpdate::Set(x) => x.serialize(s),
        FieldUpdate::Keep | FieldUpdate::Clear => s.serialize_none(),
    }
}
