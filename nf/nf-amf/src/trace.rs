//! Per-UE trace correlation (the SUCI-keyed span map).
//!
//! A UE's registration + PDU-session-establishment flow spans many NGAP
//! messages and gNB round-trips, each handled in its own call into
//! [`handle_ngap`](crate::main). A **flow root span keyed by SUCI** ties the
//! per-procedure spans — and, through W3C context propagation
//! (`sbi_core::otel`), every SBI call the AMF makes on the UE's behalf — into
//! one trace. The root is created on first use and ended (dropped, so it
//! exports) when the flow completes: the `PDUSessionResourceSetupResponse`
//! lands, or the UE deregisters.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

use tracing::Span;

/// Live flow root spans, keyed by SUCI/SUPI.
static UE_SPANS: LazyLock<Mutex<HashMap<String, Span>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// The UE's flow root span, created (as a trace root) on first use.
pub fn ue_flow(suci: &str) -> Span {
    UE_SPANS
        .lock()
        .unwrap()
        .entry(suci.to_string())
        .or_insert_with(|| {
            tracing::info_span!(parent: None, "ue_flow", otel.name = %format!("UE {suci}"), suci = %suci)
        })
        .clone()
}

/// A procedure span under the UE's flow root — one NGAP/NAS handler entry.
pub fn procedure(suci: &str, name: &'static str) -> Span {
    let root = ue_flow(suci);
    tracing::info_span!(parent: &root, "procedure", otel.name = name, suci = %suci)
}

/// End the UE's flow: drop the root handle so the span closes (and exports)
/// once its outstanding procedure spans finish. A later [`ue_flow`] for the
/// same SUCI starts a fresh trace.
pub fn end_ue_flow(suci: &str) {
    UE_SPANS.lock().unwrap().remove(suci);
}
