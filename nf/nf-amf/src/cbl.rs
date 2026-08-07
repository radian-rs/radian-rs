//! "Come Back Later" (CBL) — admission pacing for AMF registration overload
//! (design/136), ported from the l5g_log_ai free5GC prototype
//! (`cbl_admission_pacing`).
//!
//! When the number of **in-progress registrations** C(t) reaches the admission
//! threshold M(t), a fresh `InitialUEMessage` is deferred instead of admitted:
//! the AMF answers with a small **SCTP-layer indication** (its own PPID, below
//! NGAP) telling the RAN exactly when the UE should come back, and the UE
//! re-attempts then with a fresh connection. Under a registration storm this
//! bounds the AMF's concurrent registration work instead of letting every
//! attempt in to time out and retry against an already-collapsing core.
//!
//! The threshold check and the counter increment are **one CAS**, so concurrent
//! handlers cannot admit past M(t) — no check-then-increment TOCTOU (the
//! prototype plan's P0-1 atomic check-and-reserve). C(t) can exceed M(t) only
//! when an operator lowers the threshold below the live count, which is legal:
//! existing admissions are kept, new admits stop, and the count converges as
//! slots free. `max_overshoot` records that event so a run can prove the
//! concurrent-admission bound held.
//!
//! Disabled unless `RADIAN_AMF_CBL_THRESHOLD` is set (or the OAM endpoint arms
//! it at runtime — `GET`/`POST /oam/v1/cbl` on the SBI surface).

use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use sctp_rs::{ConnectedSocket, SendData, SendInfo};
use tracing::{info, warn};

/// SCTP Payload Protocol Identifier for CBL indications on the N2 association.
/// MUST match the RAN side (free-ran-ue `constant.CBL_PPID`). "CB" = Come Back.
const CBL_PPID: u32 = 0xcb00_0000;
/// Payload magic. The RAN also branches on it directly: `0xCB, 0x01` never
/// begins a valid NGAP PDU (those start 0x00 / 0x20 / 0x40), so the indication
/// is recognisable however the PPID round-trips.
const CBL_MAGIC: [u8; 2] = [0xcb, 0x01];

const THRESHOLD_ENV: &str = "RADIAN_AMF_CBL_THRESHOLD";
const RETRY_MS_ENV: &str = "RADIAN_AMF_CBL_RETRY_MS";
const DECAY_SECS_ENV: &str = "RADIAN_AMF_CBL_DECAY_SECS";

/// Default retry timer handed to a deferred UE.
const DEFAULT_RETRY_MS: u32 = 2000;
/// Default slot lease: how long one UE may occupy an admission slot before it is
/// reclaimed as stale. Registration normally completes in well under a second;
/// this is a safety ceiling so a UE that silently disappears mid-registration
/// cannot leak C(t) and permanently throttle new admissions.
const DEFAULT_DECAY_SECS: u64 = 10;

/// The CBL admission gate: threshold, live count, and run counters.
pub struct CblState {
    enabled: AtomicBool,
    /// M(t) — the admission threshold.
    threshold: AtomicI64,
    /// C(t) — admitted, not-yet-completed registrations.
    ongoing: AtomicI64,
    /// Retry timer (ms) sent in the CBL indication.
    retry_ms: AtomicU32,
    /// Slot lease (ms); 0 = no lease (slots free only on completion/teardown).
    decay_ms: AtomicU64,
    admitted_total: AtomicU64,
    deferred_total: AtomicU64,
    /// Slots reclaimed by the lease — admitted registrations that never
    /// completed, the downstream-saturation signal in the prototype.
    stale_total: AtomicU64,
    /// Largest observed C(t) − M(t) at an admit or threshold change. Stays 0
    /// for concurrent admits (the CAS bounds them); positive only after an
    /// operator lowers M below the live count.
    max_overshoot: AtomicI64,
}

/// The gate, configured from the environment. Absent `RADIAN_AMF_CBL_THRESHOLD`
/// it starts disabled and can be armed over OAM.
pub static CBL: LazyLock<Arc<CblState>> = LazyLock::new(|| {
    fn env_parse<T: std::str::FromStr>(name: &str) -> Option<T> {
        std::env::var(name).ok().and_then(|v| v.parse().ok())
    }
    let threshold = env_parse::<i64>(THRESHOLD_ENV);
    let retry_ms = env_parse::<u32>(RETRY_MS_ENV).unwrap_or(DEFAULT_RETRY_MS);
    let decay_ms = env_parse::<u64>(DECAY_SECS_ENV).unwrap_or(DEFAULT_DECAY_SECS) * 1000;
    let state = CblState::with(threshold, retry_ms, decay_ms);
    if let Some(m) = threshold {
        info!(
            threshold = m,
            retry_ms,
            decay_ms,
            "CBL admission pacing armed ({THRESHOLD_ENV})"
        );
    }
    state
});

/// What the gate decided for one `InitialUEMessage`.
pub enum Admission {
    /// The gate is disabled — no slot accounting at all.
    Disabled,
    /// A slot was reserved; bind it to the UE context. Dropping it releases it.
    Admitted(CblSlot),
    /// At the threshold — defer, telling the UE to come back in `retry_ms`.
    Deferred { retry_ms: u32 },
}

impl CblState {
    fn with(threshold: Option<i64>, retry_ms: u32, decay_ms: u64) -> Arc<Self> {
        Arc::new(Self {
            enabled: AtomicBool::new(threshold.is_some()),
            threshold: AtomicI64::new(threshold.unwrap_or(0)),
            ongoing: AtomicI64::new(0),
            retry_ms: AtomicU32::new(retry_ms),
            decay_ms: AtomicU64::new(decay_ms),
            admitted_total: AtomicU64::new(0),
            deferred_total: AtomicU64::new(0),
            stale_total: AtomicU64::new(0),
            max_overshoot: AtomicI64::new(0),
        })
    }

    /// Atomic check-and-reserve: admit iff C(t) < M(t), reserving the slot in
    /// the same CAS as the threshold check (P0-1 — concurrent handlers cannot
    /// admit past M(t)).
    pub fn admit(self: &Arc<Self>) -> Admission {
        if !self.enabled.load(Ordering::Relaxed) {
            return Admission::Disabled;
        }
        loop {
            let cur = self.ongoing.load(Ordering::Relaxed);
            let m = self.threshold.load(Ordering::Relaxed);
            if cur >= m {
                self.deferred_total.fetch_add(1, Ordering::Relaxed);
                return Admission::Deferred { retry_ms: self.retry_ms.load(Ordering::Relaxed) };
            }
            if self.ongoing.compare_exchange(cur, cur + 1, Ordering::AcqRel, Ordering::Relaxed).is_ok()
            {
                self.admitted_total.fetch_add(1, Ordering::Relaxed);
                self.record_overshoot(cur + 1 - m);
                return Admission::Admitted(CblSlot::arm(self.clone()));
            }
            // CAS lost = a concurrent admit. Reload and retry.
        }
    }

    fn record_overshoot(&self, over: i64) {
        self.max_overshoot.fetch_max(over, Ordering::Relaxed);
    }

    fn set_threshold(&self, m: i64) {
        let old = self.threshold.swap(m, Ordering::Relaxed);
        // Lowering M below the live count is legal — existing admissions are
        // kept, only new admits stop — but record it as an overshoot event so
        // runs can tell it apart from a (structurally impossible) racing admit.
        self.record_overshoot(self.ongoing.load(Ordering::Relaxed) - m);
        info!(event = "cbl_threshold_set", old_threshold = old, new_threshold = m, "CBL threshold set");
    }

    /// Telemetry for `GET /oam/v1/cbl` — the seam an external controller (the
    /// l5g_log_ai MCP/LLM layer) reads to decide a threshold.
    pub fn snapshot(&self) -> serde_json::Value {
        serde_json::json!({
            "enable": self.enabled.load(Ordering::Relaxed),
            "threshold": self.threshold.load(Ordering::Relaxed),
            "ongoing_registrations": self.ongoing.load(Ordering::Relaxed),
            "retry_timer_ms": self.retry_ms.load(Ordering::Relaxed),
            "admitted_total": self.admitted_total.load(Ordering::Relaxed),
            "deferred_total": self.deferred_total.load(Ordering::Relaxed),
            "stale_total": self.stale_total.load(Ordering::Relaxed),
            "max_overshoot": self.max_overshoot.load(Ordering::Relaxed),
        })
    }

    /// Apply an OAM control body: `{"threshold": N}` arms the gate at N
    /// (optionally with `"retry_ms": M` and/or `"decay_ms": D` — the slot lease,
    /// applied to slots reserved from then on); `{"enable": false}` stands it
    /// down. Returns `false` when the body carries nothing applicable.
    pub fn apply_control(&self, body: &serde_json::Value) -> bool {
        let mut applied = false;
        if let Some(ms) = body.get("retry_ms").and_then(|v| v.as_u64()) {
            self.retry_ms.store(ms as u32, Ordering::Relaxed);
            applied = true;
        }
        if let Some(ms) = body.get("decay_ms").and_then(|v| v.as_u64()) {
            self.decay_ms.store(ms, Ordering::Relaxed);
            applied = true;
        }
        if let Some(m) = body.get("threshold").and_then(|v| v.as_i64()) {
            self.set_threshold(m);
            self.enabled.store(true, Ordering::Relaxed);
            applied = true;
        }
        if let Some(enable) = body.get("enable").and_then(|v| v.as_bool()) {
            self.enabled.store(enable, Ordering::Relaxed);
            info!(enable, "CBL admission pacing {}", if enable { "armed" } else { "stood down" });
            applied = true;
        }
        applied
    }
}

/// One reserved admission slot — a unit of C(t). Released **exactly once** on
/// the first of: the holding `UeContext` dropping it (registration complete, or
/// any teardown path — reject, release, association loss), or the decay lease
/// expiring (the admission went stale).
pub struct CblSlot(Arc<SlotLease>);

struct SlotLease {
    state: Arc<CblState>,
    released: AtomicBool,
}

impl SlotLease {
    fn release(&self, stale: bool) {
        if self.released.compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed).is_ok() {
            self.state.ongoing.fetch_sub(1, Ordering::AcqRel);
            if stale {
                self.state.stale_total.fetch_add(1, Ordering::Relaxed);
                warn!(
                    event = "cbl_stale",
                    ongoing_registrations = self.state.ongoing.load(Ordering::Relaxed),
                    "CBL: admission slot decayed before the registration completed"
                );
            }
        }
    }
}

impl CblSlot {
    fn arm(state: Arc<CblState>) -> Self {
        let lease = Arc::new(SlotLease { state: state.clone(), released: AtomicBool::new(false) });
        let decay_ms = state.decay_ms.load(Ordering::Relaxed);
        // 0 disables the lease. Outside a runtime (plain unit tests) there is no
        // timer to arm — the slot then frees only via its holder.
        if decay_ms > 0
            && let Ok(handle) = tokio::runtime::Handle::try_current()
        {
            let timer = lease.clone();
            handle.spawn(async move {
                tokio::time::sleep(Duration::from_millis(decay_ms)).await;
                timer.release(true);
            });
        }
        CblSlot(lease)
    }
}

impl Drop for CblSlot {
    fn drop(&mut self) {
        self.0.release(false);
    }
}

impl std::fmt::Debug for CblSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CblSlot")
    }
}

/// The CBL indication payload (big-endian, 10 bytes):
/// `magic[2] | RAN-UE-NGAP-ID u32 | retry timer ms u32` — must match the
/// free-ran-ue `gnb/cbl.go` decoder.
fn cbl_payload(ran_ue_id: u32, retry_ms: u32) -> [u8; 10] {
    let mut p = [0u8; 10];
    p[..2].copy_from_slice(&CBL_MAGIC);
    p[2..6].copy_from_slice(&ran_ue_id.to_be_bytes());
    p[6..10].copy_from_slice(&retry_ms.to_be_bytes());
    p
}

/// Send a CBL indication for `ran_ue_id` on the N2 association, at the SCTP
/// transport layer (below NGAP/NAS) with [`CBL_PPID`] so the gNB can branch on
/// the PPID before NGAP decoding.
pub async fn send_come_back_later(conn: &ConnectedSocket, ran_ue_id: u32, retry_ms: u32) {
    let send = SendData {
        payload: cbl_payload(ran_ue_id, retry_ms).to_vec(),
        snd_info: Some(SendInfo { ppid: CBL_PPID, ..Default::default() }),
    };
    match conn.sctp_send(send).await {
        Ok(()) => info!(
            event = "cbl_defer",
            ran_ue_ngap_id = ran_ue_id,
            retry_timer_ms = retry_ms,
            ongoing_registrations = CBL.ongoing.load(Ordering::Relaxed),
            threshold = CBL.threshold.load(Ordering::Relaxed),
            "Come Back Later: deferred new registration due to AMF overload"
        ),
        Err(e) => warn!("CBL indication send failed: {e:#}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// P0-1 acceptance: the one-CAS gate structurally bounds racing admits at M —
    /// concurrent-admission overshoot is zero, always.
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn concurrent_admits_never_exceed_the_threshold() {
        let state = CblState::with(Some(8), 2000, 60_000);
        let attempts: Vec<_> = (0..64)
            .map(|_| {
                let s = state.clone();
                tokio::spawn(async move { s.admit() })
            })
            .collect();
        let (mut slots, mut deferred) = (Vec::new(), 0);
        for a in attempts {
            match a.await.unwrap() {
                Admission::Admitted(slot) => slots.push(slot),
                Admission::Deferred { retry_ms } => {
                    assert_eq!(retry_ms, 2000);
                    deferred += 1;
                }
                Admission::Disabled => panic!("the gate is enabled"),
            }
        }
        assert_eq!(slots.len(), 8, "exactly M admits");
        assert_eq!(deferred, 56);
        assert_eq!(state.ongoing.load(Ordering::Relaxed), 8);
        assert_eq!(state.max_overshoot.load(Ordering::Relaxed), 0, "no racing overshoot");
        drop(slots);
        assert_eq!(state.ongoing.load(Ordering::Relaxed), 0, "released slots return");
        assert!(matches!(state.admit(), Admission::Admitted(_)), "freed capacity admits again");
    }

    /// The drop and the decay lease race to release — the slot frees exactly once.
    #[tokio::test]
    async fn a_slot_releases_exactly_once() {
        let state = CblState::with(Some(1), 2000, 20);
        let Admission::Admitted(slot) = state.admit() else { panic!("first admit") };
        drop(slot);
        assert_eq!(state.ongoing.load(Ordering::Relaxed), 0);
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert_eq!(state.ongoing.load(Ordering::Relaxed), 0, "late decay must not double-free");
        assert_eq!(state.stale_total.load(Ordering::Relaxed), 0);
    }

    /// A UE that vanishes mid-registration cannot leak C(t): the lease reclaims
    /// its slot as stale, and a later drop of the decayed slot is a no-op.
    #[tokio::test]
    async fn the_decay_lease_reclaims_a_stalled_slot() {
        let state = CblState::with(Some(1), 2000, 20);
        let Admission::Admitted(stalled) = state.admit() else { panic!("first admit") };
        assert!(matches!(state.admit(), Admission::Deferred { .. }), "at the threshold");
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert_eq!(state.ongoing.load(Ordering::Relaxed), 0, "the lease reclaimed the slot");
        assert_eq!(state.stale_total.load(Ordering::Relaxed), 1);
        let Admission::Admitted(second) = state.admit() else { panic!("reclaimed slot readmits") };
        drop(stalled); // the decayed admission completing late must not double-free
        assert_eq!(state.ongoing.load(Ordering::Relaxed), 1);
        drop(second);
        assert_eq!(state.ongoing.load(Ordering::Relaxed), 0);
    }

    /// Lowering M below the live count stops new admits, keeps existing ones, and
    /// is recorded as the (only legal) overshoot.
    #[tokio::test]
    async fn lowering_the_threshold_below_the_live_count() {
        let state = CblState::with(Some(2), 2000, 60_000);
        let Admission::Admitted(a) = state.admit() else { panic!() };
        let Admission::Admitted(b) = state.admit() else { panic!() };
        state.set_threshold(1);
        assert!(matches!(state.admit(), Admission::Deferred { .. }));
        assert_eq!(state.max_overshoot.load(Ordering::Relaxed), 1, "C−M recorded at the change");
        drop(a);
        assert!(matches!(state.admit(), Admission::Deferred { .. }), "still at the new threshold");
        drop(b);
        assert!(matches!(state.admit(), Admission::Admitted(_)), "below it again");
    }

    /// Golden bytes — must match free-ran-ue's `gnb/cbl.go` decoder.
    #[test]
    fn the_payload_matches_the_free_ran_ue_decoder() {
        assert_eq!(cbl_payload(7, 1500), [0xcb, 0x01, 0, 0, 0, 7, 0, 0, 0x05, 0xdc]);
    }

    /// OAM arms a disabled gate, adjusts it, and stands it down.
    #[test]
    fn oam_control_arms_and_stands_down_the_gate() {
        let state = CblState::with(None, DEFAULT_RETRY_MS, 0);
        assert!(matches!(state.admit(), Admission::Disabled));
        assert!(state.apply_control(&serde_json::json!({ "threshold": 0, "retry_ms": 1500 })));
        match state.admit() {
            Admission::Deferred { retry_ms } => assert_eq!(retry_ms, 1500),
            _ => panic!("threshold 0 defers everything"),
        }
        assert!(state.apply_control(&serde_json::json!({ "decay_ms": 250 })));
        assert_eq!(state.decay_ms.load(Ordering::Relaxed), 250, "lease retuned over OAM");
        assert!(state.apply_control(&serde_json::json!({ "enable": false })));
        assert!(matches!(state.admit(), Admission::Disabled));
        assert!(!state.apply_control(&serde_json::json!({ "nonsense": 1 })), "nothing applicable");
    }
}
