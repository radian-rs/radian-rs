//! Fuzz bodies for radian's codec crates (design/145, G36) — one `run_*` per wire
//! surface, shared between the libFuzzer targets in `fuzz_targets/` and the
//! stable-toolchain corpus-replay regression test below.
//!
//! Each body drives the exact entry point the NFs feed network bytes into, and —
//! where a decode succeeds — re-encodes, so "decoded but unencodable" panics
//! surface too. The bodies must never panic on *any* input; a panic is a finding.
//! Corpora live in `corpus/<target>/`: radian-built golden messages (regenerate
//! with `cargo run --bin make_corpus`) plus seeds lifted from open5gs
//! `tests/fuzzing` (`nas_5gs`/`pfcp`/`gtp` — the same protocols radian speaks).

use std::net::Ipv4Addr;

/// NGAP: the AMF's N2 ingest (`NGAP_PDU::decode` on every SCTP datagram), plus a
/// re-encode of anything that decodes.
pub fn run_ngap(data: &[u8]) {
    if let Ok(pdu) = ngap::NGAP_PDU::decode(data) {
        let _ = pdu.encode();
    }
}

/// NAS-5GS: the top-level TS 24.501 decoder every N1 payload goes through, a
/// re-encode of anything that decodes, and the crate's hand-written TLV value
/// parsers that take raw IE bytes.
pub fn run_nas(data: &[u8]) {
    if let Ok(msg) = nas::decode_nas_5gs_message(data) {
        let _ = nas::gmm_message_type(&msg);
        let _ = nas::encode_nas_5gs_message(&msg);
    }
    let _ = nas::parse_authentication_request(data);
    let _ = nas::parse_nssai_value(data);
    let _ = nas::parse_rejected_nssai_value(data);
    let _ = nas::accept_5gsm_cause(data);
}

/// PFCP: the UPF's whole N4 ingest — `handle_n4` parses the message (rs-pfcp)
/// and walks every IE radian's dialect reads, against a fresh session table.
pub fn run_pfcp(data: &[u8]) {
    let mut state = pfcp::UpfState::new();
    let _ = pfcp::handle_n4(data, Ipv4Addr::LOCALHOST, &mut state, 0);
}

/// GTP-U: the N3/N9 datagram parser (extension-header chain walking), the F1-U
/// NR RAN Container variant, and the payload decap.
pub fn run_gtpu(data: &[u8]) {
    let _ = gtpu::parse(data);
    let _ = gtpu::parse_nr_ran_container(data);
    let _ = gtpu::decap(data);
}

/// RRC: the four logical-channel parsers the gNB/DU feed UE bytes into
/// (hampi-generated APER under each).
pub fn run_rrc(data: &[u8]) {
    let _ = rrc::parse_ul_ccch(data);
    let _ = rrc::parse_dl_ccch(data);
    let _ = rrc::parse_ul_dcch(data);
    let _ = rrc::parse_dl_dcch(data);
}

/// F1AP: the CU↔DU PDU decoder (hampi-generated APER).
pub fn run_f1ap(data: &[u8]) {
    let _ = f1ap::decode(data);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Replay every committed corpus seed through its fuzz body — a
    /// stable-toolchain regression net: any seed that once crashed a codec stays
    /// fatal here forever. (The libFuzzer targets need nightly; this doesn't.)
    #[test]
    fn corpus_replays_clean() {
        let targets: &[(&str, fn(&[u8]))] = &[
            ("ngap", run_ngap),
            ("nas", run_nas),
            ("pfcp", run_pfcp),
            ("gtpu", run_gtpu),
            ("rrc", run_rrc),
            ("f1ap", run_f1ap),
        ];
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("corpus");
        let mut replayed = 0usize;
        for (name, run) in targets {
            let dir = root.join(name);
            let entries = std::fs::read_dir(&dir)
                .unwrap_or_else(|e| panic!("corpus dir {} missing: {e}", dir.display()));
            for entry in entries {
                let path = entry.expect("read corpus entry").path();
                let bytes = std::fs::read(&path).expect("read corpus seed");
                run(&bytes);
                replayed += 1;
            }
        }
        assert!(replayed >= 30, "expected a seeded corpus, replayed only {replayed}");
    }
}
