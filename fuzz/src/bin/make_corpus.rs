//! Regenerate the radian-built corpus seeds in `corpus/<target>/` (design/145).
//! Each seed is a golden message from the crates' own builders — the shapes the
//! NFs really exchange — so the fuzzers mutate from valid wire bytes instead of
//! discovering the framing from zero. open5gs-lifted seeds (`o5gs-*`) are
//! committed files, not regenerated here.

use std::net::Ipv4Addr;

fn write(target: &str, name: &str, bytes: &[u8]) {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("corpus").join(target);
    std::fs::create_dir_all(&dir).expect("create corpus dir");
    std::fs::write(dir.join(name), bytes).expect("write corpus seed");
    println!("{target}/{name}: {} bytes", bytes.len());
}

fn main() {
    let nas_reg_accept = nas::identity_request_suci();

    // NGAP — one seed per procedure family the AMF serves.
    let enc = |pdu: &ngap::NGAP_PDU| pdu.encode().expect("encode NGAP seed");
    write("ngap", "ng-setup-request", &enc(&ngap::ng_setup_request(1, "001", "01", &[[0, 0, 1]])));
    write("ngap", "ng-setup-response", &enc(&ngap::ng_setup_response("radian-amf", "001", "01")));
    write("ngap", "initial-ue-message", &enc(&ngap::initial_ue_message_with_nas(7, nas_reg_accept.clone())));
    write("ngap", "downlink-nas-transport", &enc(&ngap::downlink_nas_transport(1, 7, nas_reg_accept.clone())));
    write("ngap", "uplink-nas-transport", &enc(&ngap::uplink_nas_transport(1, 7, nas_reg_accept.clone())));
    write(
        "ngap",
        "ue-context-release-command",
        &enc(&ngap::ue_context_release_command(1, 7, ngap::CauseNas::DEREGISTER)),
    );
    write(
        "ngap",
        "ng-reset-partial",
        &enc(&ngap::ng_reset_partial(ngap::CauseRadioNetwork::UNSPECIFIED, &[(1, 7)])),
    );
    write(
        "ngap",
        "error-indication",
        &enc(&ngap::error_indication(Some(1), Some(7), ngap::CauseRadioNetwork::UNSPECIFIED)),
    );
    write("ngap", "paging", &enc(&ngap::paging(0x1234_5678, "001", "01", &[[0, 0, 1]])));
    write(
        "ngap",
        "overload-start",
        &enc(&ngap::overload_start(ngap::OverloadAction::REJECT_NON_EMERGENCY_MO_DT)),
    );

    // NAS-5GS — builders for the 5GMM messages radian exchanges.
    write("nas", "identity-request", &nas::identity_request_suci());
    write("nas", "authentication-request", &nas::authentication_request(0, &[0xAA; 16], &[0xBB; 16]));
    write("nas", "authentication-response", &nas::authentication_response(&[0xCC; 16]));

    // PFCP — the N4 messages the SMF really sends the UPF.
    write("pfcp", "association-setup-request", &pfcp::association_setup_request(Ipv4Addr::LOCALHOST, 1));
    write(
        "pfcp",
        "session-establishment-request",
        &pfcp::session_establishment_request(
            0xCAFE,
            2,
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::new(10, 45, 0, 2),
            "internet",
            Some(pfcp::SessionAmbr { uplink_bps: 1_000_000, downlink_bps: 2_000_000 }),
            &[pfcp::FlowQer {
                qfi: 2,
                filter: pfcp::FlowFilter::transport(17, 5000, 5010),
                mfbr_dl_bps: 80_000,
                mfbr_ul_bps: 80_000,
                gate: pfcp::Gate::OPEN,
            }],
            Some(1_000_000),
        ),
    );
    write(
        "pfcp",
        "session-modification-request",
        &pfcp::session_modification_request(1, 3, 2, 0x5678, Ipv4Addr::new(10, 0, 0, 9), "internet", true),
    );
    write("pfcp", "session-deletion-request", &pfcp::session_deletion_request(1, 4));

    // GTP-U — every frame shape the UPF/gNB emit.
    let ip_pkt = {
        let mut p = vec![0u8; 28];
        p[0] = 0x45;
        p
    };
    write("gtpu", "gpdu-plain", &gtpu::encap(0x42, &ip_pkt));
    write("gtpu", "gpdu-ul-qfi", &gtpu::encap_ul_qfi(0x42, 9, &ip_pkt));
    write("gtpu", "gpdu-dl-qfi", &gtpu::encap_dl_qfi(0x42, 5, true, &ip_pkt));
    write("gtpu", "echo-request", &gtpu::echo_request(7));
    write("gtpu", "echo-response", &gtpu::echo_response(7));
    write("gtpu", "end-marker", &gtpu::end_marker(0x42));
    write("gtpu", "f1u-dl-user-data", &gtpu::encap_f1u_dl_user_data(0x42, 3, b"pdcp-pdu"));
    write("gtpu", "f1u-delivery-status", &gtpu::encap_f1u_delivery_status(0x42, 65536));

    // RRC — the SRB0/SRB1 messages the CU/DU exchange with a UE.
    write("rrc", "rrc-setup-request", &rrc::rrc_setup_request(0x1234_5678_9A, 3));
    write("rrc", "rrc-setup", &rrc::rrc_setup(0, b"mcg".to_vec().as_slice()));
    write("rrc", "rrc-setup-complete", &rrc::rrc_setup_complete(0, 1, nas_reg_accept.clone()));
    write("rrc", "security-mode-command", &rrc::security_mode_command(1, 2, 2));
    write("rrc", "security-mode-complete", &rrc::security_mode_complete(1));
    write("rrc", "ul-information-transfer", &rrc::ul_information_transfer(nas_reg_accept.clone()));
    write("rrc", "dl-information-transfer", &rrc::dl_information_transfer(2, nas_reg_accept.clone()));
    write("rrc", "rrc-reconfiguration", &rrc::rrc_reconfiguration(3));
    write("rrc", "rrc-reconfiguration-complete", &rrc::rrc_reconfiguration_complete(3));

    // F1AP — the CU↔DU procedures the split gNB runs.
    write("f1ap", "f1-setup-request", &f1ap::f1_setup_request(1, 100));
    write("f1ap", "f1-setup-response", &f1ap::f1_setup_response(1));
    write(
        "f1ap",
        "initial-ul-rrc",
        &f1ap::initial_ul_rrc_message_transfer(9, "001", "01", 0x100, 0x4601, rrc::rrc_setup_request(1, 0)),
    );
    write("f1ap", "dl-rrc", &f1ap::dl_rrc_message_transfer(1, 9, 1, rrc::security_mode_command(1, 2, 2)));
    write("f1ap", "ul-rrc", &f1ap::ul_rrc_message_transfer(1, 9, 1, rrc::security_mode_complete(1)));
}
