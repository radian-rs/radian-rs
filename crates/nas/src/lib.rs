//! NAS — Non-Access Stratum (TS 24.501), the N1 protocol between UE and core.
//! 5GMM (mobility) is handled by the AMF; 5GSM (session) by the SMF.
//!
//! NAS is **hand-defined binary TLV/IEI — not ASN.1**. Carried transparently
//! inside NGAP on N2, and over the SBI as `application/vnd.3gpp.5gnas`.
//!
//! Thin re-export of [`oxirush_nas`], keeping the NAS codec behind this crate
//! boundary (see `design/02`). Primary entry points:
//! [`decode_nas_5gs_message`] / [`encode_nas_5gs_message`].

pub use oxirush_nas::*;

/// Build and encode a 5GMM **Identity Request** asking the UE for its SUCI
/// (TS 24.501 §8.2.20). The AMF can send this standalone — no AUSF/UDM needed.
pub fn identity_request_suci() -> Vec<u8> {
    let msg = Nas5gsMessage::new_5gmm(
        Nas5gmmMessageType::IdentityRequest,
        Nas5gmmMessage::IdentityRequest(messages::NasIdentityRequest::new(
            NasFGsIdentityType::from_identity_type(MobileIdentityType::Suci),
        )),
    );
    encode_nas_5gs_message(&msg).expect("encode 5GMM IdentityRequest")
}

/// Build and encode a 5GMM **Authentication Request** (TS 24.501 §8.2.1) carrying
/// the AKA challenge (RAND + AUTN) and the key set identifier (ngKSI).
pub fn authentication_request(ngksi: u8, rand: &[u8; 16], autn: &[u8; 16]) -> Vec<u8> {
    let req = messages::NasAuthenticationRequest::new(
        NasKeySetIdentifier::new(ngksi),
        NasAbba::new(vec![0x00, 0x00]),
    )
    .set_authentication_parameter_rand(NasAuthenticationParameterRand::new(rand.to_vec()))
    .set_authentication_parameter_autn(NasAuthenticationParameterAutn::new(autn.to_vec()));
    let msg = Nas5gsMessage::new_5gmm(
        Nas5gmmMessageType::AuthenticationRequest,
        Nas5gmmMessage::AuthenticationRequest(req),
    );
    encode_nas_5gs_message(&msg).expect("encode AuthenticationRequest")
}

/// Build and encode a 5GMM **Authentication Response** (TS 24.501 §8.2.2) carrying
/// RES*. Used by tests and a UE simulator.
pub fn authentication_response(res_star: &[u8]) -> Vec<u8> {
    let resp = messages::NasAuthenticationResponse::new().set_authentication_response_parameter(
        NasAuthenticationResponseParameter::new(res_star.to_vec()),
    );
    let msg = Nas5gsMessage::new_5gmm(
        Nas5gmmMessageType::AuthenticationResponse,
        Nas5gmmMessage::AuthenticationResponse(resp),
    );
    encode_nas_5gs_message(&msg).expect("encode AuthenticationResponse")
}

/// Extract (RAND, AUTN) from an encoded Authentication Request (UE side / tests).
pub fn parse_authentication_request(bytes: &[u8]) -> Option<([u8; 16], [u8; 16])> {
    let Nas5gsMessage::Gmm(_, Nas5gmmMessage::AuthenticationRequest(req)) =
        decode_nas_5gs_message(bytes).ok()?
    else {
        return None;
    };
    let rand = req.authentication_parameter_rand?.value.try_into().ok()?;
    let autn = req.authentication_parameter_autn?.value.try_into().ok()?;
    Some((rand, autn))
}

/// Build and encode a 5GMM **Authentication Failure** with cause
/// *synch failure* (#21) carrying the UE's **AUTS** (TS 24.501 §8.2.4). UE side
/// / tests — the UE sends this when the network's SQN is out of range.
pub fn authentication_failure_synch(auts: &[u8]) -> Vec<u8> {
    let fail = messages::NasAuthenticationFailure::new(NasFGmmCause::from_cause(
        GmmCause::SynchFailure,
    ))
    .set_authentication_failure_parameter(NasAuthenticationFailureParameter::new(auts.to_vec()));
    let msg = Nas5gsMessage::new_5gmm(
        Nas5gmmMessageType::AuthenticationFailure,
        Nas5gmmMessage::AuthenticationFailure(fail),
    );
    encode_nas_5gs_message(&msg).expect("encode AuthenticationFailure")
}

/// From a decoded **Authentication Failure**, the `(5GMM cause, optional AUTS)`.
/// The AUTS is present only on a synch failure (#21).
pub fn authentication_failure_info(msg: &Nas5gsMessage) -> Option<(u8, Option<Vec<u8>>)> {
    let Nas5gsMessage::Gmm(_, Nas5gmmMessage::AuthenticationFailure(fail)) = msg else {
        return None;
    };
    let cause = fail.fgmm_cause.value;
    let auts = fail.authentication_failure_parameter.as_ref().map(|p| p.value.clone());
    Some((cause, auts))
}

/// The 5GMM cause value for *synchronisation failure* (TS 24.501 §9.11.3.2).
pub const GMM_CAUSE_SYNCH_FAILURE: u8 = 0x15;

/// Extract RES* from a decoded Authentication Response, if present.
pub fn res_star_from_authentication_response(msg: &Nas5gsMessage) -> Option<&[u8]> {
    if let Nas5gsMessage::Gmm(_, Nas5gmmMessage::AuthenticationResponse(resp)) = msg {
        resp.authentication_response_parameter
            .as_ref()
            .map(|p| p.value.as_slice())
    } else {
        None
    }
}

/// Build a 5GMM **Security Mode Command** (TS 24.501 §8.2.25) selecting the NAS
/// algorithms (`nea`/`nia` identifiers), key set, and replayed UE capabilities.
pub fn security_mode_command(nea: u8, nia: u8, ngksi: u8, replayed_ue_sec_cap: &[u8]) -> Nas5gsMessage {
    let smc = messages::NasSecurityModeCommand::new(
        NasSecurityAlgorithms::new((nea << 4) | (nia & 0x0F)),
        NasKeySetIdentifier::new(ngksi),
        NasUeSecurityCapability::new(replayed_ue_sec_cap.to_vec()),
    );
    Nas5gsMessage::new_5gmm(
        Nas5gmmMessageType::SecurityModeCommand,
        Nas5gmmMessage::SecurityModeCommand(smc),
    )
}

/// Build a 5GMM **Security Mode Complete** (TS 24.501 §8.2.26). UE side / tests.
pub fn security_mode_complete() -> Nas5gsMessage {
    Nas5gsMessage::new_5gmm(
        Nas5gmmMessageType::SecurityModeComplete,
        Nas5gmmMessage::SecurityModeComplete(messages::NasSecurityModeComplete::new()),
    )
}

/// Encode a list of `(SST, optional SD)` slices as an NSSAI IE *value*
/// (TS 24.501 §9.11.3.37): each S-NSSAI is length-prefixed — `[1, sst]` or
/// `[4, sst, sd0, sd1, sd2]`.
pub fn nssai_value(slices: &[(u8, Option<[u8; 3]>)]) -> Vec<u8> {
    let mut v = Vec::with_capacity(slices.len() * 5);
    for (sst, sd) in slices {
        match sd {
            Some(sd) => {
                v.push(4);
                v.push(*sst);
                v.extend_from_slice(sd);
            }
            None => {
                v.push(1);
                v.push(*sst);
            }
        }
    }
    v
}

/// Decode an NSSAI IE *value* back into `(SST, optional SD)` slices (UE side /
/// tests). Entries with lengths other than 1 (SST) or 4 (SST+SD) are skipped
/// (mapped-HPLMN forms are not modeled).
pub fn parse_nssai_value(mut v: &[u8]) -> Vec<(u8, Option<[u8; 3]>)> {
    let mut out = Vec::new();
    while let Some((&len, rest)) = v.split_first() {
        let len = len as usize;
        if len == 0 || rest.len() < len {
            break;
        }
        match len {
            1 => out.push((rest[0], None)),
            4 => out.push((rest[0], Some([rest[1], rest[2], rest[3]]))),
            _ => {}
        }
        v = &rest[len..];
    }
    out
}

/// Rejection causes for the **rejected NSSAI** IE (TS 24.501 §9.11.3.46).
pub mod nssai_cause {
    /// The S-NSSAI is not available in the current PLMN (not subscribed).
    pub const NOT_AVAILABLE_IN_PLMN: u8 = 0;
}

/// Encode a **rejected NSSAI** IE *value* (TS 24.501 §9.11.3.46): each rejected
/// S-NSSAI is one octet `(contents-length << 4) | cause` followed by SST
/// (+ optional SD), with the same `cause` applied to every slice.
pub fn rejected_nssai_value(slices: &[(u8, Option<[u8; 3]>)], cause: u8) -> Vec<u8> {
    let mut v = Vec::with_capacity(slices.len() * 5);
    for (sst, sd) in slices {
        match sd {
            Some(sd) => {
                v.push((4 << 4) | (cause & 0x0F));
                v.push(*sst);
                v.extend_from_slice(sd);
            }
            None => {
                v.push((1 << 4) | (cause & 0x0F));
                v.push(*sst);
            }
        }
    }
    v
}

/// Decode a rejected NSSAI IE *value* into `((SST, optional SD), cause)` entries
/// (UE side / tests). Entries with contents-lengths other than 1 or 4 are skipped.
pub fn parse_rejected_nssai_value(mut v: &[u8]) -> Vec<((u8, Option<[u8; 3]>), u8)> {
    let mut out = Vec::new();
    while let Some((&head, rest)) = v.split_first() {
        let len = (head >> 4) as usize;
        let cause = head & 0x0F;
        if len == 0 || rest.len() < len {
            break;
        }
        match len {
            1 => out.push(((rest[0], None), cause)),
            4 => out.push(((rest[0], Some([rest[1], rest[2], rest[3]])), cause)),
            _ => {}
        }
        v = &rest[len..];
    }
    out
}

/// Extract the UE's **requested NSSAI** from a decoded Registration Request
/// (TS 24.501 §8.2.6, IEI 0x2F). Empty when the UE omitted the IE (the network
/// then grants the subscribed defaults).
pub fn requested_nssai_from_registration_request(msg: &Nas5gsMessage) -> Vec<(u8, Option<[u8; 3]>)> {
    let Nas5gsMessage::Gmm(_, Nas5gmmMessage::RegistrationRequest(reg)) = msg else {
        return Vec::new();
    };
    reg.requested_nssai.as_ref().map(|n| parse_nssai_value(&n.value)).unwrap_or_default()
}

/// The 5G-TMSI when a Registration Request identifies the UE by **5G-GUTI**
/// (TS 24.501 §5.5.1.2: a UE holding a valid GUTI registers with it, not its
/// SUCI). `None` when the mobile identity is another type.
pub fn guti_tmsi_from_registration_request(msg: &Nas5gsMessage) -> Option<u32> {
    let Nas5gsMessage::Gmm(_, Nas5gmmMessage::RegistrationRequest(reg)) = msg else {
        return None;
    };
    reg.fgs_mobile_identity.as_guti().map(|g| g.tmsi)
}

/// The 5G-TMSI the AMF assigned in a Registration Accept's 5G-GUTI IE — how the UE
/// (and tests) read a **reallocated** GUTI (TS 24.501 §5.4.1.3). `None` when the
/// accept carries no GUTI.
pub fn guti_tmsi_from_registration_accept(msg: &Nas5gsMessage) -> Option<u32> {
    let Nas5gsMessage::Gmm(_, Nas5gmmMessage::RegistrationAccept(accept)) = msg else {
        return None;
    };
    accept.fg_guti.as_ref().and_then(|g| g.as_guti()).map(|g| g.tmsi)
}

/// Build the null-protection-scheme SUCI mobile identity for `mcc`/`mnc`/`msin`
/// (TS 24.501 §9.11.3.4) — the inverse of what [`suci_to_supi`] deconceals.
fn suci_mobile_identity(mcc: &str, mnc: &str, msin: &str) -> NasFGsMobileIdentity {
    let plmn = PlmnId { mcc: mcc_digits(mcc), mnc: mnc_digits(mnc) };
    let mut value = vec![0x01]; // SUPI format IMSI, type SUCI
    value.extend_from_slice(&plmn.to_tbcd());
    value.extend_from_slice(&[0x00, 0x00]); // routing indicator "0000"
    value.push(0x00); // protection scheme: null
    value.push(0x00); // home network public key id
    // MSIN in BCD: low nibble first, 0xF filler on an odd digit count.
    let digits: Vec<u8> = msin.bytes().map(|b| b.wrapping_sub(b'0')).collect();
    for pair in digits.chunks(2) {
        let hi = pair.get(1).copied().unwrap_or(0x0F);
        value.push((hi << 4) | pair[0]);
    }
    NasFGsMobileIdentity::new(value)
}

/// Build and encode a 5GMM **Registration Request** identifying by 5G-GUTI
/// (UE side / tests): a returning UE re-registers with the GUTI a previous
/// Registration Accept assigned instead of exposing its SUCI.
pub fn registration_request_with_guti(
    mcc: &str,
    mnc: &str,
    tmsi: u32,
    ue_sec_cap: &[u8],
) -> Vec<u8> {
    let guti = NasFGsMobileIdentity::from_guti(&Guti {
        mcc: mcc_digits(mcc),
        mnc: mnc_digits(mnc),
        amf_region_id: 0x01,
        amf_set_id: 0x001,
        amf_pointer: 0x00,
        tmsi,
    });
    let reg = messages::NasRegistrationRequest::new(
        // Initial registration, ngKSI 7 (no key), no follow-on request.
        NasFGsRegistrationType::from_parts(RegistrationType::InitialRegistration, false, 7, false),
        guti,
    )
    .set_ue_security_capability(NasUeSecurityCapability::new(ue_sec_cap.to_vec()));
    let msg = Nas5gsMessage::new_5gmm(
        Nas5gmmMessageType::RegistrationRequest,
        Nas5gmmMessage::RegistrationRequest(reg),
    );
    encode_nas_5gs_message(&msg).expect("encode 5GMM RegistrationRequest (GUTI)")
}

/// Encode a two-octet **PDU session bitmap** — the shared value format of the
/// Uplink Data Status (TS 24.501 §9.11.3.57) and PDU Session Status (§9.11.3.44)
/// IEs: bit `n` marks PDU session `n` (octet 3 = PSI 0–7, octet 4 = PSI 8–15).
/// PSI 0 is spare.
fn psi_bitmap_value(psis: &[u8]) -> Vec<u8> {
    let mut bits = [0u8; 2];
    for &psi in psis {
        if psi < 16 {
            bits[(psi / 8) as usize] |= 1 << (psi % 8);
        }
    }
    bits.to_vec()
}

/// The PDU session ids set in a two-octet PDU session bitmap value (ascending).
fn psis_from_psi_bitmap(value: &[u8]) -> Vec<u8> {
    let mut psis = Vec::new();
    for (byte, &b) in value.iter().take(2).enumerate() {
        for bit in 0..8u8 {
            if b & (1 << bit) != 0 {
                psis.push((byte as u8) * 8 + bit);
            }
        }
    }
    psis
}

/// Build a 5GMM **Registration Request** of `reg_type`, identifying by 5G-GUTI,
/// integrity-protected under the current security context (ngKSI 0). When
/// `uplink_data_psis` is non-empty, the **Uplink Data Status** IE lists the PDU
/// sessions with pending uplink data (the network reactivates their user plane).
/// UE side / tests.
fn registration_request_of_type(
    reg_type: RegistrationType,
    mcc: &str,
    mnc: &str,
    tmsi: u32,
    uplink_data_psis: &[u8],
) -> Nas5gsMessage {
    let guti = NasFGsMobileIdentity::from_guti(&Guti {
        mcc: mcc_digits(mcc),
        mnc: mnc_digits(mnc),
        amf_region_id: 0x01,
        amf_set_id: 0x001,
        amf_pointer: 0x00,
        tmsi,
    });
    let mut reg = messages::NasRegistrationRequest::new(
        NasFGsRegistrationType::from_parts(reg_type, false, 0, false),
        guti,
    );
    if !uplink_data_psis.is_empty() {
        reg = reg.set_uplink_data_status(NasUplinkDataStatus::new(psi_bitmap_value(
            uplink_data_psis,
        )));
    }
    Nas5gsMessage::new_5gmm(
        Nas5gmmMessageType::RegistrationRequest,
        Nas5gmmMessage::RegistrationRequest(reg),
    )
}

/// A 5GMM Registration Request of type *mobility registration updating*
/// (TS 24.501 §5.5.1.3) — what a UE sends when it enters a tracking area outside
/// its registration area (UE side / tests).
pub fn registration_request_mobility(mcc: &str, mnc: &str, tmsi: u32) -> Nas5gsMessage {
    registration_request_of_type(RegistrationType::MobilityRegistrationUpdate, mcc, mnc, tmsi, &[])
}

/// A 5GMM Registration Request of type *periodic registration updating*
/// (TS 24.501 §5.5.1.3.2) — what a UE sends when T3512 expires to prove it is still
/// reachable, without moving (UE side / tests).
pub fn registration_request_periodic(mcc: &str, mnc: &str, tmsi: u32) -> Nas5gsMessage {
    registration_request_of_type(RegistrationType::PeriodicRegistrationUpdate, mcc, mnc, tmsi, &[])
}

/// A registration update carrying an **Uplink Data Status** IE listing the PDU
/// sessions the UE has pending uplink data for (UE side / tests).
pub fn registration_request_with_uplink_data(
    reg_type: RegistrationType,
    mcc: &str,
    mnc: &str,
    tmsi: u32,
    psis: &[u8],
) -> Nas5gsMessage {
    registration_request_of_type(reg_type, mcc, mnc, tmsi, psis)
}

/// The PDU sessions the UE flagged in a Registration Request's **Uplink Data
/// Status** IE (TS 24.501 §9.11.3.57) — the network reactivates their user plane.
/// Empty when the IE is absent.
pub fn uplink_data_status_from_registration_request(msg: &Nas5gsMessage) -> Vec<u8> {
    let Nas5gsMessage::Gmm(_, Nas5gmmMessage::RegistrationRequest(reg)) = msg else {
        return Vec::new();
    };
    reg.uplink_data_status
        .as_ref()
        .map(|u| psis_from_psi_bitmap(&u.value))
        .unwrap_or_default()
}

/// The PDU sessions the UE reports as **still active** in its **PDU Session Status**
/// IE (TS 24.501 §9.11.3.44), from a decoded Service Request or Registration
/// Request — the AMF releases any session it tracks that the UE has dropped.
/// `None` when the IE is absent (the UE reported nothing — leave every session
/// intact); `Some(psis)` (possibly empty) is the authoritative UE view.
pub fn pdu_session_status_from_request(msg: &Nas5gsMessage) -> Option<Vec<u8>> {
    let status = match msg {
        Nas5gsMessage::Gmm(_, Nas5gmmMessage::ServiceRequest(req)) => req.pdu_session_status.as_ref(),
        Nas5gsMessage::Gmm(_, Nas5gmmMessage::RegistrationRequest(reg)) => {
            reg.pdu_session_status.as_ref()
        }
        _ => return None,
    };
    status.map(|s| psis_from_psi_bitmap(&s.value))
}

/// The PDU sessions the network reports as **active** in a Service Accept's or
/// Registration Accept's **PDU Session Status** IE (TS 24.501 §9.11.3.44) — the UE
/// locally releases any session it holds that the network does not list. `None`
/// when the IE is absent. UE side / tests.
pub fn pdu_session_status_from_accept(msg: &Nas5gsMessage) -> Option<Vec<u8>> {
    let status = match msg {
        Nas5gsMessage::Gmm(_, Nas5gmmMessage::ServiceAccept(acc)) => acc.pdu_session_status.as_ref(),
        Nas5gsMessage::Gmm(_, Nas5gmmMessage::RegistrationAccept(acc)) => {
            acc.pdu_session_status.as_ref()
        }
        _ => return None,
    };
    status.map(|s| psis_from_psi_bitmap(&s.value))
}

/// The registration type of a decoded Registration Request (TS 24.501 §9.11.3.7) —
/// initial / mobility updating / periodic updating / … `None` for other messages.
pub fn registration_type_from_request(msg: &Nas5gsMessage) -> Option<RegistrationType> {
    let Nas5gsMessage::Gmm(_, Nas5gmmMessage::RegistrationRequest(reg)) = msg else {
        return None;
    };
    reg.fgs_registration_type.registration_type()
}

/// Build and encode a 5GMM **Identity Response** (TS 24.501 §8.2.22) carrying the
/// UE's null-scheme SUCI — the answer to an Identity Request. UE side / tests.
pub fn identity_response_suci(mcc: &str, mnc: &str, msin: &str) -> Vec<u8> {
    let msg = Nas5gsMessage::new_5gmm(
        Nas5gmmMessageType::IdentityResponse,
        Nas5gmmMessage::IdentityResponse(messages::NasIdentityResponse::new(
            suci_mobile_identity(mcc, mnc, msin),
        )),
    );
    encode_nas_5gs_message(&msg).expect("encode 5GMM IdentityResponse")
}

/// The SUPI (deconcealed null-scheme SUCI) from an Identity Response — how the
/// AMF resumes a registration it paused on an Identity Request.
pub fn supi_from_identity_response(msg: &Nas5gsMessage) -> Option<String> {
    let Nas5gsMessage::Gmm(_, Nas5gmmMessage::IdentityResponse(resp)) = msg else {
        return None;
    };
    resp.mobile_identity.as_suci().map(|s| suci_to_supi(&s))
}

/// Build a 5GMM **Registration Accept** (TS 24.501 §8.2.7) assigning a 5G-GUTI,
/// with the **allowed NSSAI** (IEI 0x15) when the network grants any slices and
/// the **rejected NSSAI** (IEI 0x11, cause *not available in the current PLMN*)
/// for requested slices the subscription doesn't cover (design/32, design/33).
///
/// `active_pdu_sessions` carries the network's **PDU Session Status** IE
/// (§9.11.3.44) when `Some` — the sessions the network considers active, so the UE
/// releases any it holds that are not listed (reconciliation on a registration
/// update). `None` omits the IE (initial registration — no sessions yet).
pub fn registration_accept(
    mcc: &str,
    mnc: &str,
    tmsi: u32,
    allowed_nssai: &[(u8, Option<[u8; 3]>)],
    rejected_nssai: &[(u8, Option<[u8; 3]>)],
    t3512_secs: u32,
    registration_area: &[[u8; 3]],
    active_pdu_sessions: Option<&[u8]>,
) -> Nas5gsMessage {
    let guti = NasFGsMobileIdentity::from_guti(&Guti {
        mcc: mcc_digits(mcc),
        mnc: mnc_digits(mnc),
        amf_region_id: 0x01,
        amf_set_id: 0x001,
        amf_pointer: 0x00,
        tmsi,
    });
    // T3512 (IEI 0x5E): the periodic-registration timer — the UE re-registers when
    // it expires, so the AMF knows a UE that goes silent is unreachable (its
    // retained CM-IDLE context can be implicitly deregistered).
    let mut accept = messages::NasRegistrationAccept::new(NasFGsRegistrationResult::new(vec![0x01]))
        .set_fg_guti(guti)
        .set_t3512_value(NasGprsTimer3::new(vec![GprsTimer3::from_secs(t3512_secs).octet()]));
    // 5GS TAI list (IEI 0x54): the UE's registration area — it may move among
    // these tracking areas without a mobility registration update, and paging is
    // scoped to them.
    if !registration_area.is_empty() {
        accept = accept.set_tai_list(NasFGsTrackingAreaIdentityList::new(tai_list_value(
            mcc,
            mnc,
            registration_area,
        )));
    }
    if !allowed_nssai.is_empty() {
        accept = accept.set_allowed_nssai(NasNssai::new(nssai_value(allowed_nssai)));
    }
    if !rejected_nssai.is_empty() {
        accept = accept.set_rejected_nssai(NasRejectedNssai::new(rejected_nssai_value(
            rejected_nssai,
            nssai_cause::NOT_AVAILABLE_IN_PLMN,
        )));
    }
    // PDU session status (IEI 0x50): the network's authoritative active-session set,
    // so the UE releases any session it holds that the network dropped.
    if let Some(active) = active_pdu_sessions {
        accept = accept.set_pdu_session_status(NasPduSessionStatus::new(psi_bitmap_value(active)));
    }
    Nas5gsMessage::new_5gmm(
        Nas5gmmMessageType::RegistrationAccept,
        Nas5gmmMessage::RegistrationAccept(accept),
    )
}

/// Encode a 5GS tracking area identity list value (TS 24.501 §9.11.3.9) as one
/// **type-00 partial list** — non-consecutive TACs belonging to one PLMN:
/// `[0(spare) | 00(type) | NNNNN(count-1)] [PLMN TBCD ×3] [TAC ×3]…`. A partial
/// list holds at most 16 TACs; excess is truncated.
fn tai_list_value(mcc: &str, mnc: &str, tacs: &[[u8; 3]]) -> Vec<u8> {
    let tacs = &tacs[..tacs.len().min(16)];
    let plmn = PlmnId { mcc: mcc_digits(mcc), mnc: mnc_digits(mnc) };
    let mut value = vec![(tacs.len() as u8 - 1) & 0x1F];
    value.extend_from_slice(&plmn.to_tbcd());
    for tac in tacs {
        value.extend_from_slice(tac);
    }
    value
}

/// The registration area (TAC list) from a decoded Registration Accept's 5GS TAI
/// list IE — type-00 partial list only (UE side / tests). `None` when absent or
/// not type-00.
pub fn registration_area_from_registration_accept(msg: &Nas5gsMessage) -> Option<Vec<[u8; 3]>> {
    let Nas5gsMessage::Gmm(_, Nas5gmmMessage::RegistrationAccept(accept)) = msg else {
        return None;
    };
    let value = &accept.tai_list.as_ref()?.value;
    // Octet 0: spare + list type (bits 6-5) + element count - 1 (bits 4-0).
    if value.len() < 7 || (value[0] >> 5) & 0b11 != 0b00 {
        return None;
    }
    let n = (value[0] & 0x1F) as usize + 1;
    let tacs = &value[4..]; // past the header octet + 3-octet PLMN
    Some(tacs.chunks_exact(3).take(n).map(|c| [c[0], c[1], c[2]]).collect())
}

/// Extract the allowed NSSAI from a decoded Registration Accept (UE side / tests).
pub fn allowed_nssai_from_registration_accept(msg: &Nas5gsMessage) -> Vec<(u8, Option<[u8; 3]>)> {
    let Nas5gsMessage::Gmm(_, Nas5gmmMessage::RegistrationAccept(accept)) = msg else {
        return Vec::new();
    };
    accept.allowed_nssai.as_ref().map(|n| parse_nssai_value(&n.value)).unwrap_or_default()
}

/// The T3512 (periodic-registration) timer octet from a decoded Registration
/// Accept, if present (UE side / tests) — compare against [`GprsTimer3::octet`].
pub fn t3512_octet_from_registration_accept(msg: &Nas5gsMessage) -> Option<u8> {
    let Nas5gsMessage::Gmm(_, Nas5gmmMessage::RegistrationAccept(accept)) = msg else {
        return None;
    };
    accept.t3512_value.as_ref()?.value.first().copied()
}

/// Extract the rejected NSSAI (with causes) from a decoded Registration Accept
/// (UE side / tests).
pub fn rejected_nssai_from_registration_accept(
    msg: &Nas5gsMessage,
) -> Vec<((u8, Option<[u8; 3]>), u8)> {
    let Nas5gsMessage::Gmm(_, Nas5gmmMessage::RegistrationAccept(accept)) = msg else {
        return Vec::new();
    };
    accept.rejected_nssai.as_ref().map(|n| parse_rejected_nssai_value(&n.value)).unwrap_or_default()
}

/// 5GMM cause values (TS 24.501 §9.11.3.2) this stack emits.
pub mod mm_cause {
    /// #62 — no network slices available.
    pub const NO_NETWORK_SLICES_AVAILABLE: u8 = 62;
}

/// Whether a decoded 5GMM **Deregistration Request (UE originating)**
/// (TS 24.501 §8.2.12) asks for **switch-off** (bit 4 of the de-registration
/// type, §9.11.3.20) — a switched-off UE expects no Deregistration Accept.
pub fn deregistration_is_switch_off(msg: &Nas5gsMessage) -> Option<bool> {
    let Nas5gsMessage::Gmm(_, Nas5gmmMessage::DeregistrationRequestFromUe(req)) = msg else {
        return None;
    };
    Some(req.de_registration_type.value & 0x08 != 0)
}

/// Build a 5GMM **Deregistration Accept (UE originating)** (TS 24.501 §8.2.13) —
/// header-only.
pub fn deregistration_accept() -> Nas5gsMessage {
    Nas5gsMessage::new_5gmm(
        Nas5gmmMessageType::DeregistrationAcceptFromUe,
        Nas5gmmMessage::DeregistrationAcceptFromUe(messages::NasDeregistrationAcceptFromUe::new()),
    )
}

/// Build a 5GMM **Deregistration Request (UE originating)**. UE side / tests.
/// `dereg_type` is the §9.11.3.20 half-octet (bit 4 = switch-off, bits 2-1 =
/// access type) with ngKSI in the high nibble.
pub fn deregistration_request_from_ue(dereg_type: u8, mcc: &str, mnc: &str, tmsi: u32) -> Nas5gsMessage {
    let identity = NasFGsMobileIdentity::from_guti(&Guti {
        mcc: mcc_digits(mcc),
        mnc: mnc_digits(mnc),
        amf_region_id: 0x01,
        amf_set_id: 0x001,
        amf_pointer: 0x00,
        tmsi,
    });
    let req = messages::NasDeregistrationRequestFromUe::new(
        NasDeRegistrationType::new(dereg_type),
        identity,
    );
    Nas5gsMessage::new_5gmm(
        Nas5gmmMessageType::DeregistrationRequestFromUe,
        Nas5gmmMessage::DeregistrationRequestFromUe(req),
    )
}

/// Build a 5GMM **Service Request** (TS 24.501 §8.2.16) — a CM-IDLE UE resuming
/// its N2 connection. `service_type` (§9.11.3.50: 0 signalling, 1 data) and `ngksi`
/// share octet 4 (service type in the high nibble); the UE is identified by its
/// **5G-S-TMSI**. UE side / tests. (This message is integrity-protected in flight.)
pub fn service_request(service_type: u8, ngksi: u8, tmsi: u32) -> Vec<u8> {
    let stmsi = NasFGsMobileIdentity::from_s_tmsi(&STmsi {
        amf_set_id: 0x001,
        amf_pointer: 0x00,
        tmsi,
    });
    let req = messages::NasServiceRequest::new(
        NasKeySetIdentifier::new(((service_type & 0x07) << 4) | (ngksi & 0x07)),
        stmsi,
    );
    let msg = Nas5gsMessage::new_5gmm(
        Nas5gmmMessageType::ServiceRequest,
        Nas5gmmMessage::ServiceRequest(req),
    );
    encode_nas_5gs_message(&msg).expect("encode ServiceRequest")
}

/// A **Service Request** carrying a **PDU Session Status** IE (TS 24.501
/// §9.11.3.44) listing the PDU sessions the UE still considers active — the AMF
/// releases any session it tracks that the UE has locally dropped. UE side / tests.
pub fn service_request_with_pdu_status(
    service_type: u8,
    ngksi: u8,
    tmsi: u32,
    active_psis: &[u8],
) -> Vec<u8> {
    let stmsi = NasFGsMobileIdentity::from_s_tmsi(&STmsi {
        amf_set_id: 0x001,
        amf_pointer: 0x00,
        tmsi,
    });
    let req = messages::NasServiceRequest::new(
        NasKeySetIdentifier::new(((service_type & 0x07) << 4) | (ngksi & 0x07)),
        stmsi,
    )
    .set_pdu_session_status(NasPduSessionStatus::new(psi_bitmap_value(active_psis)));
    let msg = Nas5gsMessage::new_5gmm(
        Nas5gmmMessageType::ServiceRequest,
        Nas5gmmMessage::ServiceRequest(req),
    );
    encode_nas_5gs_message(&msg).expect("encode ServiceRequest (PDU Session Status)")
}

/// From a decoded **Service Request**, the `(service_type, 5G-TMSI)`. The AMF uses
/// the 5G-TMSI to find the UE's retained CM-IDLE context.
pub fn service_request_info(msg: &Nas5gsMessage) -> Option<(u8, u32)> {
    let Nas5gsMessage::Gmm(_, Nas5gmmMessage::ServiceRequest(req)) = msg else {
        return None;
    };
    let service_type = (req.ngksi.value >> 4) & 0x07;
    let tmsi = req.fg_s_tmsi.tmsi()?;
    Some((service_type, tmsi))
}

/// Build a 5GMM **Service Accept** (TS 24.501 §8.2.17) — the AMF's answer resuming
/// the UE's connection. `active_pdu_sessions` carries the **PDU Session Status** IE
/// (§9.11.3.44) when `Some`: the sessions the network kept active, so the UE
/// releases any it holds that the network dropped. The reactivated sessions are
/// re-established over N2 alongside it.
pub fn service_accept(active_pdu_sessions: Option<&[u8]>) -> Nas5gsMessage {
    let mut accept = messages::NasServiceAccept::new();
    if let Some(active) = active_pdu_sessions {
        accept = accept.set_pdu_session_status(NasPduSessionStatus::new(psi_bitmap_value(active)));
    }
    Nas5gsMessage::new_5gmm(
        Nas5gmmMessageType::ServiceAccept,
        Nas5gmmMessage::ServiceAccept(accept),
    )
}

/// Build a 5GMM **Deregistration Accept (UE terminated)** (TS 24.501 §8.2.15) —
/// the UE's answer to a network-initiated deregistration. UE side / tests.
pub fn deregistration_accept_to_ue() -> Nas5gsMessage {
    Nas5gsMessage::new_5gmm(
        Nas5gmmMessageType::DeregistrationAcceptToUe,
        Nas5gmmMessage::DeregistrationAcceptToUe(messages::NasDeregistrationAcceptToUe::new()),
    )
}

/// Build a 5GMM **Deregistration Request (UE terminated)** (TS 24.501 §8.2.14) —
/// network-initiated. `dereg_type` is the §9.11.3.20 half-octet; for a
/// subscription withdrawal use `0x01` (re-registration not required, 3GPP access).
pub fn deregistration_request_to_ue(dereg_type: u8) -> Nas5gsMessage {
    let req =
        messages::NasDeregistrationRequestToUe::new(NasDeRegistrationType::new(dereg_type));
    Nas5gsMessage::new_5gmm(
        Nas5gmmMessageType::DeregistrationRequestToUe,
        Nas5gmmMessage::DeregistrationRequestToUe(req),
    )
}

/// GPRS Timer 2 (TS 24.008 §10.5.7.4): one octet holding a 3-bit unit (bits 6-8)
/// and a 5-bit multiple (bits 1-5) — coarser than [`GprsTimer3`] (units 2s /
/// 1min / decihour). Carried as the **T3346 value** IE in 5GMM rejects: the UE
/// must not re-attempt registration until it expires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GprsTimer2(u8);

impl GprsTimer2 {
    /// Encode a duration, choosing the finest unit whose 5-bit multiple fits and
    /// rounding up — the UE backs off *at least* `secs`. Durations beyond the
    /// encodable maximum (31 decihours) clamp to it.
    pub fn from_secs(secs: u32) -> Self {
        // (unit bits, seconds per step): 2s, 1min, decihour (6min).
        const UNITS: [(u8, u32); 3] = [(0b000, 2), (0b001, 60), (0b010, 360)];
        for (unit, step) in UNITS {
            let multiple = secs.div_ceil(step);
            if multiple <= 31 {
                return Self((unit << 5) | multiple as u8);
            }
        }
        Self((0b010 << 5) | 31)
    }

    /// The timer-deactivated encoding (unit 0b111).
    pub fn deactivated() -> Self {
        Self(0b111_00000)
    }

    /// The raw value octet as it appears on the wire.
    pub fn octet(self) -> u8 {
        self.0
    }
}

/// Build a 5GMM **Registration Reject** (TS 24.501 §8.2.9) with `cause` (pick from
/// [`mm_cause`]), the **rejected NSSAI** when non-empty (IEI 0x69, cause *not
/// available in the current PLMN*) so the UE learns which slices were refused,
/// and optionally the **T3346 value** IE (IEI 0x5F) holding the UE off from an
/// immediate re-registration.
pub fn registration_reject(
    cause: u8,
    rejected_nssai: &[(u8, Option<[u8; 3]>)],
    backoff: Option<GprsTimer2>,
) -> Nas5gsMessage {
    let mut reject = messages::NasRegistrationReject::new(NasFGmmCause::new(cause));
    if !rejected_nssai.is_empty() {
        reject = reject.set_rejected_nssai(NasRejectedNssai::new(rejected_nssai_value(
            rejected_nssai,
            nssai_cause::NOT_AVAILABLE_IN_PLMN,
        )));
    }
    if let Some(t) = backoff {
        reject = reject.set_t3346_value(NasGprsTimer2::new(vec![t.octet()]));
    }
    Nas5gsMessage::new_5gmm(
        Nas5gmmMessageType::RegistrationReject,
        Nas5gmmMessage::RegistrationReject(reject),
    )
}

/// Extract `(5GMM cause, rejected NSSAI, T3346 value octet)` from a decoded
/// Registration Reject (UE side / tests).
pub fn parse_registration_reject(
    msg: &Nas5gsMessage,
) -> Option<(u8, Vec<((u8, Option<[u8; 3]>), u8)>, Option<u8>)> {
    let Nas5gsMessage::Gmm(_, Nas5gmmMessage::RegistrationReject(rej)) = msg else {
        return None;
    };
    let rejected =
        rej.rejected_nssai.as_ref().map(|n| parse_rejected_nssai_value(&n.value)).unwrap_or_default();
    let t3346 = rej.t3346_value.as_ref().and_then(|t| t.value.first().copied());
    Some((rej.fgmm_cause.value, rejected, t3346))
}

/// Build a minimal 5GMM **Configuration Update Command** (TS 24.501 §8.2.19). The AMF
/// sends this after Registration Complete; a compliant UE waits for it before initiating
/// a PDU session. All IEs are optional — none are included and no acknowledgement is
/// requested, so the UE simply consumes it.
pub fn configuration_update_command() -> Nas5gsMessage {
    Nas5gsMessage::new_5gmm(
        Nas5gmmMessageType::ConfigurationUpdateCommand,
        Nas5gmmMessage::ConfigurationUpdateCommand(messages::NasConfigurationUpdateCommand::new()),
    )
}

/// Build a 5GMM **Configuration Update Command** (TS 24.501 §8.2.19) carrying the
/// UE's new **Allowed NSSAI** (IEI 0x15, §9.11.3.37) — the network delivers a
/// changed allowed-slice set to the UE inline. `allowed` empty ⇒ a plain command
/// (equivalent to [`configuration_update_command`]). `acknowledgement_requested`
/// sets the ACK bit so the UE must reply with a Configuration Update Complete — the
/// network then retransmits under T3555 until that ack arrives.
pub fn configuration_update_command_with_nssai(
    allowed: &[(u8, Option<[u8; 3]>)],
    registration_requested: bool,
    acknowledgement_requested: bool,
) -> Nas5gsMessage {
    let mut cuc = messages::NasConfigurationUpdateCommand::new();
    if !allowed.is_empty() {
        cuc = cuc.set_allowed_nssai(NasNssai::new(nssai_value(allowed)));
    }
    // Configuration update indication (IEI 0xD0, §9.11.3.18): the **registration
    // requested** bit (bit 1) tells the UE to re-register (set when the allowed
    // NSSAI narrows so the UE renegotiates its slices); the **acknowledgement
    // requested** bit (bit 2) tells the UE it must confirm with a Configuration
    // Update Complete.
    let mut indication = 0u8;
    if registration_requested {
        indication |= CUI_REGISTRATION_REQUESTED;
    }
    if acknowledgement_requested {
        indication |= CUI_ACKNOWLEDGEMENT_REQUESTED;
    }
    if indication != 0 {
        cuc = cuc
            .set_configuration_update_indication(NasConfigurationUpdateIndication::new(indication));
    }
    Nas5gsMessage::new_5gmm(
        Nas5gmmMessageType::ConfigurationUpdateCommand,
        Nas5gmmMessage::ConfigurationUpdateCommand(cuc),
    )
}

/// Configuration update indication (§9.11.3.18) **registration requested** bit.
const CUI_REGISTRATION_REQUESTED: u8 = 0x01;
/// Configuration update indication (§9.11.3.18) **acknowledgement requested** bit.
const CUI_ACKNOWLEDGEMENT_REQUESTED: u8 = 0x02;

/// The allowed NSSAI carried in a decoded Configuration Update Command (UE side /
/// tests); empty when the IE is absent.
pub fn allowed_nssai_from_configuration_update_command(
    msg: &Nas5gsMessage,
) -> Vec<(u8, Option<[u8; 3]>)> {
    let Nas5gsMessage::Gmm(_, Nas5gmmMessage::ConfigurationUpdateCommand(cuc)) = msg else {
        return Vec::new();
    };
    cuc.allowed_nssai.as_ref().map(|n| parse_nssai_value(&n.value)).unwrap_or_default()
}

/// Whether a decoded Configuration Update Command asks the UE to **re-register**
/// (the registration-requested bit of the Configuration update indication IE).
pub fn configuration_update_registration_requested(msg: &Nas5gsMessage) -> bool {
    let Nas5gsMessage::Gmm(_, Nas5gmmMessage::ConfigurationUpdateCommand(cuc)) = msg else {
        return false;
    };
    cuc.configuration_update_indication
        .as_ref()
        .is_some_and(|i| i.value & CUI_REGISTRATION_REQUESTED != 0)
}

/// Whether a decoded Configuration Update Command asks the UE to **acknowledge** it
/// with a Configuration Update Complete (the acknowledgement-requested bit of the
/// Configuration update indication IE). UE side / tests.
pub fn configuration_update_acknowledgement_requested(msg: &Nas5gsMessage) -> bool {
    let Nas5gsMessage::Gmm(_, Nas5gmmMessage::ConfigurationUpdateCommand(cuc)) = msg else {
        return false;
    };
    cuc.configuration_update_indication
        .as_ref()
        .is_some_and(|i| i.value & CUI_ACKNOWLEDGEMENT_REQUESTED != 0)
}

/// Build a 5GMM **Configuration Update Complete** (TS 24.501 §8.2.20) — the UE's
/// acknowledgement of a Configuration Update Command. UE side / tests.
pub fn configuration_update_complete() -> Nas5gsMessage {
    Nas5gsMessage::new_5gmm(
        Nas5gmmMessageType::ConfigurationUpdateComplete,
        Nas5gmmMessage::ConfigurationUpdateComplete(
            messages::NasConfigurationUpdateComplete::new(),
        ),
    )
}

/// Build a 5GMM **Registration Complete** (TS 24.501 §8.2.8). UE side / tests.
pub fn registration_complete() -> Nas5gsMessage {
    Nas5gsMessage::new_5gmm(
        Nas5gmmMessageType::RegistrationComplete,
        Nas5gmmMessage::RegistrationComplete(messages::NasRegistrationComplete::new()),
    )
}

/// Build and encode a 5GMM **UL NAS Transport** (TS 24.501 §8.2.10) carrying an N1 SM
/// container (a 5GSM message) for `pdu_session_id`, optionally with the UE's requested
/// **DNN** and **S-NSSAI** IEs. UE side / tests — the AMF relays the container to the
/// SMF transparently.
pub fn ul_nas_transport_sm(
    pdu_session_id: u8,
    sm_container: Vec<u8>,
    dnn: Option<&str>,
    snssai: Option<(u8, Option<[u8; 3]>)>,
) -> Vec<u8> {
    let mut transport = messages::NasUlNasTransport::new(
        NasPayloadContainerType::new(0x01), // N1 SM information
        NasPayloadContainer::new(sm_container),
    )
    .set_pdu_session_id(NasPduSessionIdentity2::new(pdu_session_id));
    if let Some(dnn) = dnn {
        transport = transport.set_dnn(NasDnn::from_string(dnn));
    }
    if let Some((sst, sd)) = snssai {
        transport = transport.set_s_nssai(NasSNssai::from_sst_sd(sst, sd));
    }
    let msg = Nas5gsMessage::new_5gmm(
        Nas5gmmMessageType::UlNasTransport,
        Nas5gmmMessage::UlNasTransport(transport),
    );
    encode_nas_5gs_message(&msg).expect("encode UlNasTransport")
}

/// A Session-AMBR in TS 24.501 §9.11.4.14 wire form: a unit octet plus a 16-bit
/// multiple, per direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionAmbr {
    pub dl_unit: u8,
    pub dl: u16,
    pub ul_unit: u8,
    pub ul: u16,
}

impl SessionAmbr {
    /// The pre-subscription default this stack used: 10 Mbps each way.
    pub const TEN_MBPS: SessionAmbr =
        SessionAmbr { dl_unit: 0x06, dl: 10, ul_unit: 0x06, ul: 10 };
}

/// Convert TS 29.571 `BitRate` strings (as provisioned in the UDR sm-data, e.g.
/// `"2 Gbps"`) to the NAS Session-AMBR encoding. Integer values only; `None` if
/// either string doesn't parse or overflows the 16-bit multiple.
pub fn session_ambr_from_bitrates(uplink: &str, downlink: &str) -> Option<SessionAmbr> {
    fn one(s: &str) -> Option<(u8, u16)> {
        let (value, unit) = s.trim().split_once(' ')?;
        let value: u16 = value.parse().ok()?;
        // TS 24.501 Table 9.11.4.14.1 (the 1× steps; finer multiples unused here).
        let unit = match unit {
            "Kbps" => 0x01,
            "Mbps" => 0x06,
            "Gbps" => 0x0B,
            "Tbps" => 0x10,
            _ => return None,
        };
        Some((unit, value))
    }
    let (ul_unit, ul) = one(uplink)?;
    let (dl_unit, dl) = one(downlink)?;
    Some(SessionAmbr { dl_unit, dl, ul_unit, ul })
}

/// A GBR flow's guaranteed/maximum bit rates, each in NAS unit+value form (reuse
/// the Session-AMBR encoding: a unit octet + 16-bit multiple, per direction).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GbrFlow {
    pub gfbr: SessionAmbr,
    pub mfbr: SessionAmbr,
}

/// One authorized QoS flow description (TS 24.501 §9.11.4.12): the QFI, its 5QI,
/// and the GBR rates when guaranteed. Carried in the accept's `Authorized QoS
/// flow descriptions` IE (0x79).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QosFlowDesc {
    pub qfi: u8,
    pub five_qi: u8,
    pub gbr: Option<GbrFlow>,
}

/// Encode a list of QoS flow descriptions as the IE *value* (TS 24.501
/// §9.11.4.12), using the free5gc byte layout: per flow `QFI`, `opcode<<5`
/// (create=1), `E<<6 | numParams`, then each parameter as `id, len, content`.
/// A GBR flow adds GFBR/MFBR params (unit octet + 16-bit value per direction).
fn qos_flow_descriptions_value(flows: &[QosFlowDesc]) -> Vec<u8> {
    let mut v = Vec::new();
    for f in flows {
        v.push(f.qfi);
        v.push(0x01 << 5); // operation code 1 (create) in bits 8-6
        // Parameters: 5QI always, plus GFBR-ul/dl + MFBR-ul/dl when GBR.
        let n_params: u8 = if f.gbr.is_some() { 5 } else { 1 };
        v.push((1 << 6) | n_params); // E=1, number of parameters
        // 5QI (id 0x01, len 1).
        v.extend_from_slice(&[0x01, 0x01, f.five_qi]);
        if let Some(g) = f.gbr {
            // GFBR uplink (0x02), downlink (0x03), MFBR uplink (0x04), downlink (0x05).
            // Each: unit octet + 16-bit value (len 3).
            let param = |id: u8, unit: u8, value: u16| {
                let mut p = vec![id, 0x03, unit];
                p.extend_from_slice(&value.to_be_bytes());
                p
            };
            v.extend(param(0x02, g.gfbr.ul_unit, g.gfbr.ul));
            v.extend(param(0x03, g.gfbr.dl_unit, g.gfbr.dl));
            v.extend(param(0x04, g.mfbr.ul_unit, g.mfbr.ul));
            v.extend(param(0x05, g.mfbr.dl_unit, g.mfbr.dl));
        }
    }
    v
}

/// Build a 5GSM **PDU Session Establishment Accept** (TS 24.501 §8.3.2) as the raw N1 SM
/// container bytes. Hand-encoded to the exact TS 24.501 layout (so it interoperates with a
/// free5GC UE regardless of codec quirks): SSC mode 1 + IPv4, one default *match-all* QoS
/// rule, the subscribed **Session-AMBR**, the **PDU address** carrying the UE's assigned
/// IPv4 (the field the UE reads to configure its stack), and the subscribed **S-NSSAI** +
/// **DNN** (which the UE also reads). `pti` echoes the request's procedure transaction id;
/// S-NSSAI/AMBR come from the subscriber's UDR sm-data (design/27).
pub fn pdu_session_establishment_accept(
    pdu_session_id: u8,
    pti: u8,
    ue_ip: std::net::Ipv4Addr,
    dnn: &str,
    snssai_sst: u8,
    snssai_sd: Option<[u8; 3]>,
    ambr: SessionAmbr,
    flows: &[QosFlowDesc],
) -> Vec<u8> {
    let mut m = Vec::with_capacity(48);
    // 5GSM header: EPD, PDU session id, PTI, message type (0xC2 = Establishment Accept).
    m.extend_from_slice(&[0x2e, pdu_session_id, pti, 0xc2]);
    // Selected SSC mode (1, bits 5-7) + selected PDU session type (IPv4 = 1, bits 1-3).
    m.push(0x11);
    // Authorized QoS rules (LV-E, 2-byte length): one "create new" default (DQR) rule with a
    // single bidirectional match-all packet filter, precedence 0xFF, QFI 1.
    let qos_rules: [u8; 9] = [0x01, 0x00, 0x06, 0x31, 0x31, 0x01, 0x01, 0xff, 0x01];
    m.extend_from_slice(&(qos_rules.len() as u16).to_be_bytes());
    m.extend_from_slice(&qos_rules);
    // Session-AMBR (LV, length 6): downlink unit+value then uplink unit+value.
    m.push(6);
    m.push(ambr.dl_unit);
    m.extend_from_slice(&ambr.dl.to_be_bytes());
    m.push(ambr.ul_unit);
    m.extend_from_slice(&ambr.ul.to_be_bytes());
    // PDU address (IEI 0x29, length 5): PDU session type IPv4 (1) + the UE's IPv4 address.
    m.push(0x29);
    m.push(5);
    m.push(0x01);
    m.extend_from_slice(&ue_ip.octets());
    // S-NSSAI (IEI 0x22): SST, plus the SD when the slice has one.
    m.push(0x22);
    match snssai_sd {
        Some(sd) => {
            m.push(4);
            m.push(snssai_sst);
            m.extend_from_slice(&sd);
        }
        None => {
            m.push(1);
            m.push(snssai_sst);
        }
    }
    // Authorized QoS flow descriptions (IEI 0x79, LV-E) — per-flow 5QI/GBR — when
    // the network authorized flows beyond the implicit default. Omitted (bytes
    // unchanged) when empty, keeping the common single-flow accept minimal.
    if !flows.is_empty() {
        let desc = qos_flow_descriptions_value(flows);
        m.push(0x79);
        m.extend_from_slice(&(desc.len() as u16).to_be_bytes());
        m.extend_from_slice(&desc);
    }
    // DNN (IEI 0x25): RFC 1035 label form — a length-prefixed label per dot-separated part.
    m.push(0x25);
    let dnn_buf: Vec<u8> = rfc1035_labels(dnn);
    m.push(dnn_buf.len() as u8);
    m.extend_from_slice(&dnn_buf);
    m
}

/// Build a 5GSM **PDU Session Modification Command** (TS 24.501 §8.3.5) as the raw
/// N1 SM container bytes — the network-initiated mid-session QoS change delivered to
/// the UE. Carries the updated **Session-AMBR** (IEI 0x2A) and the **Authorized QoS
/// flow descriptions** (IEI 0x79): `flows` are created/modified (opcode 1) and each
/// QFI in `released` gets a **delete** operation (opcode 2). `pti` is 0 for a
/// network-initiated procedure.
///
/// Hand-encoded to the TS 24.501 layout. Note: unlike the establishment accept, this
/// is not exercised by the live free-ran-ue UE (which does not drive a modification),
/// so its wire shape is pinned by unit tests rather than interop.
pub fn pdu_session_modification_command(
    pdu_session_id: u8,
    pti: u8,
    ambr: SessionAmbr,
    flows: &[QosFlowDesc],
    released: &[u8],
) -> Vec<u8> {
    // 5GSM header: EPD, PDU session id, PTI, message type (0xCB = Modification Command).
    let mut m = vec![0x2e, pdu_session_id, pti, 0xcb];
    // Session-AMBR (IEI 0x2A, TLV length 6): downlink unit+value then uplink unit+value.
    m.push(0x2a);
    m.push(6);
    m.push(ambr.dl_unit);
    m.extend_from_slice(&ambr.dl.to_be_bytes());
    m.push(ambr.ul_unit);
    m.extend_from_slice(&ambr.ul.to_be_bytes());
    // Authorized QoS flow descriptions (IEI 0x79, LV-E): create/modify the given
    // flows, then delete (operation code 2, no parameters) each released QFI.
    let mut desc = qos_flow_descriptions_value(flows);
    for qfi in released {
        desc.extend_from_slice(&[*qfi, 0x02 << 5, 0x00]);
    }
    if !desc.is_empty() {
        m.push(0x79);
        m.extend_from_slice(&(desc.len() as u16).to_be_bytes());
        m.extend_from_slice(&desc);
    }
    m
}

/// Build a 5GSM **PDU Session Release Command** (TS 24.501 §8.3.4) as the raw N1 SM
/// container bytes: the 5GSM header (message type 0xD3), then the mandatory 5GSM
/// cause (V, one octet). Network-initiated release ⇒ PTI 0; pick `cause` from
/// [`sm_cause`] (e.g. *regular deactivation*). The gNB relays this to the UE inside
/// the N2 PDU Session Resource Release Command.
pub fn pdu_session_release_command(pdu_session_id: u8, pti: u8, cause: u8) -> Vec<u8> {
    // EPD (0x2e), PDU session id, PTI, message type (0xD3 = Release Command), cause.
    vec![0x2e, pdu_session_id, pti, 0xd3, cause]
}

/// Build a 5GSM **PDU Session Release Complete** (TS 24.501 §8.3.5) as the raw N1 SM
/// container bytes — the UE's answer to a Release Command. UE side / tests.
pub fn pdu_session_release_complete(pdu_session_id: u8, pti: u8) -> Vec<u8> {
    // EPD, PDU session id, PTI, message type (0xD4 = Release Complete). No cause.
    vec![0x2e, pdu_session_id, pti, 0xd4]
}

/// Whether a raw N1 SM container is a 5GSM **PDU Session Release Complete** (message
/// type 0xD4 at offset 3) — the AMF finalises the release when the UE sends it.
pub fn is_pdu_session_release_complete(sm_container: &[u8]) -> bool {
    sm_container.get(3) == Some(&0xd4)
}

/// 5GSM cause values (TS 24.501 §9.11.4.2) this stack emits.
pub mod sm_cause {
    /// #26 — insufficient resources (GFBR admission control refused the session).
    pub const INSUFFICIENT_RESOURCES: u8 = 26;
    /// #36 — regular deactivation (the network released the PDU session normally).
    pub const REGULAR_DEACTIVATION: u8 = 36;
    /// #27 — the requested DNN is not subscribed / unknown.
    pub const MISSING_OR_UNKNOWN_DNN: u8 = 27;
    /// #31 — request rejected, unspecified (internal / upstream failure).
    pub const REQUEST_REJECTED_UNSPECIFIED: u8 = 31;
    /// #70 — the (S-NSSAI, DNN) pair the UE requested is not valid together.
    pub const MISSING_OR_UNKNOWN_DNN_IN_SLICE: u8 = 70;
}

/// GPRS Timer 3 (TS 24.008 §10.5.7.4a): one octet holding a 3-bit unit (bits 6-8)
/// and a 5-bit multiple (bits 1-5). Carried as the **back-off timer value** IE
/// (T3396) in 5GSM rejects — the UE must not re-request the same DNN until it
/// expires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GprsTimer3(u8);

impl GprsTimer3 {
    /// Encode a duration, choosing the finest unit whose 5-bit multiple fits and
    /// rounding up — the UE backs off *at least* `secs`. Durations beyond the
    /// encodable maximum (31 × 320 hours) clamp to it.
    pub fn from_secs(secs: u32) -> Self {
        // (unit bits, seconds per step): 2s, 30s, 1min, 10min, 1h, 10h, 320h.
        const UNITS: [(u8, u32); 7] = [
            (0b011, 2),
            (0b100, 30),
            (0b101, 60),
            (0b000, 600),
            (0b001, 3_600),
            (0b010, 36_000),
            (0b110, 1_152_000),
        ];
        for (unit, step) in UNITS {
            let multiple = secs.div_ceil(step);
            if multiple <= 31 {
                return Self((unit << 5) | multiple as u8);
            }
        }
        Self((0b110 << 5) | 31)
    }

    /// The timer-deactivated encoding (unit 0b111).
    pub fn deactivated() -> Self {
        Self(0b111_00000)
    }

    /// The raw value octet as it appears on the wire.
    pub fn octet(self) -> u8 {
        self.0
    }
}

/// Build a 5GSM **PDU Session Establishment Reject** (TS 24.501 §8.3.3) as the raw
/// N1 SM container bytes: the 5GSM header (message type 0xC3), the mandatory 5GSM
/// cause (V, one octet), and optionally the **back-off timer value** IE (IEI 0x37,
/// TLV — starts T3396 in the UE). `pti` echoes the request's procedure transaction
/// id; pick `cause` from [`sm_cause`].
pub fn pdu_session_establishment_reject(
    pdu_session_id: u8,
    pti: u8,
    cause: u8,
    backoff: Option<GprsTimer3>,
) -> Vec<u8> {
    let mut m = vec![0x2e, pdu_session_id, pti, 0xc3, cause];
    if let Some(t) = backoff {
        m.extend_from_slice(&[0x37, 0x01, t.octet()]);
    }
    m
}

/// Encode a DNN as RFC 1035 labels (each dot-separated label prefixed by its length),
/// as TS 24.501 §9.11.2.1A specifies.
fn rfc1035_labels(dnn: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(dnn.len() + 2);
    for label in dnn.split('.').filter(|l| !l.is_empty()) {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out
}

/// Build a 5GMM **DL NAS Transport** (TS 24.501 §8.2.11) carrying an N1 SM container (a 5GSM
/// message) down to the UE for `pdu_session_id`. The AMF NAS-protects this and hands it to the
/// gNB in the N2 PDU Session Resource Setup, which relays it to the UE.
pub fn dl_nas_transport_sm(pdu_session_id: u8, n1_sm_container: Vec<u8>) -> Nas5gsMessage {
    let transport = messages::NasDlNasTransport::new(
        NasPayloadContainerType::new(0x01), // N1 SM information
        NasPayloadContainer::new(n1_sm_container),
    )
    .set_pdu_session_id(NasPduSessionIdentity2::new(pdu_session_id));
    Nas5gsMessage::new_5gmm(
        Nas5gmmMessageType::DlNasTransport,
        Nas5gmmMessage::DlNasTransport(transport),
    )
}

/// Extract `(pdu_session_id, N1 SM container)` from a decoded 5GMM UL NAS Transport.
pub fn sm_container_from_ul_nas_transport(msg: &Nas5gsMessage) -> Option<(u8, Vec<u8>)> {
    let Nas5gsMessage::Gmm(_, Nas5gmmMessage::UlNasTransport(transport)) = msg else {
        return None;
    };
    let psi = transport.pdu_session_id.as_ref()?.value;
    Some((psi, transport.payload_container.value.clone()))
}

/// Extract the UE's requested **DNN** from a decoded 5GMM UL NAS Transport
/// (TS 24.501 §8.2.10, IEI 0x25), decoded from its RFC 1035 label form to a
/// dot-separated string. `None` when the UE omitted the IE (the network then
/// falls back to a default DNN).
pub fn requested_dnn_from_ul_nas_transport(msg: &Nas5gsMessage) -> Option<String> {
    let Nas5gsMessage::Gmm(_, Nas5gmmMessage::UlNasTransport(transport)) = msg else {
        return None;
    };
    transport.dnn.as_ref()?.as_string()
}

/// Extract the UE's requested **S-NSSAI** from a decoded 5GMM UL NAS Transport
/// (TS 24.501 §8.2.10, IEI 0x22) as `(SST, optional SD)`. `None` when the UE
/// omitted the IE (the network then serves the subscribed default slice).
pub fn requested_snssai_from_ul_nas_transport(
    msg: &Nas5gsMessage,
) -> Option<(u8, Option<[u8; 3]>)> {
    let Nas5gsMessage::Gmm(_, Nas5gmmMessage::UlNasTransport(transport)) = msg else {
        return None;
    };
    let contents = transport.s_nssai.as_ref()?.parse()?;
    Some((contents.sst, contents.sd))
}

/// Extract `(pdu_session_id, N1 SM container)` from a decoded 5GMM DL NAS Transport.
pub fn sm_container_from_dl_nas_transport(msg: &Nas5gsMessage) -> Option<(u8, Vec<u8>)> {
    let Nas5gsMessage::Gmm(_, Nas5gmmMessage::DlNasTransport(transport)) = msg else {
        return None;
    };
    let psi = transport.pdu_session_id.as_ref()?.value;
    Some((psi, transport.payload_container.value.clone()))
}

/// Deconceal a **SUCI** (TS 33.501 Annex C) to its **SUPI** in the `imsi-<MCC><MNC><MSIN>`
/// form the UDM/UDR key subscribers under.
///
/// Only the **null protection scheme** (scheme 0) is supported: there the scheme output is
/// the MSIN in BCD (low nibble first, `0xF` filler ignored). ECIES schemes (profiles A/B)
/// need the home-network private key and are not implemented yet — for those the SUCI is
/// returned in [canonical string form](suci_canonical_string) (which will not resolve to a
/// subscriber, but stays inspectable) rather than a misleading partial IMSI.
pub fn suci_to_supi(suci: &Suci) -> String {
    if suci.protection_scheme != 0 {
        return suci_canonical_string(suci);
    }
    let mut supi = String::from("imsi-");
    // MCC/MNC are stored as one digit per byte (MNC may carry a 0xF filler for 2-digit MNCs).
    for &d in suci.mcc.iter().chain(&suci.mnc) {
        if d <= 9 {
            supi.push((b'0' + d) as char);
        }
    }
    // Null scheme: scheme output is the MSIN, BCD-packed (two digits per byte, low first).
    for &byte in &suci.scheme_output {
        for nibble in [byte & 0x0F, byte >> 4] {
            if nibble <= 9 {
                supi.push((b'0' + nibble) as char);
            }
        }
    }
    supi
}

/// The canonical SUCI string form `suci-<supi_fmt>-<MCC>-<MNC>-<RI>-<scheme>-<keyid>-<output>`
/// (as free5GC/Open5GS render it) — used for logging and for unsupported protection schemes.
pub fn suci_canonical_string(suci: &Suci) -> String {
    fn digits(d: &[u8]) -> String {
        d.iter().filter(|&&n| n <= 9).map(|n| char::from(b'0' + n)).collect()
    }
    fn hex_lower(bytes: &[u8]) -> String {
        use std::fmt::Write;
        let mut out = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            let _ = write!(out, "{b:02x}");
        }
        out
    }
    format!(
        "suci-0-{}-{}-{}-{}-{}-{}",
        digits(&suci.mcc),
        digits(&suci.mnc),
        hex_lower(&suci.routing_indicator),
        suci.protection_scheme,
        suci.home_nw_public_key_id,
        hex_lower(&suci.scheme_output),
    )
}

/// The 5GMM message type of a decoded NAS message, if it is a 5GMM message.
pub fn gmm_message_type(msg: &Nas5gsMessage) -> Option<Nas5gmmMessageType> {
    if let Nas5gsMessage::Gmm(hdr, _) = msg {
        Some(hdr.message_type)
    } else {
        None
    }
}

fn mcc_digits(mcc: &str) -> [u8; 3] {
    let b = mcc.as_bytes();
    [b[0] - b'0', b[1] - b'0', b[2] - b'0']
}

fn mnc_digits(mnc: &str) -> [u8; 3] {
    let b = mnc.as_bytes();
    if mnc.len() == 2 {
        [b[0] - b'0', b[1] - b'0', 0x0F]
    } else {
        [b[0] - b'0', b[1] - b'0', b[2] - b'0']
    }
}

/// NAS security header types (TS 24.501 §9.1.1).
pub mod sht {
    pub const INTEGRITY: u8 = 0x01;
    pub const INTEGRITY_CIPHERED: u8 = 0x02;
    pub const INTEGRITY_NEW_CONTEXT: u8 = 0x03;
    pub const INTEGRITY_CIPHERED_NEW_CONTEXT: u8 = 0x04;
}

const NAS_BEARER: u8 = 1; // TS 33.501 §6.4.3.1: NAS bearer is always 1.
const EPD_5GMM: u8 = 0x7e;

/// NAS security context (TS 33.501 §8.2 / TS 24.501 §9.1.1): the keys, algorithms,
/// and per-direction NAS COUNT used to integrity-protect and cipher NAS messages.
///
/// One context per peer protects its downlink and unprotects its uplink (AMF) or
/// vice-versa (UE). `direction`: 0 = uplink, 1 = downlink.
#[derive(Debug, Clone)]
pub struct NasSecurityContext {
    pub knas_int: [u8; 16],
    pub knas_enc: [u8; 16],
    pub nia: u8,
    pub nea: u8,
    pub ul_count: u32,
    pub dl_count: u32,
}

impl NasSecurityContext {
    pub fn new(knas_int: [u8; 16], knas_enc: [u8; 16], nia: u8, nea: u8) -> Self {
        Self {
            knas_int,
            knas_enc,
            nia,
            nea,
            ul_count: 0,
            dl_count: 0,
        }
    }

    /// Wrap a NAS message in the security envelope `[EPD | SHT | MAC(4) | SN | payload]`.
    pub fn protect(&mut self, inner: &Nas5gsMessage, sht: u8, direction: u8) -> Vec<u8> {
        let mut payload = encode_nas_5gs_message(inner).expect("encode inner NAS message");
        let count = if direction == 0 {
            &mut self.ul_count
        } else {
            &mut self.dl_count
        };
        let c = *count;
        *count += 1;
        let sn = (c & 0xff) as u8;

        if matches!(sht, sht::INTEGRITY_CIPHERED | sht::INTEGRITY_CIPHERED_NEW_CONTEXT) {
            oxirush_security::nas_cipher(&self.knas_enc, c, NAS_BEARER, direction, &mut payload, self.nea);
        }

        let mut mac_input = Vec::with_capacity(1 + payload.len());
        mac_input.push(sn);
        mac_input.extend_from_slice(&payload);
        let mac = oxirush_security::nas_mac(&self.knas_int, c, NAS_BEARER, direction, &mac_input, self.nia);

        let mut out = Vec::with_capacity(7 + payload.len());
        out.push(EPD_5GMM);
        out.push(sht);
        out.extend_from_slice(&mac.to_be_bytes());
        out.push(sn);
        out.extend_from_slice(&payload);
        out
    }

    /// Verify the MAC of a protected NAS message, decipher if needed, and decode it.
    /// Returns `None` on MAC failure or malformed input.
    pub fn unprotect(&mut self, data: &[u8], direction: u8) -> Option<Nas5gsMessage> {
        if data.len() < 7 {
            return None;
        }
        let sht = data[1];
        let recv_mac = u32::from_be_bytes([data[2], data[3], data[4], data[5]]);
        let sn = data[6];
        let mut payload = data[7..].to_vec();

        let count = if direction == 0 {
            &mut self.ul_count
        } else {
            &mut self.dl_count
        };
        // Align the COUNT's low byte with the received SN (no overflow handling yet).
        let c = (*count & !0xff) | sn as u32;

        let mut mac_input = Vec::with_capacity(1 + payload.len());
        mac_input.push(sn);
        mac_input.extend_from_slice(&payload);
        if oxirush_security::nas_mac(&self.knas_int, c, NAS_BEARER, direction, &mac_input, self.nia)
            != recv_mac
        {
            return None;
        }
        *count = c + 1;

        if matches!(sht, sht::INTEGRITY_CIPHERED | sht::INTEGRITY_CIPHERED_NEW_CONTEXT) {
            oxirush_security::nas_cipher(&self.knas_enc, c, NAS_BEARER, direction, &mut payload, self.nea);
        }
        decode_nas_5gs_message(&payload).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dl_nas_transport_carries_pdu_session_accept() {
        let ue_ip = std::net::Ipv4Addr::new(10, 45, 0, 2);
        let ambr = session_ambr_from_bitrates("1 Gbps", "2 Gbps").expect("bitrates parse");
        let accept =
            pdu_session_establishment_accept(5, 1, ue_ip, "internet", 1, Some([1, 2, 3]), ambr, &[]);
        // A 5GSM Establishment Accept: header, the UE's IPv4 in the PDU address, and the DNN.
        assert_eq!(&accept[..4], &[0x2e, 5, 1, 0xc2]);
        assert!(accept.windows(7).any(|w| w == [0x29, 5, 0x01, 10, 45, 0, 2]), "PDU address = UE IPv4");
        assert!(accept.ends_with(&[0x25, 0x09, 0x08, b'i', b'n', b't', b'e', b'r', b'n', b'e', b't']), "DNN");
        // Subscribed values on the wire: AMBR DL 2 Gbps then UL 1 Gbps; S-NSSAI sst=1 sd=010203.
        assert!(accept.windows(7).any(|w| w == [6, 0x0B, 0, 2, 0x0B, 0, 1]), "Session-AMBR");
        assert!(accept.windows(6).any(|w| w == [0x22, 0x04, 0x01, 1, 2, 3]), "S-NSSAI");

        let bytes = encode_nas_5gs_message(&dl_nas_transport_sm(5, accept.clone())).expect("encode");
        let msg = decode_nas_5gs_message(&bytes).expect("decode");
        assert_eq!(gmm_message_type(&msg), Some(Nas5gmmMessageType::DlNasTransport));
        assert_eq!(sm_container_from_dl_nas_transport(&msg), Some((5, accept)));
    }

    #[test]
    fn dl_nas_transport_carries_pdu_session_reject() {
        let reject = pdu_session_establishment_reject(5, 1, sm_cause::MISSING_OR_UNKNOWN_DNN, None);
        // 5GSM header (0xC3 = Establishment Reject) + the mandatory cause octet.
        assert_eq!(reject, [0x2e, 5, 1, 0xc3, 27]);

        // With a back-off: the T3396 IE (0x37, TLV) follows — 60s = 30 × 2s (unit 0b011).
        let with_backoff = pdu_session_establishment_reject(
            5,
            1,
            sm_cause::MISSING_OR_UNKNOWN_DNN,
            Some(GprsTimer3::from_secs(60)),
        );
        assert_eq!(with_backoff, [0x2e, 5, 1, 0xc3, 27, 0x37, 0x01, 0b011_11110]);

        let bytes = encode_nas_5gs_message(&dl_nas_transport_sm(5, with_backoff.clone())).expect("encode");
        let msg = decode_nas_5gs_message(&bytes).expect("decode");
        assert_eq!(sm_container_from_dl_nas_transport(&msg), Some((5, with_backoff)));
    }

    #[test]
    fn gprs_timer3_unit_selection() {
        // Finest fitting unit, rounded up.
        assert_eq!(GprsTimer3::from_secs(60).octet(), 0b011_11110, "60s = 30 x 2s");
        assert_eq!(GprsTimer3::from_secs(63).octet(), 0b100_00011, "63s rounds up to 3 x 30s");
        assert_eq!(GprsTimer3::from_secs(300).octet(), 0b100_01010, "5min = 10 x 30s");
        assert_eq!(GprsTimer3::from_secs(3_600).octet(), 0b000_00110, "1h = 6 x 10min");
        assert_eq!(GprsTimer3::from_secs(86_400).octet(), 0b001_11000, "24h = 24 x 1h");
        // Beyond the encodable range: clamp to 31 x 320h.
        assert_eq!(GprsTimer3::from_secs(u32::MAX).octet(), 0b110_11111);
        assert_eq!(GprsTimer3::deactivated().octet(), 0b111_00000);
    }

    #[test]
    fn qos_flow_descriptions_ie_encoding() {
        // Default non-GBR flow: QFI 1, 5QI 9, one param (5QI).
        let default = QosFlowDesc { qfi: 1, five_qi: 9, gbr: None };
        assert_eq!(
            qos_flow_descriptions_value(&[default]),
            // QFI, opcode<<5, E<<6|1, [5QI id, len, value]
            [0x01, 0x20, 0x41, 0x01, 0x01, 0x09]
        );

        // GBR flow: QFI 2, 5QI 1, GFBR 100 Mbps each way, MFBR 200 Mbps each way.
        let gfbr = session_ambr_from_bitrates("100 Mbps", "100 Mbps").unwrap();
        let mfbr = session_ambr_from_bitrates("200 Mbps", "200 Mbps").unwrap();
        let gbr = QosFlowDesc { qfi: 2, five_qi: 1, gbr: Some(GbrFlow { gfbr, mfbr }) };
        assert_eq!(
            qos_flow_descriptions_value(&[gbr]),
            [
                0x02, 0x20, 0x45, // QFI 2, create, E + 5 params
                0x01, 0x01, 0x01, // 5QI = 1
                0x02, 0x03, 0x06, 0x00, 0x64, // GFBR ul: unit 0x06 (Mbps), 100
                0x03, 0x03, 0x06, 0x00, 0x64, // GFBR dl: 100
                0x04, 0x03, 0x06, 0x00, 0xC8, // MFBR ul: 200
                0x05, 0x03, 0x06, 0x00, 0xC8, // MFBR dl: 200
            ]
        );

        // In the accept, the IE rides as 0x79 + 2-byte length + value; the default
        // flow set present, DNN still last.
        let ue_ip = std::net::Ipv4Addr::new(10, 45, 0, 2);
        let ambr = session_ambr_from_bitrates("1 Gbps", "2 Gbps").unwrap();
        let accept =
            pdu_session_establishment_accept(5, 1, ue_ip, "internet", 1, Some([1, 2, 3]), ambr, &[default]);
        assert!(accept.windows(3).any(|w| w == [0x79, 0x00, 0x06]), "0x79 IE header (len 6)");
        assert!(accept.ends_with(&[0x25, 0x09, 0x08, b'i', b'n', b't', b'e', b'r', b'n', b'e', b't']), "DNN still last");
        // An empty flow list omits the IE entirely (single-flow accept stays minimal).
        let bare =
            pdu_session_establishment_accept(5, 1, ue_ip, "internet", 1, Some([1, 2, 3]), ambr, &[]);
        assert!(!bare.windows(1).any(|w| w == [0x79]), "no QoS flow descriptions IE when empty");
    }

    #[test]
    fn pdu_session_modification_command_layout() {
        let ambr = session_ambr_from_bitrates("50 Mbps", "100 Mbps").unwrap();
        let flows = [
            QosFlowDesc { qfi: 1, five_qi: 9, gbr: None },
            QosFlowDesc {
                qfi: 2,
                five_qi: 1,
                gbr: Some(GbrFlow {
                    gfbr: session_ambr_from_bitrates("10 Mbps", "10 Mbps").unwrap(),
                    mfbr: session_ambr_from_bitrates("20 Mbps", "20 Mbps").unwrap(),
                }),
            },
        ];
        // Release QFI 3 alongside the created/modified flows.
        let cmd = pdu_session_modification_command(5, 0, ambr, &flows, &[3]);
        // 5GSM header: EPD, psi, PTI 0 (network-initiated), message type 0xCB.
        assert_eq!(&cmd[..4], &[0x2e, 5, 0, 0xcb]);
        // Session-AMBR IEI 0x2A, len 6: dl unit+value, ul unit+value (50/100 Mbps).
        assert!(
            cmd.windows(8).any(|w| w == [0x2a, 0x06, 0x06, 0x00, 100, 0x06, 0x00, 50]),
            "session AMBR TLV (0x2A)"
        );
        // Authorized QoS flow descriptions IE (0x79) present with both flows.
        assert!(cmd.windows(1).any(|w| w == [0x79]), "0x79 QoS flow descriptions IE");
        // The released QFI 3 has a delete op (opcode 2 = 0x40, no parameters).
        assert!(cmd.windows(3).any(|w| w == [3, 0x40, 0x00]), "delete QoS flow description for QFI 3");
    }

    #[test]
    fn pdu_session_release_command_and_complete_layout() {
        // Release Command: EPD, psi, PTI 0 (network-initiated), 0xD3, cause #36.
        let cmd = pdu_session_release_command(5, 0, sm_cause::REGULAR_DEACTIVATION);
        assert_eq!(cmd, vec![0x2e, 5, 0, 0xd3, 36]);
        assert!(!is_pdu_session_release_complete(&cmd));

        // Release Complete: EPD, psi, PTI, 0xD4 — recognised by the detector.
        let complete = pdu_session_release_complete(5, 0);
        assert_eq!(complete, vec![0x2e, 5, 0, 0xd4]);
        assert!(is_pdu_session_release_complete(&complete));
        // A UL NAS Transport carrying it round-trips to its (psi, container).
        let raw = ul_nas_transport_sm(5, complete.clone(), None, None);
        let msg = decode_nas_5gs_message(&raw).unwrap();
        assert_eq!(sm_container_from_ul_nas_transport(&msg), Some((5, complete)));
    }

    #[test]
    fn session_ambr_bitrate_parsing() {
        assert_eq!(
            session_ambr_from_bitrates("1 Gbps", "2 Gbps"),
            Some(SessionAmbr { dl_unit: 0x0B, dl: 2, ul_unit: 0x0B, ul: 1 })
        );
        assert_eq!(
            session_ambr_from_bitrates("500 Kbps", "10 Mbps"),
            Some(SessionAmbr { dl_unit: 0x06, dl: 10, ul_unit: 0x01, ul: 500 })
        );
        assert_eq!(session_ambr_from_bitrates("0.5 Gbps", "1 Gbps"), None, "fractions unsupported");
        assert_eq!(session_ambr_from_bitrates("fast", "1 Gbps"), None);
        assert_eq!(session_ambr_from_bitrates("1 Gbps", "999999 Gbps"), None, "u16 overflow");
    }

    #[test]
    fn configuration_update_command_round_trips() {
        let bytes = encode_nas_5gs_message(&configuration_update_command()).expect("encode");
        let msg = decode_nas_5gs_message(&bytes).expect("decode");
        assert_eq!(gmm_message_type(&msg), Some(Nas5gmmMessageType::ConfigurationUpdateCommand));
        // A plain command carries no allowed NSSAI.
        assert!(allowed_nssai_from_configuration_update_command(&msg).is_empty());

        assert!(!configuration_update_registration_requested(&msg));

        assert!(!configuration_update_acknowledgement_requested(&msg));

        // A command carrying the Allowed NSSAI round-trips to that slice set; without
        // the registration-requested or acknowledgement-requested flags.
        let allowed = vec![(1u8, Some([1, 2, 3])), (2, None)];
        let bytes =
            encode_nas_5gs_message(&configuration_update_command_with_nssai(&allowed, false, false))
                .expect("encode");
        let msg = decode_nas_5gs_message(&bytes).expect("decode");
        assert_eq!(gmm_message_type(&msg), Some(Nas5gmmMessageType::ConfigurationUpdateCommand));
        assert_eq!(allowed_nssai_from_configuration_update_command(&msg), allowed);
        assert!(!configuration_update_registration_requested(&msg));
        assert!(!configuration_update_acknowledgement_requested(&msg));

        // With registration requested (a narrowing): the UE is told to re-register.
        let bytes =
            encode_nas_5gs_message(&configuration_update_command_with_nssai(&allowed, true, false))
                .expect("encode");
        let msg = decode_nas_5gs_message(&bytes).expect("decode");
        assert!(configuration_update_registration_requested(&msg), "re-registration requested");
        assert!(!configuration_update_acknowledgement_requested(&msg), "no ack requested");
        assert_eq!(allowed_nssai_from_configuration_update_command(&msg), allowed);

        // Both bits set (a narrowing that must be acknowledged): the indication IE
        // carries registration-requested AND acknowledgement-requested independently.
        let bytes =
            encode_nas_5gs_message(&configuration_update_command_with_nssai(&allowed, true, true))
                .expect("encode");
        let msg = decode_nas_5gs_message(&bytes).expect("decode");
        assert!(configuration_update_registration_requested(&msg));
        assert!(configuration_update_acknowledgement_requested(&msg), "acknowledgement requested");
        // Acknowledgement alone (no re-registration).
        let bytes =
            encode_nas_5gs_message(&configuration_update_command_with_nssai(&allowed, false, true))
                .expect("encode");
        let msg = decode_nas_5gs_message(&bytes).expect("decode");
        assert!(!configuration_update_registration_requested(&msg));
        assert!(configuration_update_acknowledgement_requested(&msg));

        // The UE's Configuration Update Complete round-trips.
        let bytes = encode_nas_5gs_message(&configuration_update_complete()).expect("encode");
        let msg = decode_nas_5gs_message(&bytes).expect("decode");
        assert_eq!(gmm_message_type(&msg), Some(Nas5gmmMessageType::ConfigurationUpdateComplete));
    }

    #[test]
    fn service_request_round_trips() {
        // service type 1 (data), ngKSI 3, 5G-TMSI 0x00A1B2C3.
        let bytes = service_request(1, 3, 0x00A1_B2C3);
        let msg = decode_nas_5gs_message(&bytes).unwrap();
        assert_eq!(gmm_message_type(&msg), Some(Nas5gmmMessageType::ServiceRequest));
        assert_eq!(service_request_info(&msg), Some((1, 0x00A1_B2C3)));
        // A non-ServiceRequest yields nothing.
        assert_eq!(service_request_info(&deregistration_accept()), None);
        // Service Accept round-trips.
        assert_eq!(
            gmm_message_type(&service_accept(None)),
            Some(Nas5gmmMessageType::ServiceAccept)
        );
    }

    #[test]
    fn authentication_failure_synch_round_trips() {
        let auts: Vec<u8> = (0..14).collect();
        let bytes = authentication_failure_synch(&auts);
        let msg = decode_nas_5gs_message(&bytes).unwrap();
        assert_eq!(
            gmm_message_type(&msg),
            Some(Nas5gmmMessageType::AuthenticationFailure)
        );
        assert_eq!(
            authentication_failure_info(&msg),
            Some((GMM_CAUSE_SYNCH_FAILURE, Some(auts)))
        );
        // A non-failure message carries no failure info.
        assert_eq!(authentication_failure_info(&deregistration_accept()), None);
    }

    #[test]
    fn guti_registration_request_round_trips() {
        // A returning UE registers with its 5G-GUTI; the AMF reads the 5G-TMSI
        // back (and still sees the UE's security capabilities).
        let bytes = registration_request_with_guti("999", "70", 0x0000_002A, &[0x20, 0x20]);
        let msg = decode_nas_5gs_message(&bytes).unwrap();
        assert_eq!(guti_tmsi_from_registration_request(&msg), Some(0x2A));
        let Nas5gsMessage::Gmm(_, Nas5gmmMessage::RegistrationRequest(reg)) = &msg else {
            panic!("not a RegistrationRequest");
        };
        assert!(reg.fgs_mobile_identity.as_suci().is_none(), "identity is a GUTI, not a SUCI");
        assert_eq!(
            reg.ue_security_capability.as_ref().map(|c| [c.ea_byte(), c.ia_byte()]),
            Some([0x20, 0x20])
        );
        // A SUCI-bearing request has no GUTI TMSI.
        let suci_req = Nas5gsMessage::new_5gmm(
            Nas5gmmMessageType::RegistrationRequest,
            Nas5gmmMessage::RegistrationRequest(messages::NasRegistrationRequest::new(
                NasFGsRegistrationType::from_parts(
                    RegistrationType::InitialRegistration,
                    false,
                    7,
                    false,
                ),
                suci_mobile_identity("999", "70", "0000000001"),
            )),
        );
        assert_eq!(guti_tmsi_from_registration_request(&suci_req), None);
    }

    #[test]
    fn identity_response_carries_the_suci() {
        let bytes = identity_response_suci("999", "70", "0000000001");
        let msg = decode_nas_5gs_message(&bytes).unwrap();
        assert_eq!(gmm_message_type(&msg), Some(Nas5gmmMessageType::IdentityResponse));
        assert_eq!(supi_from_identity_response(&msg).as_deref(), Some("imsi-999700000000001"));
        // Any other message yields nothing.
        assert_eq!(supi_from_identity_response(&deregistration_accept()), None);
    }

    #[test]
    fn null_scheme_suci_deconceals_to_supi() {
        // A null-scheme SUCI for imsi-999700000000001: MNC "70" carries a 0xF filler; the
        // MSIN "0000000001" is BCD-packed low-nibble-first (last byte 0x10 = digits 0,1).
        let suci = Suci {
            mcc: [9, 9, 9],
            mnc: [7, 0, 0x0F],
            routing_indicator: vec![0xF0, 0xFF],
            protection_scheme: 0,
            home_nw_public_key_id: 0,
            scheme_output: vec![0x00, 0x00, 0x00, 0x00, 0x10],
        };
        assert_eq!(suci_to_supi(&suci), "imsi-999700000000001");
    }

    #[test]
    fn ecies_suci_falls_back_to_canonical_string() {
        // A non-null (ECIES) scheme can't be deconcealed here → canonical SUCI string.
        let suci = Suci {
            mcc: [2, 0, 8],
            mnc: [9, 3, 0x0F],
            routing_indicator: vec![0x00, 0x00],
            protection_scheme: 1,
            home_nw_public_key_id: 1,
            scheme_output: vec![0xDE, 0xAD],
        };
        assert_eq!(suci_to_supi(&suci), "suci-0-208-93-0000-1-1-dead");
    }

    #[test]
    fn ul_nas_transport_round_trips() {
        // A minimal 5GSM PDU Session Establishment Request as the opaque N1 SM container.
        let container = vec![0x2e, 0x01, 0x01, 0xc1];
        let bytes =
            ul_nas_transport_sm(5, container.clone(), Some("ims.corp"), Some((1, Some([1, 2, 3]))));
        let msg = decode_nas_5gs_message(&bytes).expect("decode");
        assert_eq!(gmm_message_type(&msg), Some(Nas5gmmMessageType::UlNasTransport));
        assert_eq!(sm_container_from_ul_nas_transport(&msg), Some((5, container)));
        // The requested DNN (0x25 IE, RFC 1035 labels) and S-NSSAI (0x22 IE) ride along.
        assert_eq!(requested_dnn_from_ul_nas_transport(&msg).as_deref(), Some("ims.corp"));
        assert_eq!(requested_snssai_from_ul_nas_transport(&msg), Some((1, Some([1, 2, 3]))));

        // Without the IEs, extraction yields None (network defaults apply).
        let without =
            decode_nas_5gs_message(&ul_nas_transport_sm(5, vec![0x2e, 0x01, 0x01, 0xc1], None, None))
                .expect("decode");
        assert_eq!(requested_dnn_from_ul_nas_transport(&without), None);
        assert_eq!(requested_snssai_from_ul_nas_transport(&without), None);

        // SST-only slice (no SD).
        let sst_only =
            decode_nas_5gs_message(&ul_nas_transport_sm(5, vec![0x2e], None, Some((2, None))))
                .expect("decode");
        assert_eq!(requested_snssai_from_ul_nas_transport(&sst_only), Some((2, None)));
    }

    #[test]
    fn authentication_request_roundtrips() {
        let rand = [0x11u8; 16];
        let autn = [0x22u8; 16];
        let bytes = authentication_request(0, &rand, &autn);
        let (r, a) = parse_authentication_request(&bytes).expect("parse");
        assert_eq!(r, rand);
        assert_eq!(a, autn);
    }

    #[test]
    fn authentication_response_roundtrips() {
        let res_star = [0x33u8; 16];
        let bytes = authentication_response(&res_star);
        let msg = decode_nas_5gs_message(&bytes).expect("decode");
        assert_eq!(res_star_from_authentication_response(&msg), Some(&res_star[..]));
    }

    #[test]
    fn registration_accept_builds_and_decodes() {
        let allowed = [(1u8, Some([1u8, 2, 3])), (2, None)];
        let rejected = [(9u8, Some([9u8, 9, 9]))];
        let area = [[0u8, 0, 1], [0, 0, 2]];
        let msg = registration_accept("999", "70", 0x01020304, &allowed, &rejected, 3240, &area, None);
        let bytes = encode_nas_5gs_message(&msg).unwrap();
        let back = decode_nas_5gs_message(&bytes).unwrap();
        assert_eq!(
            gmm_message_type(&back),
            Some(Nas5gmmMessageType::RegistrationAccept)
        );
        // The assigned 5G-GUTI's 5G-TMSI reads back (GUTI reallocation, design/85).
        assert_eq!(guti_tmsi_from_registration_accept(&back), Some(0x01020304));
        // The allowed (IEI 0x15) and rejected (IEI 0x11) NSSAIs survive the round trip.
        assert_eq!(allowed_nssai_from_registration_accept(&back), allowed.to_vec());
        assert_eq!(
            rejected_nssai_from_registration_accept(&back),
            vec![((9, Some([9, 9, 9])), nssai_cause::NOT_AVAILABLE_IN_PLMN)]
        );
        // T3512 (IEI 0x5E) rides along — 3240s = 54min = 54 × 1min.
        assert_eq!(
            t3512_octet_from_registration_accept(&back),
            Some(GprsTimer3::from_secs(3240).octet())
        );
        // The registration area (5GS TAI list, IEI 0x54) survives the round trip.
        assert_eq!(registration_area_from_registration_accept(&back), Some(area.to_vec()));

        // No slices / no registration area → no IEs.
        let bare = registration_accept("999", "70", 0x01020304, &[], &[], 3240, &[], None);
        let back = decode_nas_5gs_message(&encode_nas_5gs_message(&bare).unwrap()).unwrap();
        assert!(allowed_nssai_from_registration_accept(&back).is_empty());
        assert!(rejected_nssai_from_registration_accept(&back).is_empty());
        assert_eq!(registration_area_from_registration_accept(&back), None);
    }

    #[test]
    fn mobility_registration_request_roundtrips() {
        let msg = registration_request_mobility("999", "70", 0xCAFE_D00D);
        let back = decode_nas_5gs_message(&encode_nas_5gs_message(&msg).unwrap()).unwrap();
        assert_eq!(gmm_message_type(&back), Some(Nas5gmmMessageType::RegistrationRequest));
        assert_eq!(
            registration_type_from_request(&back),
            Some(RegistrationType::MobilityRegistrationUpdate)
        );
        assert_eq!(guti_tmsi_from_registration_request(&back), Some(0xCAFE_D00D));
        // Other message types have no registration type.
        assert_eq!(registration_type_from_request(&deregistration_accept()), None);

        // A periodic registration updating carries its own type + GUTI.
        let msg = registration_request_periodic("999", "70", 0x0000_00AB);
        let back = decode_nas_5gs_message(&encode_nas_5gs_message(&msg).unwrap()).unwrap();
        assert_eq!(
            registration_type_from_request(&back),
            Some(RegistrationType::PeriodicRegistrationUpdate)
        );
        assert_eq!(guti_tmsi_from_registration_request(&back), Some(0x0000_00AB));
        // No Uplink Data Status IE → no reactivation requested.
        assert!(uplink_data_status_from_registration_request(&back).is_empty());

        // An Uplink Data Status IE (PSI 5 + PSI 9) round-trips to its PSI list.
        let msg = registration_request_with_uplink_data(
            RegistrationType::MobilityRegistrationUpdate,
            "999",
            "70",
            0x0000_00AB,
            &[5, 9],
        );
        let back = decode_nas_5gs_message(&encode_nas_5gs_message(&msg).unwrap()).unwrap();
        assert_eq!(uplink_data_status_from_registration_request(&back), vec![5, 9]);
    }

    #[test]
    fn uplink_data_status_bitmap_encoding() {
        // PSI 5 → octet 3 bit 5 (0x20); PSI 8 → octet 4 bit 0 (0x01).
        assert_eq!(psi_bitmap_value(&[5, 8]), vec![0x20, 0x01]);
        assert_eq!(psis_from_psi_bitmap(&[0x20, 0x01]), vec![5, 8]);
        // Out-of-range PSIs are dropped; an empty set is all-zero.
        assert_eq!(psi_bitmap_value(&[]), vec![0, 0]);
        assert!(psis_from_psi_bitmap(&[0, 0]).is_empty());
    }

    #[test]
    fn pdu_session_status_reconciliation_ies() {
        // UE side: a Service Request carrying a PDU Session Status IE round-trips to
        // the UE's active-session view; a plain Service Request reports nothing.
        let raw = service_request_with_pdu_status(1, 0, 0x0000_00AB, &[5, 6]);
        let back = decode_nas_5gs_message(&raw).unwrap();
        assert_eq!(pdu_session_status_from_request(&back), Some(vec![5, 6]));
        let plain = decode_nas_5gs_message(&service_request(1, 0, 0x0000_00AB)).unwrap();
        assert_eq!(pdu_session_status_from_request(&plain), None, "IE absent → no view");

        // Network side: a Service Accept advertising its active set round-trips; the
        // minimal accept omits the IE.
        let acc = service_accept(Some(&[5]));
        let back = decode_nas_5gs_message(&encode_nas_5gs_message(&acc).unwrap()).unwrap();
        assert_eq!(pdu_session_status_from_accept(&back), Some(vec![5]));
        let bare = decode_nas_5gs_message(&encode_nas_5gs_message(&service_accept(None)).unwrap()).unwrap();
        assert_eq!(pdu_session_status_from_accept(&bare), None);

        // A Registration Accept carries the same IE (reconciliation on a reg update).
        let reg = registration_accept("999", "70", 1, &[], &[], 3240, &[], Some(&[7]));
        let back = decode_nas_5gs_message(&encode_nas_5gs_message(&reg).unwrap()).unwrap();
        assert_eq!(pdu_session_status_from_accept(&back), Some(vec![7]));
    }

    #[test]
    fn tai_list_value_encodes_type_00() {
        // 2 TACs, PLMN 999/70: [count-1=1][TBCD 99 F9 07][TAC][TAC].
        let v = tai_list_value("999", "70", &[[0, 0, 1], [0, 0, 0x0a]]);
        assert_eq!(v, [0x01, 0x99, 0xf9, 0x07, 0, 0, 1, 0, 0, 0x0a]);
        // A partial list caps at 16 TACs.
        let many: Vec<[u8; 3]> = (0..20).map(|i| [0, 0, i as u8]).collect();
        let v = tai_list_value("999", "70", &many);
        assert_eq!(v[0], 15, "count-1 capped at 16 elements");
        assert_eq!(v.len(), 1 + 3 + 16 * 3);
    }

    #[test]
    fn nssai_value_roundtrips() {
        let slices = vec![(1u8, Some([0x01, 0x02, 0x03])), (7, None)];
        assert_eq!(nssai_value(&slices), [4, 1, 1, 2, 3, 1, 7]);
        assert_eq!(parse_nssai_value(&nssai_value(&slices)), slices);
        assert!(parse_nssai_value(&[]).is_empty());
        // A truncated entry stops the parse instead of panicking.
        assert_eq!(parse_nssai_value(&[4, 1, 2]), Vec::<(u8, Option<[u8; 3]>)>::new());
    }

    #[test]
    fn registration_reject_roundtrips() {
        let rejected = [(9u8, Some([9u8, 9, 9]))];
        let msg = registration_reject(
            mm_cause::NO_NETWORK_SLICES_AVAILABLE,
            &rejected,
            Some(GprsTimer2::from_secs(600)),
        );
        let back = decode_nas_5gs_message(&encode_nas_5gs_message(&msg).unwrap()).unwrap();
        assert_eq!(gmm_message_type(&back), Some(Nas5gmmMessageType::RegistrationReject));
        assert_eq!(
            parse_registration_reject(&back),
            Some((
                62,
                vec![((9, Some([9, 9, 9])), nssai_cause::NOT_AVAILABLE_IN_PLMN)],
                Some(0b001_01010), // 600s = 10 x 1min
            ))
        );

        // Without rejected slices or back-off, only the cause rides.
        let bare = registration_reject(mm_cause::NO_NETWORK_SLICES_AVAILABLE, &[], None);
        let back = decode_nas_5gs_message(&encode_nas_5gs_message(&bare).unwrap()).unwrap();
        assert_eq!(parse_registration_reject(&back), Some((62, vec![], None)));
    }

    #[test]
    fn deregistration_roundtrips() {
        // Normal deregistration (3GPP access, no switch-off) — bit 4 clear.
        let req = deregistration_request_from_ue(0x01, "999", "70", 1);
        let back = decode_nas_5gs_message(&encode_nas_5gs_message(&req).unwrap()).unwrap();
        assert_eq!(gmm_message_type(&back), Some(Nas5gmmMessageType::DeregistrationRequestFromUe));
        assert_eq!(deregistration_is_switch_off(&back), Some(false));

        // Switch-off (bit 4 set) — the UE expects no accept.
        let req = deregistration_request_from_ue(0x09, "999", "70", 1);
        let back = decode_nas_5gs_message(&encode_nas_5gs_message(&req).unwrap()).unwrap();
        assert_eq!(deregistration_is_switch_off(&back), Some(true));

        // The UE-terminated accept round-trips.
        let acc = deregistration_accept_to_ue();
        let back = decode_nas_5gs_message(&encode_nas_5gs_message(&acc).unwrap()).unwrap();
        assert_eq!(gmm_message_type(&back), Some(Nas5gmmMessageType::DeregistrationAcceptToUe));

        // Network-initiated request (UE terminated) round-trips.
        let req = deregistration_request_to_ue(0x01);
        let back = decode_nas_5gs_message(&encode_nas_5gs_message(&req).unwrap()).unwrap();
        assert_eq!(gmm_message_type(&back), Some(Nas5gmmMessageType::DeregistrationRequestToUe));

        // The accept is header-only and round-trips.
        let acc = deregistration_accept();
        let back = decode_nas_5gs_message(&encode_nas_5gs_message(&acc).unwrap()).unwrap();
        assert_eq!(gmm_message_type(&back), Some(Nas5gmmMessageType::DeregistrationAcceptFromUe));
        // A non-dereg message yields None (not a bool).
        assert_eq!(deregistration_is_switch_off(&back), None);
    }

    #[test]
    fn gprs_timer2_unit_selection() {
        assert_eq!(GprsTimer2::from_secs(60).octet(), 0b000_11110, "60s = 30 x 2s");
        assert_eq!(GprsTimer2::from_secs(63).octet(), 0b001_00010, "63s rounds up to 2 x 1min");
        assert_eq!(GprsTimer2::from_secs(600).octet(), 0b001_01010, "10min = 10 x 1min");
        assert_eq!(GprsTimer2::from_secs(3_600).octet(), 0b010_01010, "1h = 10 x 6min");
        // Beyond the encodable range: clamp to 31 decihours.
        assert_eq!(GprsTimer2::from_secs(u32::MAX).octet(), 0b010_11111);
        assert_eq!(GprsTimer2::deactivated().octet(), 0b111_00000);
    }

    #[test]
    fn rejected_nssai_value_roundtrips() {
        let slices = vec![(1u8, Some([0x01, 0x02, 0x03])), (7, None)];
        // Head octet = (contents-length << 4) | cause.
        assert_eq!(rejected_nssai_value(&slices, 0), [0x40, 1, 1, 2, 3, 0x10, 7]);
        assert_eq!(
            parse_rejected_nssai_value(&rejected_nssai_value(&slices, 0)),
            vec![((1, Some([1, 2, 3])), 0), ((7, None), 0)]
        );
        assert_eq!(parse_rejected_nssai_value(&[0x41, 1, 2]), vec![], "truncated entry");
    }

    #[test]
    fn requested_nssai_extraction_from_registration_request() {
        let identity = NasFGsMobileIdentity::from_guti(&Guti {
            mcc: [9, 9, 9],
            mnc: [7, 0, 0x0F],
            amf_region_id: 1,
            amf_set_id: 1,
            amf_pointer: 0,
            tmsi: 1,
        });
        let requested = vec![(1u8, Some([1u8, 2, 3])), (2, None)];
        let reg = messages::NasRegistrationRequest::new(
            NasFGsRegistrationType::new(0x09), // initial registration
            identity.clone(),
        )
        .set_requested_nssai(NasNssai::new(nssai_value(&requested)));
        let msg = Nas5gsMessage::new_5gmm(
            Nas5gmmMessageType::RegistrationRequest,
            Nas5gmmMessage::RegistrationRequest(reg),
        );
        let back = decode_nas_5gs_message(&encode_nas_5gs_message(&msg).unwrap()).unwrap();
        assert_eq!(requested_nssai_from_registration_request(&back), requested);

        // Omitted IE → empty (the network grants the subscribed defaults).
        let bare = messages::NasRegistrationRequest::new(NasFGsRegistrationType::new(0x09), identity);
        let msg = Nas5gsMessage::new_5gmm(
            Nas5gmmMessageType::RegistrationRequest,
            Nas5gmmMessage::RegistrationRequest(bare),
        );
        let back = decode_nas_5gs_message(&encode_nas_5gs_message(&msg).unwrap()).unwrap();
        assert!(requested_nssai_from_registration_request(&back).is_empty());
    }

    #[test]
    fn nas_security_protect_unprotect() {
        // AMF and UE share keys/algorithms (NIA2 / NEA2); each has its own context.
        let (ki, ke) = ([0x11u8; 16], [0x22u8; 16]);
        let mut amf = NasSecurityContext::new(ki, ke, 2, 2);
        let mut ue = NasSecurityContext::new(ki, ke, 2, 2);

        // Integrity-protected (new context) Security Mode Command, downlink.
        let smc = security_mode_command(2, 2, 0, &[0xE0, 0xE0]);
        let protected = amf.protect(&smc, sht::INTEGRITY_NEW_CONTEXT, 1);
        let decoded = ue.unprotect(&protected, 1).expect("UE verifies + decodes SMC");
        assert_eq!(
            gmm_message_type(&decoded),
            Some(Nas5gmmMessageType::SecurityModeCommand)
        );

        // Integrity-protected + ciphered Registration Accept, downlink.
        let accept = registration_accept("999", "70", 0xDEAD_BEEF, &[], &[], 3240, &[], None);
        let protected = amf.protect(&accept, sht::INTEGRITY_CIPHERED, 1);
        let decoded = ue.unprotect(&protected, 1).expect("UE verifies + deciphers Accept");
        assert_eq!(
            gmm_message_type(&decoded),
            Some(Nas5gmmMessageType::RegistrationAccept)
        );

        // A tampered MAC is rejected.
        let mut bad = amf.protect(&security_mode_complete(), sht::INTEGRITY, 1);
        bad[2] ^= 0xff;
        assert!(ue.unprotect(&bad, 1).is_none());
    }
}
