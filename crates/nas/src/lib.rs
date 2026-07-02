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

/// Build a 5GMM **Registration Accept** (TS 24.501 §8.2.7) assigning a 5G-GUTI.
pub fn registration_accept(mcc: &str, mnc: &str, tmsi: u32) -> Nas5gsMessage {
    let guti = NasFGsMobileIdentity::from_guti(&Guti {
        mcc: mcc_digits(mcc),
        mnc: mnc_digits(mnc),
        amf_region_id: 0x01,
        amf_set_id: 0x001,
        amf_pointer: 0x00,
        tmsi,
    });
    let accept = messages::NasRegistrationAccept::new(NasFGsRegistrationResult::new(vec![0x01]))
        .set_fg_guti(guti);
    Nas5gsMessage::new_5gmm(
        Nas5gmmMessageType::RegistrationAccept,
        Nas5gmmMessage::RegistrationAccept(accept),
    )
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

/// Build a 5GMM **Registration Complete** (TS 24.501 §8.2.8). UE side / tests.
pub fn registration_complete() -> Nas5gsMessage {
    Nas5gsMessage::new_5gmm(
        Nas5gmmMessageType::RegistrationComplete,
        Nas5gmmMessage::RegistrationComplete(messages::NasRegistrationComplete::new()),
    )
}

/// Build and encode a 5GMM **UL NAS Transport** (TS 24.501 §8.2.10) carrying an N1 SM
/// container (a 5GSM message) for `pdu_session_id`, optionally with the UE's requested
/// **DNN** IE. UE side / tests — the AMF relays the container to the SMF transparently.
pub fn ul_nas_transport_sm(pdu_session_id: u8, sm_container: Vec<u8>, dnn: Option<&str>) -> Vec<u8> {
    let mut transport = messages::NasUlNasTransport::new(
        NasPayloadContainerType::new(0x01), // N1 SM information
        NasPayloadContainer::new(sm_container),
    )
    .set_pdu_session_id(NasPduSessionIdentity2::new(pdu_session_id));
    if let Some(dnn) = dnn {
        transport = transport.set_dnn(NasDnn::from_string(dnn));
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
    // DNN (IEI 0x25): RFC 1035 label form — a length-prefixed label per dot-separated part.
    m.push(0x25);
    let dnn_buf: Vec<u8> = rfc1035_labels(dnn);
    m.push(dnn_buf.len() as u8);
    m.extend_from_slice(&dnn_buf);
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
            pdu_session_establishment_accept(5, 1, ue_ip, "internet", 1, Some([1, 2, 3]), ambr);
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
        let bytes = ul_nas_transport_sm(5, container.clone(), Some("ims.corp"));
        let msg = decode_nas_5gs_message(&bytes).expect("decode");
        assert_eq!(gmm_message_type(&msg), Some(Nas5gmmMessageType::UlNasTransport));
        assert_eq!(sm_container_from_ul_nas_transport(&msg), Some((5, container)));
        // The requested DNN rides in the transport's 0x25 IE (RFC 1035 labels).
        assert_eq!(requested_dnn_from_ul_nas_transport(&msg).as_deref(), Some("ims.corp"));

        // Without the IE, extraction yields None (network default applies).
        let without = decode_nas_5gs_message(&ul_nas_transport_sm(5, vec![0x2e, 0x01, 0x01, 0xc1], None))
            .expect("decode");
        assert_eq!(requested_dnn_from_ul_nas_transport(&without), None);
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
        let msg = registration_accept("999", "70", 0x01020304);
        let bytes = encode_nas_5gs_message(&msg).unwrap();
        let back = decode_nas_5gs_message(&bytes).unwrap();
        assert_eq!(
            gmm_message_type(&back),
            Some(Nas5gmmMessageType::RegistrationAccept)
        );
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
        let accept = registration_accept("999", "70", 0xDEAD_BEEF);
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
