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

/// Build a 5GMM **Registration Complete** (TS 24.501 §8.2.8). UE side / tests.
pub fn registration_complete() -> Nas5gsMessage {
    Nas5gsMessage::new_5gmm(
        Nas5gmmMessageType::RegistrationComplete,
        Nas5gmmMessage::RegistrationComplete(messages::NasRegistrationComplete::new()),
    )
}

/// Build and encode a 5GMM **UL NAS Transport** (TS 24.501 §8.2.10) carrying an N1 SM
/// container (a 5GSM message) for `pdu_session_id`. UE side / tests — the AMF relays
/// the container to the SMF transparently.
pub fn ul_nas_transport_sm(pdu_session_id: u8, sm_container: Vec<u8>) -> Vec<u8> {
    let transport = messages::NasUlNasTransport::new(
        NasPayloadContainerType::new(0x01), // N1 SM information
        NasPayloadContainer::new(sm_container),
    )
    .set_pdu_session_id(NasPduSessionIdentity2::new(pdu_session_id));
    let msg = Nas5gsMessage::new_5gmm(
        Nas5gmmMessageType::UlNasTransport,
        Nas5gmmMessage::UlNasTransport(transport),
    );
    encode_nas_5gs_message(&msg).expect("encode UlNasTransport")
}

/// Extract `(pdu_session_id, N1 SM container)` from a decoded 5GMM UL NAS Transport.
pub fn sm_container_from_ul_nas_transport(msg: &Nas5gsMessage) -> Option<(u8, Vec<u8>)> {
    let Nas5gsMessage::Gmm(_, Nas5gmmMessage::UlNasTransport(transport)) = msg else {
        return None;
    };
    let psi = transport.pdu_session_id.as_ref()?.value;
    Some((psi, transport.payload_container.value.clone()))
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
    fn ul_nas_transport_round_trips() {
        // A minimal 5GSM PDU Session Establishment Request as the opaque N1 SM container.
        let container = vec![0x2e, 0x01, 0x01, 0xc1];
        let bytes = ul_nas_transport_sm(5, container.clone());
        let msg = decode_nas_5gs_message(&bytes).expect("decode");
        assert_eq!(gmm_message_type(&msg), Some(Nas5gmmMessageType::UlNasTransport));
        assert_eq!(sm_container_from_ul_nas_transport(&msg), Some((5, container)));
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
