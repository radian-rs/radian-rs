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

#[cfg(test)]
mod tests {
    use super::*;

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
}
