//! 5G-AKA — Authentication and Key Agreement (TS 33.501).
//!
//! Network-side 5G-AKA crypto: the UDM/ARPF generates the authentication vector
//! (RAND, AUTN, XRES*, K_AUSF), the AUSF derives HXRES*/K_SEAF, and the UE side
//! (used in tests and a UE simulator) verifies AUTN and computes RES*. Built on
//! MILENAGE (f1–f5) and the TS 33.501 key-derivation functions.

use milenage::Milenage;
use oxirush_security::{compute_hres_star, derive_kausf, derive_kseaf};

#[derive(Debug, thiserror::Error)]
pub enum AkaError {
    #[error("milenage: {0}")]
    Milenage(String),
    #[error("authentication failure: {0}")]
    AuthFailure(&'static str),
}

/// Long-term subscriber credentials held by the UDM/ARPF.
#[derive(Debug, Clone)]
pub struct SubscriberKey {
    pub k: [u8; 16],
    pub opc: [u8; 16],
    /// Authentication Management Field — the AKA AMF (not the AMF network function).
    pub amf: [u8; 2],
}

/// 5G Home Environment Authentication Vector (TS 33.501 §6.1.3.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthVector {
    pub rand: [u8; 16],
    pub autn: [u8; 16],
    pub xres_star: [u8; 16],
    pub kausf: [u8; 32],
}

/// K_AUSF derivation FC. Free5GC / UERANSIM use 0x6A.
const KAUSF_FC: u8 = 0x6A;

/// Serving network name (TS 24.501 §9.11.3.4): `5G:mnc<MNC3>.mcc<MCC>.3gppnetwork.org`.
pub fn serving_network_name(mcc: &str, mnc: &str) -> String {
    let mnc3 = if mnc.len() == 2 {
        format!("0{mnc}")
    } else {
        mnc.to_string()
    };
    format!("5G:mnc{mnc3}.mcc{mcc}.3gppnetwork.org")
}

/// UDM/ARPF: generate the 5G HE authentication vector for a subscriber.
pub fn generate_5g_he_av(
    sub: &SubscriberKey,
    sqn: &[u8; 6],
    rand: &[u8; 16],
    mcc: &str,
    mnc: &str,
) -> Result<AuthVector, AkaError> {
    let mut m = Milenage::new_with_opc(sub.k, sub.opc);
    let mac_a = m.f1(rand, sqn, &sub.amf);
    let (res, ck, ik, ak) = m.f2345(rand);

    let autn = assemble_autn(sqn, &ak, &sub.amf, &mac_a);
    let xres_star = m
        .compute_res_star(mcc, mnc, rand, &res)
        .map_err(|e| AkaError::Milenage(format!("{e:?}")))?;

    let snn = serving_network_name(mcc, mnc);
    let sqn_xor_ak = xor6(sqn, &ak);
    let kausf = derive_kausf(&ck, &ik, snn.as_bytes(), &sqn_xor_ak, KAUSF_FC);

    Ok(AuthVector {
        rand: *rand,
        autn,
        xres_star,
        kausf,
    })
}

/// AUSF: HXRES* = SHA-256(RAND || XRES*)[16..] (TS 33.501 Annex A.5).
pub fn hxres_star(rand: &[u8; 16], xres_star: &[u8; 16]) -> [u8; 16] {
    compute_hres_star(rand, xres_star)
}

/// AUSF: K_SEAF from K_AUSF (TS 33.501 Annex A.6).
pub fn kseaf(kausf: &[u8; 32], mcc: &str, mnc: &str) -> [u8; 32] {
    derive_kseaf(kausf, serving_network_name(mcc, mnc).as_bytes())
}

/// 128-bit NAS keys derived from K_AMF (TS 33.501 Annex A.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NasKeys {
    pub knas_int: [u8; 16],
    pub knas_enc: [u8; 16],
}

/// AMF: derive K_AMF from K_SEAF (TS 33.501 Annex A.7). `supi` may carry the
/// `imsi-` prefix (stripped); `abba` is typically `[0x00, 0x00]`.
pub fn kamf(kseaf: &[u8; 32], supi: &str, abba: &[u8]) -> [u8; 32] {
    let digits = supi.strip_prefix("imsi-").unwrap_or(supi);
    oxirush_security::derive_kamf(kseaf, digits, abba)
}

/// AMF/UE: derive the 128-bit NAS integrity/ciphering keys (TS 33.501 Annex A.8).
/// `nea`/`nia` are the algorithm identifiers (e.g. 2 for 128-NEA2 / 128-NIA2).
pub fn nas_keys(kamf: &[u8; 32], nea: u8, nia: u8) -> NasKeys {
    use oxirush_security::{derive_nas_key, extract_128};
    NasKeys {
        knas_enc: extract_128(&derive_nas_key(kamf, 0x01, nea)),
        knas_int: extract_128(&derive_nas_key(kamf, 0x02, nia)),
    }
}

/// UE side: verify AUTN and compute RES* (TS 33.501). Used by tests / a UE simulator.
pub fn ue_compute_res_star(
    sub: &SubscriberKey,
    rand: &[u8; 16],
    autn: &[u8; 16],
    mcc: &str,
    mnc: &str,
) -> Result<[u8; 16], AkaError> {
    let mut m = Milenage::new_with_opc(sub.k, sub.opc);
    let (res, _ck, _ik, ak) = m.f2345(rand);

    // Recover SQN = (SQN ⊕ AK) ⊕ AK, then verify MAC-A against AUTN.
    let sqn = xor6(&autn[..6], &ak);
    let amf: [u8; 2] = autn[6..8].try_into().expect("2-byte AMF slice");
    let mac_a = m.f1(rand, &sqn, &amf);
    if mac_a[..] != autn[8..16] {
        return Err(AkaError::AuthFailure("AUTN MAC mismatch"));
    }

    m.compute_res_star(mcc, mnc, rand, &res)
        .map_err(|e| AkaError::Milenage(format!("{e:?}")))
}

fn assemble_autn(sqn: &[u8; 6], ak: &[u8; 6], amf: &[u8; 2], mac_a: &[u8; 8]) -> [u8; 16] {
    let mut autn = [0u8; 16];
    autn[..6].copy_from_slice(&xor6(sqn, ak));
    autn[6..8].copy_from_slice(amf);
    autn[8..16].copy_from_slice(mac_a);
    autn
}

fn xor6(a: &[u8], b: &[u8; 6]) -> [u8; 6] {
    let mut o = [0u8; 6];
    for i in 0..6 {
        o[i] = a[i] ^ b[i];
    }
    o
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn milenage_test_set_1() {
        // 3GPP TS 35.208 Test Set 1.
        let k = hex!("465b5ce8b199b49faa5f0a2ee238a6bc");
        let op = hex!("cdc202d5123e20f62b6d676ac72cb318");
        let rand = hex!("23553cbe9637a89d218ae64dae47bf35");
        let sqn = hex!("ff9bb4d0b607");
        let amf = hex!("b9b9");

        let mut m = Milenage::new_with_op(k, op);
        let mac_a = m.f1(&rand, &sqn, &amf);
        let (res, ck, ik, ak) = m.f2345(&rand);

        assert_eq!(mac_a, hex!("4a9ffac354dfafb3"));
        assert_eq!(res, hex!("a54211d5e3ba50bf"));
        assert_eq!(ak, hex!("aa689c648370"));
        assert_eq!(ck, hex!("b40ba9a3c58b2a05bbf0d987b21bf8cb"));
        assert_eq!(ik, hex!("f769bcd751044604127672711c6d3441"));
    }

    fn test_subscriber() -> SubscriberKey {
        // TS 35.208 Test Set 1 key + its derived OPc.
        SubscriberKey {
            k: hex!("465b5ce8b199b49faa5f0a2ee238a6bc"),
            opc: hex!("cd63cb71954a9f4e48a5994e37a02baf"),
            amf: hex!("8000"),
        }
    }

    #[test]
    fn five_g_aka_roundtrip_succeeds() {
        let sub = test_subscriber();
        let sqn = hex!("000000000001");
        let rand = hex!("23553cbe9637a89d218ae64dae47bf35");
        let (mcc, mnc) = ("999", "70");

        // UDM generates the 5G HE AV; AUSF computes HXRES*.
        let av = generate_5g_he_av(&sub, &sqn, &rand, mcc, mnc).unwrap();
        let hxres = hxres_star(&av.rand, &av.xres_star);
        let _kseaf = kseaf(&av.kausf, mcc, mnc);

        // UE verifies AUTN and computes RES*.
        let res_star = ue_compute_res_star(&sub, &av.rand, &av.autn, mcc, mnc).unwrap();

        // Confirmation: RES* == XRES*, and HRES*(RAND, RES*) == HXRES*.
        assert_eq!(res_star, av.xres_star, "RES* must equal XRES*");
        assert_eq!(
            hxres_star(&av.rand, &res_star),
            hxres,
            "HRES* must equal HXRES*"
        );
    }

    #[test]
    fn ue_rejects_tampered_autn() {
        let sub = test_subscriber();
        let sqn = hex!("000000000001");
        let rand = hex!("23553cbe9637a89d218ae64dae47bf35");
        let mut av = generate_5g_he_av(&sub, &sqn, &rand, "999", "70").unwrap();
        av.autn[15] ^= 0xff; // corrupt MAC-A
        assert!(ue_compute_res_star(&sub, &av.rand, &av.autn, "999", "70").is_err());
    }
}
