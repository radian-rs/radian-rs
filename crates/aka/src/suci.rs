//! SUCI deconcealment (TS 33.501 Annex C; TS 23.003 §2.2B) — recover the SUPI from a
//! Subscription Concealed Identifier presented to the UDM. Three protection schemes:
//!
//! - **Null** (scheme 0): the scheme output *is* the MSIN in the clear.
//! - **Profile A** (scheme 1): ECIES over **X25519**.
//! - **Profile B** (scheme 2): ECIES over **P-256** (compressed points).
//!
//! Both ECIES profiles share the same construction (TS 33.501 C.3.2): ephemeral-static
//! ECDH → **ANSI-X9.63 KDF** (SHA-256) → the first 16 octets are the AES-128 key, the
//! next 16 the initial counter block, the last 32 the HMAC-SHA-256 key. The scheme
//! output is `ephemeral_public_key ‖ ciphertext ‖ MAC-tag`, where the MAC is
//! HMAC-SHA-256 over the ciphertext truncated to 8 octets, and the ciphertext is the
//! TBCD-encoded MSIN under AES-128-CTR.
//!
//! The home network's **private** key stays at the UDM; the UE conceals with the
//! matching public key. [`conceal`] (the UE side) exists for round-trip tests.

use std::collections::BTreeMap;

use ctr::cipher::{KeyIvInit, StreamCipher};
use hmac::{Hmac, Mac};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use sha2::{Digest, Sha256};

type Aes128Ctr = ctr::Ctr128BE<aes::Aes128>;
type HmacSha256 = Hmac<Sha256>;

/// Why a SUCI could not be deconcealed.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SuciError {
    #[error("malformed SUCI")]
    Malformed,
    #[error("unsupported protection scheme {0}")]
    UnknownScheme(String),
    #[error("no home-network private key for scheme {scheme} key id {key_id}")]
    NoKey { scheme: &'static str, key_id: u8 },
    #[error("ECIES MAC verification failed")]
    BadMac,
}

/// The home network's ECIES **private** keys, by protection scheme and key id (the
/// SUCI names which via its Home Network Public Key Id). One key per scheme is the
/// common case; the map allows key rotation.
#[derive(Default)]
pub struct HomeNetworkKeys {
    /// Profile A: 32-byte X25519 static private keys.
    profile_a: BTreeMap<u8, [u8; 32]>,
    /// Profile B: 32-byte P-256 private scalars.
    profile_b: BTreeMap<u8, [u8; 32]>,
}

impl HomeNetworkKeys {
    /// No keys — only the null scheme (and plain-SUPI passthrough) will deconceal.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Add a Profile A (X25519) private key under `key_id`.
    pub fn with_profile_a(mut self, key_id: u8, private_key: [u8; 32]) -> Self {
        self.profile_a.insert(key_id, private_key);
        self
    }

    /// Add a Profile B (P-256) private scalar under `key_id`.
    pub fn with_profile_b(mut self, key_id: u8, private_key: [u8; 32]) -> Self {
        self.profile_b.insert(key_id, private_key);
        self
    }

    /// Whether any ECIES key is configured (else only null-scheme SUCIs deconceal).
    pub fn is_empty(&self) -> bool {
        self.profile_a.is_empty() && self.profile_b.is_empty()
    }
}

/// Recover the SUPI from `input`. A plain SUPI (`imsi-…`, not starting with `suci-`)
/// is returned unchanged, so a caller can pass either. A SUCI is parsed and, for a
/// protected scheme, deconcealed with the matching home-network private key.
///
/// SUCI string form (TS 29.571): `suci-<supiType>-<mcc>-<mnc>-<routingInd>-<scheme>-<keyId>-<schemeOutput>`.
pub fn deconceal(input: &str, keys: &HomeNetworkKeys) -> Result<String, SuciError> {
    if !input.starts_with("suci-") {
        return Ok(input.to_string()); // already a SUPI
    }
    let f: Vec<&str> = input.split('-').collect();
    // supiType 0 = IMSI (the only type this UDM serves).
    let [_, "0", mcc, mnc, _routing, scheme, key_id, output] = f.as_slice() else {
        return Err(SuciError::Malformed);
    };
    let key_id: u8 = key_id.parse().map_err(|_| SuciError::Malformed)?;
    let msin = match *scheme {
        "0" => (*output).to_string(),
        "1" => {
            let priv_key =
                keys.profile_a.get(&key_id).ok_or(SuciError::NoKey { scheme: "A", key_id })?;
            decrypt_ecies(output, EciesProfile::a(priv_key))?
        }
        "2" => {
            let priv_key =
                keys.profile_b.get(&key_id).ok_or(SuciError::NoKey { scheme: "B", key_id })?;
            decrypt_ecies(output, EciesProfile::b(priv_key))?
        }
        other => return Err(SuciError::UnknownScheme(other.to_string())),
    };
    Ok(format!("imsi-{mcc}{mnc}{msin}"))
}

// ── ECIES (shared by Profile A and B) ────────────────────────────────────────────

/// The curve-specific half of ECIES: the ephemeral public key length and the two
/// primitives that differ between profiles (the static→ephemeral ECDH, and — for
/// [`conceal`] — an ephemeral keypair generator).
struct EciesProfile<'a> {
    eph_pub_len: usize,
    /// ECDH between the home-net private key and the UE's ephemeral public key,
    /// yielding the shared secret Z.
    ecdh: Box<dyn Fn(&[u8]) -> Result<Vec<u8>, SuciError> + 'a>,
}

impl<'a> EciesProfile<'a> {
    fn a(private_key: &'a [u8; 32]) -> Self {
        Self {
            eph_pub_len: 32,
            ecdh: Box::new(move |eph_pub| {
                let secret = x25519_dalek::StaticSecret::from(*private_key);
                let their: [u8; 32] = eph_pub.try_into().map_err(|_| SuciError::Malformed)?;
                Ok(secret.diffie_hellman(&x25519_dalek::PublicKey::from(their)).as_bytes().to_vec())
            }),
        }
    }

    fn b(private_key: &'a [u8; 32]) -> Self {
        Self {
            eph_pub_len: 33, // compressed SEC1 point
            ecdh: Box::new(move |eph_pub| {
                let secret = p256::SecretKey::from_slice(private_key)
                    .map_err(|_| SuciError::Malformed)?;
                let public =
                    p256::PublicKey::from_sec1_bytes(eph_pub).map_err(|_| SuciError::Malformed)?;
                let shared = p256::ecdh::diffie_hellman(
                    secret.to_nonzero_scalar(),
                    public.as_affine(),
                );
                Ok(shared.raw_secret_bytes().to_vec())
            }),
        }
    }
}

/// Deconceal a hex `scheme output` = `eph_pub ‖ ciphertext ‖ MAC(8)`: ECDH → KDF →
/// verify the MAC → AES-128-CTR decrypt → TBCD-decode to the MSIN digits.
fn decrypt_ecies(output_hex: &str, profile: EciesProfile) -> Result<String, SuciError> {
    let bytes = hex::decode(output_hex).map_err(|_| SuciError::Malformed)?;
    if bytes.len() < profile.eph_pub_len + MAC_LEN {
        return Err(SuciError::Malformed);
    }
    let (eph_pub, rest) = bytes.split_at(profile.eph_pub_len);
    let (ciphertext, mac_tag) = rest.split_at(rest.len() - MAC_LEN);

    let z = (profile.ecdh)(eph_pub)?;
    let (aes_key, icb, mac_key) = ecies_kdf(&z, eph_pub);
    if hmac_sha256_64(&mac_key, ciphertext) != mac_tag {
        return Err(SuciError::BadMac);
    }
    let mut plain = ciphertext.to_vec();
    Aes128Ctr::new(&aes_key.into(), &icb.into()).apply_keystream(&mut plain);
    Ok(tbcd_decode(&plain))
}

const MAC_LEN: usize = 8;

/// The ECIES KDF (TS 33.501 C.3.2): ANSI-X9.63-KDF with SHA-256 over `Z ‖ counter ‖
/// eph_pub`, partitioned into the AES-128 key (16), the initial counter block (16),
/// and the HMAC key (32).
fn ecies_kdf(z: &[u8], eph_pub: &[u8]) -> ([u8; 16], [u8; 16], [u8; 32]) {
    let mut derived = Vec::with_capacity(64);
    let mut counter: u32 = 1;
    while derived.len() < 64 {
        let mut h = Sha256::new();
        h.update(z);
        h.update(counter.to_be_bytes());
        h.update(eph_pub); // SharedInfo = the ephemeral public key
        derived.extend_from_slice(&h.finalize());
        counter += 1;
    }
    let mut aes_key = [0u8; 16];
    let mut icb = [0u8; 16];
    let mut mac_key = [0u8; 32];
    aes_key.copy_from_slice(&derived[0..16]);
    icb.copy_from_slice(&derived[16..32]);
    mac_key.copy_from_slice(&derived[32..64]);
    (aes_key, icb, mac_key)
}

/// HMAC-SHA-256 truncated to the leftmost 8 octets (the ECIES MAC tag).
fn hmac_sha256_64(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes()[..MAC_LEN].to_vec()
}

/// Decode packed **TBCD** (TS 29.002): each octet holds two digits, low nibble first;
/// a `0xF` nibble is the odd-length filler and is dropped.
fn tbcd_decode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        for nibble in [b & 0x0F, b >> 4] {
            if nibble != 0x0F {
                s.push((b'0' + nibble.min(9)) as char);
            }
        }
    }
    s
}

/// Encode decimal digits as packed TBCD (the inverse of [`tbcd_decode`]).
fn tbcd_encode(digits: &str) -> Vec<u8> {
    let vals: Vec<u8> = digits.bytes().map(|d| d - b'0').collect();
    vals.chunks(2)
        .map(|c| c[0] | (c.get(1).copied().unwrap_or(0x0F) << 4))
        .collect()
}

// ── Conceal (the UE side) — for round-trip tests ─────────────────────────────────

/// Conceal `msin` for the home network identified by `(mcc, mnc)` under Profile A or B
/// (`scheme` = `"1"`/`"2"`), producing a SUCI string. The UE side of ECIES: an
/// ephemeral keypair, ECDH against the home-net **public** key, the same KDF, then
/// AES-128-CTR + the MAC tag. Used to round-trip [`deconceal`] in tests.
pub fn conceal(
    mcc: &str,
    mnc: &str,
    msin: &str,
    scheme: &str,
    key_id: u8,
    home_net_public_key: &[u8],
) -> Result<String, SuciError> {
    let (eph_pub, z) = match scheme {
        "1" => {
            let eph_priv = random_scalar();
            let secret = x25519_dalek::StaticSecret::from(eph_priv);
            let their: [u8; 32] =
                home_net_public_key.try_into().map_err(|_| SuciError::Malformed)?;
            let z = secret.diffie_hellman(&x25519_dalek::PublicKey::from(their)).as_bytes().to_vec();
            (x25519_dalek::PublicKey::from(&secret).as_bytes().to_vec(), z)
        }
        "2" => {
            let eph_secret = loop {
                if let Ok(s) = p256::SecretKey::from_slice(&random_scalar()) {
                    break s;
                }
            };
            let public = p256::PublicKey::from_sec1_bytes(home_net_public_key)
                .map_err(|_| SuciError::Malformed)?;
            let z = p256::ecdh::diffie_hellman(eph_secret.to_nonzero_scalar(), public.as_affine())
                .raw_secret_bytes()
                .to_vec();
            let eph_pub = eph_secret.public_key().to_encoded_point(true).as_bytes().to_vec();
            (eph_pub, z)
        }
        other => return Err(SuciError::UnknownScheme(other.to_string())),
    };
    let (aes_key, icb, mac_key) = ecies_kdf(&z, &eph_pub);
    let mut ciphertext = tbcd_encode(msin);
    Aes128Ctr::new(&aes_key.into(), &icb.into()).apply_keystream(&mut ciphertext);
    let mac = hmac_sha256_64(&mac_key, &ciphertext);
    let output: Vec<u8> = eph_pub.into_iter().chain(ciphertext).chain(mac).collect();
    Ok(format!("suci-0-{mcc}-{mnc}-0-{scheme}-{key_id}-{}", hex::encode(output)))
}

/// The X25519/P-256 public key for a private key, so a test can conceal against the
/// key the UDM will deconceal with.
pub fn public_key_a(private_key: &[u8; 32]) -> [u8; 32] {
    let secret = x25519_dalek::StaticSecret::from(*private_key);
    *x25519_dalek::PublicKey::from(&secret).as_bytes()
}

/// The compressed (33-byte) P-256 public key for a Profile B private scalar.
pub fn public_key_b(private_key: &[u8; 32]) -> Vec<u8> {
    let secret = p256::SecretKey::from_slice(private_key).expect("valid P-256 scalar");
    secret.public_key().to_encoded_point(true).as_bytes().to_vec()
}

fn random_scalar() -> [u8; 32] {
    let mut b = [0u8; 32];
    getrandom::getrandom(&mut b).expect("getrandom");
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_scheme_and_plain_supi_passthrough() {
        let keys = HomeNetworkKeys::empty();
        // A null-scheme SUCI: the scheme output is the MSIN in the clear.
        assert_eq!(
            deconceal("suci-0-999-70-0-0-0-0000000001", &keys).unwrap(),
            "imsi-999700000000001"
        );
        // A plain SUPI is returned unchanged (the caller may pass either).
        assert_eq!(deconceal("imsi-999700000000001", &keys).unwrap(), "imsi-999700000000001");
    }

    #[test]
    fn malformed_and_unknown_scheme_rejected() {
        let keys = HomeNetworkKeys::empty();
        assert_eq!(deconceal("suci-0-999-70", &keys), Err(SuciError::Malformed));
        assert_eq!(
            deconceal("suci-0-999-70-0-9-0-abcd", &keys),
            Err(SuciError::UnknownScheme("9".into()))
        );
        // A protected SUCI with no configured key is refused.
        assert_eq!(
            deconceal("suci-0-999-70-0-1-0-abcd", &keys),
            Err(SuciError::NoKey { scheme: "A", key_id: 0 })
        );
    }

    #[test]
    fn tbcd_round_trips_even_and_odd() {
        for msin in ["0123456789", "123456789", "0000000001", "7"] {
            assert_eq!(tbcd_decode(&tbcd_encode(msin)), msin);
        }
    }

    /// Profile A: conceal with the home-net public key, deconceal with the private key.
    #[test]
    fn profile_a_round_trips() {
        let priv_a = [0x11u8; 32];
        let keys = HomeNetworkKeys::empty().with_profile_a(1, priv_a);
        let pub_a = public_key_a(&priv_a);
        let suci = conceal("999", "70", "0000000042", "1", 1, &pub_a).unwrap();
        assert!(suci.starts_with("suci-0-999-70-0-1-1-"));
        assert_eq!(deconceal(&suci, &keys).unwrap(), "imsi-999700000000042");
    }

    /// Profile B: same round trip over P-256 (compressed ephemeral points).
    #[test]
    fn profile_b_round_trips() {
        // A fixed valid P-256 scalar.
        let priv_b = [
            0x0f, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x10, 0x20, 0x30, 0x40,
            0x50, 0x60, 0x70, 0x80,
        ];
        let keys = HomeNetworkKeys::empty().with_profile_b(2, priv_b);
        let pub_b = public_key_b(&priv_b);
        let suci = conceal("999", "70", "0123456789", "2", 2, &pub_b).unwrap();
        assert_eq!(deconceal(&suci, &keys).unwrap(), "imsi-999700123456789");
    }

    /// A tampered ciphertext fails the MAC check rather than yielding a wrong SUPI.
    #[test]
    fn tampering_is_caught_by_the_mac() {
        let priv_a = [0x22u8; 32];
        let keys = HomeNetworkKeys::empty().with_profile_a(1, priv_a);
        let suci = conceal("999", "70", "0000000042", "1", 1, &public_key_a(&priv_a)).unwrap();
        // Flip one hex nibble in the middle (the ciphertext region).
        let mut chars: Vec<char> = suci.chars().collect();
        let mid = chars.len() - 6;
        chars[mid] = if chars[mid] == 'a' { 'b' } else { 'a' };
        let tampered: String = chars.into_iter().collect();
        assert_eq!(deconceal(&tampered, &keys), Err(SuciError::BadMac));
    }
}
