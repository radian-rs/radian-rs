//! Subscription store — the UDM/ARPF persistence seam.
//!
//! Two concerns are split behind traits:
//! - [`SubscriberDb`]: subscriber existence + the mutable sequence number (SQN).
//! - [`ArpfKeyStore`]: the long-term credential boundary (K/OPc). **K never crosses
//!   this trait** — only the derived authentication vector leaves. Back it with an
//!   HSM or vault in production; here we provide in-memory (tests) and redb (persistent).
//!
//! Architecture note: per TS 23.501 / 29.504 this data belongs in the **UDR** (Nudr)
//! with the UDM as a stateless front-end; relocating it behind `nf-udr` is a later
//! slice. Persisted credentials are not yet encrypted at rest (TODO: HSM / KMS).

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;

use aka::{AuthVector, SubscriberKey};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use redb::{Builder, Database, ReadableDatabase, ReadableTable, TableDefinition};

/// Subscriber subscription data + mutable authentication state.
pub trait SubscriberDb: Send + Sync {
    /// Whether a subscriber with this SUPI exists.
    fn exists(&self, supi: &str) -> bool;
    /// Atomically take the next SQN for an authentication (post-increment).
    fn next_sqn(&self, supi: &str) -> Option<[u8; 6]>;
}

/// The ARPF credential boundary. Holds K/OPc and computes authentication vectors
/// **without ever exposing the long-term key** across the trait.
pub trait ArpfKeyStore: Send + Sync {
    /// Generate a 5G HE authentication vector for `supi` with the given SQN and
    /// challenge. `None` if the subscriber is unknown. K/OPc never leave the impl.
    fn generate_he_av(
        &self,
        supi: &str,
        sqn: &[u8; 6],
        rand: &[u8; 16],
        mcc: &str,
        mnc: &str,
    ) -> Option<AuthVector>;
}

/// Combined store the UDM holds as `Arc<dyn SubscriberStore>`.
pub trait SubscriberStore: SubscriberDb + ArpfKeyStore {}
impl<T: SubscriberDb + ArpfKeyStore + ?Sized> SubscriberStore for T {}

/// One subscriber's authentication record (40-byte fixed layout on disk).
#[derive(Clone)]
struct Record {
    key: SubscriberKey,
    sqn: [u8; 6],
}

impl Record {
    fn to_bytes(&self) -> [u8; 40] {
        let mut b = [0u8; 40];
        b[0..16].copy_from_slice(&self.key.k);
        b[16..32].copy_from_slice(&self.key.opc);
        b[32..34].copy_from_slice(&self.key.amf);
        b[34..40].copy_from_slice(&self.sqn);
        b
    }

    fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() != 40 {
            return None;
        }
        Some(Record {
            key: SubscriberKey {
                k: b[0..16].try_into().ok()?,
                opc: b[16..32].try_into().ok()?,
                amf: b[32..34].try_into().ok()?,
            },
            sqn: b[34..40].try_into().ok()?,
        })
    }
}

fn increment_sqn(sqn: &mut [u8; 6]) {
    for i in (0..6).rev() {
        let (v, carry) = sqn[i].overflowing_add(1);
        sqn[i] = v;
        if !carry {
            break;
        }
    }
}

fn parse_key(k: &str, opc: &str, amf: &str) -> Result<SubscriberKey, String> {
    fn h<const N: usize>(s: &str) -> Result<[u8; N], String> {
        hex::decode(s)
            .map_err(|e| e.to_string())?
            .try_into()
            .map_err(|_| format!("expected {N} bytes"))
    }
    Ok(SubscriberKey {
        k: h(k)?,
        opc: h(opc)?,
        amf: h(amf)?,
    })
}

/// Parse a 32-byte master key (KEK) from a 64-character hex string.
pub fn parse_kek_hex(hex_str: &str) -> Result<[u8; 32], String> {
    hex::decode(hex_str.trim())
        .map_err(|e| e.to_string())?
        .try_into()
        .map_err(|_| "master key must be 32 bytes (64 hex chars)".to_string())
}

/// Generate a random ephemeral KEK (dev use when no master key is configured).
pub fn random_kek() -> [u8; 32] {
    let mut k = [0u8; 32];
    getrandom::getrandom(&mut k).expect("getrandom KEK");
    k
}

// ── In-memory backend (tests / dev) ──────────────────────────────────────────

#[derive(Default)]
pub struct InMemoryStore {
    subscribers: Mutex<HashMap<String, Record>>,
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Provision a subscriber (SQN starts at zero).
    pub fn provision(&self, supi: impl Into<String>, key: SubscriberKey) {
        self.subscribers
            .lock()
            .unwrap()
            .insert(supi.into(), Record { key, sqn: [0; 6] });
    }

    /// Provision from hex strings (K, OPc = 16 bytes; AMF = 2 bytes).
    pub fn provision_hex(&self, supi: &str, k: &str, opc: &str, amf: &str) -> Result<(), String> {
        self.provision(supi, parse_key(k, opc, amf)?);
        Ok(())
    }
}

impl SubscriberDb for InMemoryStore {
    fn exists(&self, supi: &str) -> bool {
        self.subscribers.lock().unwrap().contains_key(supi)
    }

    fn next_sqn(&self, supi: &str) -> Option<[u8; 6]> {
        let mut g = self.subscribers.lock().unwrap();
        let rec = g.get_mut(supi)?;
        increment_sqn(&mut rec.sqn);
        Some(rec.sqn)
    }
}

impl ArpfKeyStore for InMemoryStore {
    fn generate_he_av(
        &self,
        supi: &str,
        sqn: &[u8; 6],
        rand: &[u8; 16],
        mcc: &str,
        mnc: &str,
    ) -> Option<AuthVector> {
        let g = self.subscribers.lock().unwrap();
        let rec = g.get(supi)?;
        aka::generate_5g_he_av(&rec.key, sqn, rand, mcc, mnc).ok()
    }
}

// ── redb backend (persistent) ────────────────────────────────────────────────

const SUBSCRIBERS: TableDefinition<&str, &[u8]> = TableDefinition::new("subscribers");

/// Create a new file readable/writable only by the owner (mode 0600 on Unix) so the
/// persisted credential store is never world-readable. The restrictive mode is set at
/// creation (no chmod-after-create TOCTOU window).
fn create_private_file(path: &Path) -> std::io::Result<std::fs::File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
}

pub struct RedbStore {
    db: Database,
    kek: [u8; 32],
}

impl RedbStore {
    /// Open (creating if absent) a persistent subscriber store at `path`, encrypting
    /// records at rest (AES-256-GCM) with the 32-byte key-encryption key `kek`. A
    /// newly created file is owner-only (mode 0600). `kek` is injected by the caller
    /// — sourced from an HSM / KMS / env in production — and never persisted.
    pub fn open(
        path: impl AsRef<Path>,
        kek: [u8; 32],
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let path = path.as_ref();
        let db = if path.exists() {
            Database::open(path)?
        } else {
            Builder::new().create_file(create_private_file(path)?)?
        };
        let w = db.begin_write()?;
        w.open_table(SUBSCRIBERS)?; // ensure the table exists
        w.commit()?;
        Ok(Self { db, kek })
    }

    /// AEAD-encrypt a record, bound to `supi` (AAD). Layout: nonce(12) || ciphertext+tag.
    fn encrypt(&self, supi: &str, plaintext: &[u8]) -> Vec<u8> {
        let cipher = Aes256Gcm::new_from_slice(&self.kek).expect("32-byte KEK");
        let mut nonce_bytes = [0u8; 12];
        getrandom::getrandom(&mut nonce_bytes).expect("getrandom nonce");
        let nonce = Nonce::from(nonce_bytes);
        let ct = cipher
            .encrypt(&nonce, Payload { msg: plaintext, aad: supi.as_bytes() })
            .expect("AES-256-GCM encrypt");
        let mut out = Vec::with_capacity(12 + ct.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ct);
        out
    }

    /// Verify + decrypt a record (None on wrong KEK / tamper / wrong SUPI).
    fn decrypt(&self, supi: &str, blob: &[u8]) -> Option<[u8; 40]> {
        if blob.len() < 12 {
            return None;
        }
        let (nonce_bytes, ct) = blob.split_at(12);
        let nonce = Nonce::from(<[u8; 12]>::try_from(nonce_bytes).ok()?);
        let cipher = Aes256Gcm::new_from_slice(&self.kek).ok()?;
        let pt = cipher
            .decrypt(&nonce, Payload { msg: ct, aad: supi.as_bytes() })
            .ok()?;
        pt.try_into().ok()
    }

    pub fn provision(&self, supi: &str, key: SubscriberKey) -> Result<(), redb::Error> {
        // K/OPc are AEAD-encrypted at rest under the injected KEK, bound to the SUPI.
        let blob = self.encrypt(supi, &Record { key, sqn: [0; 6] }.to_bytes());
        let w = self.db.begin_write()?;
        {
            let mut table = w.open_table(SUBSCRIBERS)?;
            table.insert(supi, blob.as_slice())?;
        }
        w.commit()?;
        Ok(())
    }

    pub fn provision_hex(&self, supi: &str, k: &str, opc: &str, amf: &str) -> Result<(), String> {
        self.provision(supi, parse_key(k, opc, amf)?)
            .map_err(|e| e.to_string())
    }

    fn read_record(&self, supi: &str) -> Option<Record> {
        let r = self.db.begin_read().ok()?;
        let table = r.open_table(SUBSCRIBERS).ok()?;
        let guard = table.get(supi).ok()??;
        let plain = self.decrypt(supi, guard.value())?;
        Record::from_bytes(&plain)
    }
}

impl SubscriberDb for RedbStore {
    fn exists(&self, supi: &str) -> bool {
        self.read_record(supi).is_some()
    }

    fn next_sqn(&self, supi: &str) -> Option<[u8; 6]> {
        let w = self.db.begin_write().ok()?;
        let sqn;
        {
            let mut table = w.open_table(SUBSCRIBERS).ok()?;
            let mut rec = {
                let guard = table.get(supi).ok()??;
                let plain = self.decrypt(supi, guard.value())?;
                Record::from_bytes(&plain)?
            };
            increment_sqn(&mut rec.sqn);
            let blob = self.encrypt(supi, &rec.to_bytes());
            table.insert(supi, blob.as_slice()).ok()?;
            sqn = rec.sqn;
        }
        w.commit().ok()?;
        Some(sqn)
    }
}

impl ArpfKeyStore for RedbStore {
    fn generate_he_av(
        &self,
        supi: &str,
        sqn: &[u8; 6],
        rand: &[u8; 16],
        mcc: &str,
        mnc: &str,
    ) -> Option<AuthVector> {
        let rec = self.read_record(supi)?;
        aka::generate_5g_he_av(&rec.key, sqn, rand, mcc, mnc).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const K: &str = "465b5ce8b199b49faa5f0a2ee238a6bc";
    const OPC: &str = "cd63cb71954a9f4e48a5994e37a02baf";
    const KEK: [u8; 32] = [0x42; 32];

    #[test]
    fn in_memory_sqn_increments_and_av_generates() {
        let store = InMemoryStore::new();
        store.provision_hex("imsi-1", K, OPC, "8000").unwrap();
        assert!(store.exists("imsi-1"));
        assert!(!store.exists("imsi-2"));

        assert_eq!(store.next_sqn("imsi-1"), Some([0, 0, 0, 0, 0, 1]));
        assert_eq!(store.next_sqn("imsi-1"), Some([0, 0, 0, 0, 0, 2]));
        assert_eq!(store.next_sqn("imsi-2"), None);

        let av = store
            .generate_he_av("imsi-1", &[0, 0, 0, 0, 0, 1], &[0x11; 16], "999", "70")
            .expect("AV");
        assert_ne!(av.kausf, [0u8; 32]);
    }

    #[test]
    fn redb_persists_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub.redb");

        {
            let store = RedbStore::open(&path, KEK).unwrap();
            store.provision_hex("imsi-1", K, OPC, "8000").unwrap();
            assert_eq!(store.next_sqn("imsi-1"), Some([0, 0, 0, 0, 0, 1]));
        }

        // Reopen: the subscriber and the advanced SQN survive.
        let store = RedbStore::open(&path, KEK).unwrap();
        assert!(store.exists("imsi-1"));
        assert_eq!(store.next_sqn("imsi-1"), Some([0, 0, 0, 0, 0, 2]));
        let av = store
            .generate_he_av("imsi-1", &[0, 0, 0, 0, 0, 2], &[0x11; 16], "999", "70")
            .expect("AV");
        assert_ne!(av.kausf, [0u8; 32]);
    }

    #[test]
    fn redb_unknown_subscriber_is_none() {
        let dir = tempfile::tempdir().unwrap();
        let store = RedbStore::open(dir.path().join("s.redb"), KEK).unwrap();
        assert!(!store.exists("imsi-missing"));
        assert_eq!(store.next_sqn("imsi-missing"), None);
        assert!(store
            .generate_he_av("imsi-missing", &[0; 6], &[0x11; 16], "999", "70")
            .is_none());
    }

    #[cfg(unix)]
    #[test]
    fn redb_credential_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub.redb");
        let _store = RedbStore::open(&path, KEK).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "credential store must be owner-only, got {mode:o}");
    }

    #[test]
    fn redb_wrong_kek_cannot_read() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub.redb");
        RedbStore::open(&path, [0x11; 32])
            .unwrap()
            .provision_hex("imsi-1", K, OPC, "8000")
            .unwrap();

        // A store opened with a different KEK can't decrypt the record (GCM tag fails).
        let other = RedbStore::open(&path, [0x22; 32]).unwrap();
        assert!(!other.exists("imsi-1"));
        assert_eq!(other.next_sqn("imsi-1"), None);
        assert!(other
            .generate_he_av("imsi-1", &[0; 6], &[0x11; 16], "999", "70")
            .is_none());
    }

    #[test]
    fn redb_key_is_not_plaintext_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub.redb");
        let store = RedbStore::open(&path, KEK).unwrap();
        store.provision_hex("imsi-1", K, OPC, "8000").unwrap();
        let _ = store.next_sqn("imsi-1"); // force an encrypted write
        drop(store);

        let file = std::fs::read(&path).unwrap();
        let contains = |needle: &[u8]| file.windows(needle.len()).any(|w| w == needle);
        assert!(!contains(&hex::decode(K).unwrap()), "K must not be plaintext on disk");
        assert!(!contains(&hex::decode(OPC).unwrap()), "OPc must not be plaintext on disk");
    }
}
