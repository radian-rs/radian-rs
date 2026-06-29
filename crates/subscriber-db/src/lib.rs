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
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};

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

pub struct RedbStore {
    db: Database,
}

impl RedbStore {
    /// Open (creating if absent) a persistent subscriber store at `path`.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, redb::Error> {
        let db = Database::create(path)?;
        let w = db.begin_write()?;
        w.open_table(SUBSCRIBERS)?; // ensure the table exists
        w.commit()?;
        Ok(Self { db })
    }

    pub fn provision(&self, supi: &str, key: SubscriberKey) -> Result<(), redb::Error> {
        let bytes = Record { key, sqn: [0; 6] }.to_bytes();
        let w = self.db.begin_write()?;
        {
            let mut table = w.open_table(SUBSCRIBERS)?;
            table.insert(supi, bytes.as_slice())?;
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
        Record::from_bytes(guard.value())
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
                Record::from_bytes(guard.value())?
            };
            increment_sqn(&mut rec.sqn);
            let bytes = rec.to_bytes();
            table.insert(supi, bytes.as_slice()).ok()?;
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
            let store = RedbStore::open(&path).unwrap();
            store.provision_hex("imsi-1", K, OPC, "8000").unwrap();
            assert_eq!(store.next_sqn("imsi-1"), Some([0, 0, 0, 0, 0, 1]));
        }

        // Reopen: the subscriber and the advanced SQN survive.
        let store = RedbStore::open(&path).unwrap();
        assert!(store.exists("imsi-1"));
        assert_eq!(store.next_sqn("imsi-1"), Some([0, 0, 0, 0, 0, 2]));
        let av = store
            .generate_he_av("imsi-1", &[0, 0, 0, 0, 0, 2], &[0x11; 16], "999", "70")
            .expect("AV");
        assert_ne!(av.kausf, [0u8; 32]);
    }
}
