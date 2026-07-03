//! Subscription store — the UDR persistence seam (design/24, step 1).
//!
//! Data is partitioned by class, each behind its own trait:
//! - [`SubscriberDb`]: subscriber existence + the mutable sequence number (SQN).
//!   The SQN lives **outside** the encrypted credential blob so the per-auth hot
//!   path never re-encrypts the long-term keys.
//! - [`ArpfKeyStore`]: the long-term credential boundary (K/OPc). **K never crosses
//!   this trait** — only the derived authentication vector leaves. Back it with an
//!   HSM or vault in production; here we provide in-memory (tests) and redb (persistent).
//! - [`ProvisionedDataStore`]: provisioned subscription data (AM/SM/SMF-selection)
//!   as TS 29.505-shaped JSON documents keyed by (SUPI, serving PLMN) — the layout
//!   that ports mechanically to Postgres JSONB or a document store later.
//!
//! This store is hosted by `nf-udr` and consumed over Nudr (`sbi_core::nudr`);
//! only credentials (K/OPc/AMF) are encrypted at rest (AES-256-GCM under an
//! injected KEK). SQN and profile documents are not secret.

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
    /// Withdraw the subscription: remove credentials, auth state, and every
    /// provisioned document for this SUPI. Returns whether anything existed.
    fn remove_subscriber(&self, supi: &str) -> bool;
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

/// A provisioned-data document family (TS 29.505 `provisioned-data` resources).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DataSet {
    /// Access-and-mobility data: subscribed S-NSSAIs, UE-AMBR, …
    Am,
    /// Session-management data: per-DNN QoS, session AMBR, SSC modes, …
    Sm,
    /// SMF selection subscription data.
    SmfSelection,
}

/// Provisioned subscription data as JSON documents keyed by (SUPI, serving PLMN),
/// plus the dynamic **context data** (TS 29.505 `amf-3gpp-access`): which AMF
/// currently serves the SUPI (written at registration, purged at deregistration).
pub trait ProvisionedDataStore: Send + Sync {
    /// Fetch a provisioned document. `None` if not provisioned.
    fn get_provisioned(&self, ds: DataSet, supi: &str, plmn: &str) -> Option<serde_json::Value>;
    /// Store (create or replace) a provisioned document.
    fn put_provisioned(
        &self,
        ds: DataSet,
        supi: &str,
        plmn: &str,
        doc: &serde_json::Value,
    ) -> Result<(), String>;
    /// The serving AMF's registration document, if any.
    fn get_amf_registration(&self, supi: &str) -> Option<serde_json::Value>;
    /// Record the serving AMF (create or replace).
    fn put_amf_registration(&self, supi: &str, doc: &serde_json::Value) -> Result<(), String>;
    /// Purge the serving-AMF registration. Returns whether one existed.
    fn remove_amf_registration(&self, supi: &str) -> bool;
}

/// Combined store the UDR holds as `Arc<dyn SubscriberStore>`.
pub trait SubscriberStore: SubscriberDb + ArpfKeyStore + ProvisionedDataStore {}
impl<T: SubscriberDb + ArpfKeyStore + ProvisionedDataStore + ?Sized> SubscriberStore for T {}

/// Long-term credentials only (34-byte fixed layout: K ‖ OPc ‖ AMF). The mutable
/// SQN is deliberately **not** here — see the module docs.
fn key_to_bytes(key: &SubscriberKey) -> [u8; 34] {
    let mut b = [0u8; 34];
    b[0..16].copy_from_slice(&key.k);
    b[16..32].copy_from_slice(&key.opc);
    b[32..34].copy_from_slice(&key.amf);
    b
}

fn key_from_bytes(b: &[u8]) -> Option<SubscriberKey> {
    if b.len() != 34 {
        return None;
    }
    Some(SubscriberKey {
        k: b[0..16].try_into().ok()?,
        opc: b[16..32].try_into().ok()?,
        amf: b[32..34].try_into().ok()?,
    })
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
struct InMemoryInner {
    credentials: HashMap<String, SubscriberKey>,
    sqn: HashMap<String, [u8; 6]>,
    docs: HashMap<(DataSet, String, String), serde_json::Value>,
    amf_reg: HashMap<String, serde_json::Value>,
}

#[derive(Default)]
pub struct InMemoryStore {
    inner: Mutex<InMemoryInner>,
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Provision a subscriber (SQN starts at zero).
    pub fn provision(&self, supi: impl Into<String>, key: SubscriberKey) {
        let supi = supi.into();
        let mut g = self.inner.lock().unwrap();
        g.sqn.insert(supi.clone(), [0; 6]);
        g.credentials.insert(supi, key);
    }

    /// Provision from hex strings (K, OPc = 16 bytes; AMF = 2 bytes).
    pub fn provision_hex(&self, supi: &str, k: &str, opc: &str, amf: &str) -> Result<(), String> {
        self.provision(supi, parse_key(k, opc, amf)?);
        Ok(())
    }
}

impl SubscriberDb for InMemoryStore {
    fn exists(&self, supi: &str) -> bool {
        self.inner.lock().unwrap().credentials.contains_key(supi)
    }

    fn remove_subscriber(&self, supi: &str) -> bool {
        let mut g = self.inner.lock().unwrap();
        let existed = g.credentials.remove(supi).is_some();
        g.sqn.remove(supi);
        g.docs.retain(|(_, s, _), _| s != supi);
        g.amf_reg.remove(supi);
        existed
    }

    fn next_sqn(&self, supi: &str) -> Option<[u8; 6]> {
        let mut g = self.inner.lock().unwrap();
        if !g.credentials.contains_key(supi) {
            return None;
        }
        let sqn = g.sqn.get_mut(supi)?;
        increment_sqn(sqn);
        Some(*sqn)
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
        let g = self.inner.lock().unwrap();
        let key = g.credentials.get(supi)?;
        aka::generate_5g_he_av(key, sqn, rand, mcc, mnc).ok()
    }
}

impl ProvisionedDataStore for InMemoryStore {
    fn get_provisioned(&self, ds: DataSet, supi: &str, plmn: &str) -> Option<serde_json::Value> {
        self.inner.lock().unwrap().docs.get(&(ds, supi.to_string(), plmn.to_string())).cloned()
    }

    fn get_amf_registration(&self, supi: &str) -> Option<serde_json::Value> {
        self.inner.lock().unwrap().amf_reg.get(supi).cloned()
    }

    fn put_amf_registration(&self, supi: &str, doc: &serde_json::Value) -> Result<(), String> {
        self.inner.lock().unwrap().amf_reg.insert(supi.to_string(), doc.clone());
        Ok(())
    }

    fn remove_amf_registration(&self, supi: &str) -> bool {
        self.inner.lock().unwrap().amf_reg.remove(supi).is_some()
    }

    fn put_provisioned(
        &self,
        ds: DataSet,
        supi: &str,
        plmn: &str,
        doc: &serde_json::Value,
    ) -> Result<(), String> {
        self.inner
            .lock()
            .unwrap()
            .docs
            .insert((ds, supi.to_string(), plmn.to_string()), doc.clone());
        Ok(())
    }
}

// ── redb backend (persistent) ────────────────────────────────────────────────

/// AEAD(K ‖ OPc ‖ AMF) under the KEK — the cold ARPF partition.
const CREDENTIALS: TableDefinition<&str, &[u8]> = TableDefinition::new("credentials");
/// Plaintext 6-byte SQN — the hot per-auth counter (not secret).
const AUTH_STATE: TableDefinition<&str, &[u8]> = TableDefinition::new("auth_state");
/// Provisioned-data documents, keyed (SUPI, serving PLMN), JSON values.
const AM_DATA: TableDefinition<(&str, &str), &[u8]> = TableDefinition::new("am_data");
const SM_DATA: TableDefinition<(&str, &str), &[u8]> = TableDefinition::new("sm_data");
const SMF_SELECTION: TableDefinition<(&str, &str), &[u8]> =
    TableDefinition::new("smf_selection");
/// Dynamic context data: the serving AMF's registration (TS 29.505
/// `amf-3gpp-access`), keyed by SUPI, JSON value.
const AMF_3GPP_REG: TableDefinition<&str, &[u8]> = TableDefinition::new("amf_3gpp_reg");

fn doc_table(ds: DataSet) -> TableDefinition<'static, (&'static str, &'static str), &'static [u8]> {
    match ds {
        DataSet::Am => AM_DATA,
        DataSet::Sm => SM_DATA,
        DataSet::SmfSelection => SMF_SELECTION,
    }
}

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
    /// credential records at rest (AES-256-GCM) with the 32-byte key-encryption key
    /// `kek`. A newly created file is owner-only (mode 0600). `kek` is injected by
    /// the caller — sourced from an HSM / KMS / env in production — and never
    /// persisted.
    ///
    /// Note: pre-doc-24 stores (single `subscribers` table, SQN inside the blob)
    /// are not migrated — dev-only data; re-provision instead.
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
        w.open_table(CREDENTIALS)?; // ensure the tables exist
        w.open_table(AUTH_STATE)?;
        w.open_table(AM_DATA)?;
        w.open_table(SM_DATA)?;
        w.open_table(SMF_SELECTION)?;
        w.open_table(AMF_3GPP_REG)?;
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
    fn decrypt(&self, supi: &str, blob: &[u8]) -> Option<Vec<u8>> {
        if blob.len() < 12 {
            return None;
        }
        let (nonce_bytes, ct) = blob.split_at(12);
        let nonce = Nonce::from(<[u8; 12]>::try_from(nonce_bytes).ok()?);
        let cipher = Aes256Gcm::new_from_slice(&self.kek).ok()?;
        cipher.decrypt(&nonce, Payload { msg: ct, aad: supi.as_bytes() }).ok()
    }

    pub fn provision(&self, supi: &str, key: SubscriberKey) -> Result<(), redb::Error> {
        // K/OPc/AMF are AEAD-encrypted at rest under the injected KEK, bound to the
        // SUPI; the SQN starts at zero in its own plaintext table.
        let blob = self.encrypt(supi, &key_to_bytes(&key));
        let w = self.db.begin_write()?;
        {
            let mut creds = w.open_table(CREDENTIALS)?;
            creds.insert(supi, blob.as_slice())?;
            let mut sqn = w.open_table(AUTH_STATE)?;
            sqn.insert(supi, [0u8; 6].as_slice())?;
        }
        w.commit()?;
        Ok(())
    }

    pub fn provision_hex(&self, supi: &str, k: &str, opc: &str, amf: &str) -> Result<(), String> {
        self.provision(supi, parse_key(k, opc, amf)?)
            .map_err(|e| e.to_string())
    }

    fn read_key(&self, supi: &str) -> Option<SubscriberKey> {
        let r = self.db.begin_read().ok()?;
        let table = r.open_table(CREDENTIALS).ok()?;
        let guard = table.get(supi).ok()??;
        let plain = self.decrypt(supi, guard.value())?;
        key_from_bytes(&plain)
    }
}

impl SubscriberDb for RedbStore {
    fn exists(&self, supi: &str) -> bool {
        self.read_key(supi).is_some()
    }

    fn remove_subscriber(&self, supi: &str) -> bool {
        let Ok(w) = self.db.begin_write() else {
            return false;
        };
        let mut existed = false;
        {
            if let Ok(mut t) = w.open_table(CREDENTIALS) {
                existed = t.remove(supi).map(|old| old.is_some()).unwrap_or(false);
            }
            if let Ok(mut t) = w.open_table(AUTH_STATE) {
                let _ = t.remove(supi);
            }
            if let Ok(mut t) = w.open_table(AMF_3GPP_REG) {
                let _ = t.remove(supi);
            }
            for ds in [DataSet::Am, DataSet::Sm, DataSet::SmfSelection] {
                if let Ok(mut t) = w.open_table(doc_table(ds)) {
                    // Small tables: collect this SUPI's (supi, plmn) keys, then remove.
                    let keys: Vec<String> = t
                        .iter()
                        .map(|it| {
                            it.filter_map(|kv| kv.ok())
                                .filter(|(k, _)| k.value().0 == supi)
                                .map(|(k, _)| k.value().1.to_string())
                                .collect()
                        })
                        .unwrap_or_default();
                    for plmn in keys {
                        let _ = t.remove((supi, plmn.as_str()));
                    }
                }
            }
        }
        w.commit().is_ok() && existed
    }

    fn next_sqn(&self, supi: &str) -> Option<[u8; 6]> {
        // A subscriber is only usable if its credentials decrypt under our KEK —
        // don't advance SQNs for records we can't authenticate against.
        if !self.exists(supi) {
            return None;
        }
        let w = self.db.begin_write().ok()?;
        let sqn;
        {
            let mut table = w.open_table(AUTH_STATE).ok()?;
            let mut cur: [u8; 6] = {
                let guard = table.get(supi).ok()??;
                guard.value().try_into().ok()?
            };
            increment_sqn(&mut cur);
            table.insert(supi, cur.as_slice()).ok()?;
            sqn = cur;
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
        let key = self.read_key(supi)?;
        aka::generate_5g_he_av(&key, sqn, rand, mcc, mnc).ok()
    }
}

impl ProvisionedDataStore for RedbStore {
    fn get_provisioned(&self, ds: DataSet, supi: &str, plmn: &str) -> Option<serde_json::Value> {
        let r = self.db.begin_read().ok()?;
        let table = r.open_table(doc_table(ds)).ok()?;
        let guard = table.get((supi, plmn)).ok()??;
        serde_json::from_slice(guard.value()).ok()
    }

    fn get_amf_registration(&self, supi: &str) -> Option<serde_json::Value> {
        let r = self.db.begin_read().ok()?;
        let table = r.open_table(AMF_3GPP_REG).ok()?;
        let guard = table.get(supi).ok()??;
        serde_json::from_slice(guard.value()).ok()
    }

    fn put_amf_registration(&self, supi: &str, doc: &serde_json::Value) -> Result<(), String> {
        let bytes = serde_json::to_vec(doc).map_err(|e| e.to_string())?;
        let w = self.db.begin_write().map_err(|e| e.to_string())?;
        {
            let mut table = w.open_table(AMF_3GPP_REG).map_err(|e| e.to_string())?;
            table.insert(supi, bytes.as_slice()).map_err(|e| e.to_string())?;
        }
        w.commit().map_err(|e| e.to_string())
    }

    fn remove_amf_registration(&self, supi: &str) -> bool {
        let Ok(w) = self.db.begin_write() else {
            return false;
        };
        let mut existed = false;
        {
            if let Ok(mut t) = w.open_table(AMF_3GPP_REG) {
                existed = t.remove(supi).map(|old| old.is_some()).unwrap_or(false);
            }
        }
        w.commit().is_ok() && existed
    }

    fn put_provisioned(
        &self,
        ds: DataSet,
        supi: &str,
        plmn: &str,
        doc: &serde_json::Value,
    ) -> Result<(), String> {
        let bytes = serde_json::to_vec(doc).map_err(|e| e.to_string())?;
        let w = self.db.begin_write().map_err(|e| e.to_string())?;
        {
            let mut table = w.open_table(doc_table(ds)).map_err(|e| e.to_string())?;
            table.insert((supi, plmn), bytes.as_slice()).map_err(|e| e.to_string())?;
        }
        w.commit().map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

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
    fn in_memory_provisioned_docs_roundtrip() {
        let store = InMemoryStore::new();
        let doc = json!({"nssai": {"defaultSingleNssais": [{"sst": 1, "sd": "010203"}]}});
        store.put_provisioned(DataSet::Am, "imsi-1", "99970", &doc).unwrap();
        assert_eq!(store.get_provisioned(DataSet::Am, "imsi-1", "99970"), Some(doc));
        // Distinct per data set and per serving PLMN.
        assert!(store.get_provisioned(DataSet::Sm, "imsi-1", "99970").is_none());
        assert!(store.get_provisioned(DataSet::Am, "imsi-1", "00101").is_none());
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
    fn redb_provisioned_docs_persist_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub.redb");
        let sm = json!([{
            "singleNssai": {"sst": 1, "sd": "010203"},
            "dnnConfigurations": {"internet": {"pduSessionTypes": {"defaultSessionType": "IPV4"}}}
        }]);

        {
            let store = RedbStore::open(&path, KEK).unwrap();
            store.put_provisioned(DataSet::Sm, "imsi-1", "99970", &sm).unwrap();
        }

        let store = RedbStore::open(&path, KEK).unwrap();
        assert_eq!(store.get_provisioned(DataSet::Sm, "imsi-1", "99970"), Some(sm));
        assert!(store.get_provisioned(DataSet::SmfSelection, "imsi-1", "99970").is_none());
    }

    #[test]
    fn amf_registration_crud_and_persistence() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.redb");
        let reg = json!({"amfInstanceId": "amf-1", "deregCallbackUri": "http://a/cb"});
        {
            let store = RedbStore::open(&path, KEK).unwrap();
            assert!(store.get_amf_registration("imsi-1").is_none());
            store.put_amf_registration("imsi-1", &reg).unwrap();
            assert_eq!(store.get_amf_registration("imsi-1"), Some(reg.clone()));
        }
        // Survives reopen; purge removes it.
        let store = RedbStore::open(&path, KEK).unwrap();
        assert_eq!(store.get_amf_registration("imsi-1"), Some(reg.clone()));
        assert!(store.remove_amf_registration("imsi-1"));
        assert!(!store.remove_amf_registration("imsi-1"), "second purge is a no-op");

        let mem = InMemoryStore::new();
        mem.put_amf_registration("imsi-1", &reg).unwrap();
        assert_eq!(mem.get_amf_registration("imsi-1"), Some(reg));
        assert!(mem.remove_amf_registration("imsi-1"));
    }

    #[test]
    fn remove_subscriber_withdraws_everything() {
        let dir = tempfile::tempdir().unwrap();
        let store = RedbStore::open(dir.path().join("s.redb"), KEK).unwrap();
        store.provision_hex("imsi-1", K, OPC, "8000").unwrap();
        store
            .put_provisioned(DataSet::Am, "imsi-1", "99970", &json!({"a": 1}))
            .unwrap();
        store
            .put_provisioned(DataSet::Sm, "imsi-1", "00101", &json!({"b": 2}))
            .unwrap();

        store
            .put_amf_registration("imsi-1", &json!({"amfInstanceId": "amf-1"}))
            .unwrap();

        assert!(store.remove_subscriber("imsi-1"), "existed");
        assert!(!store.exists("imsi-1"));
        assert!(store.get_amf_registration("imsi-1").is_none(), "context data wiped too");
        assert_eq!(store.next_sqn("imsi-1"), None);
        assert!(store.get_provisioned(DataSet::Am, "imsi-1", "99970").is_none());
        assert!(store.get_provisioned(DataSet::Sm, "imsi-1", "00101").is_none());
        assert!(!store.remove_subscriber("imsi-1"), "second removal is a no-op");

        // In-memory behaves the same.
        let mem = InMemoryStore::new();
        mem.provision_hex("imsi-1", K, OPC, "8000").unwrap();
        mem.put_provisioned(DataSet::Am, "imsi-1", "99970", &json!({"a": 1})).unwrap();
        assert!(mem.remove_subscriber("imsi-1"));
        assert!(!mem.exists("imsi-1"));
        assert!(mem.get_provisioned(DataSet::Am, "imsi-1", "99970").is_none());
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

        // A store opened with a different KEK can't decrypt the credentials (GCM tag
        // fails) — and must not advance SQNs for a subscriber it can't authenticate.
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
        let _ = store.next_sqn("imsi-1"); // SQN writes must not leak key material either
        drop(store);

        let file = std::fs::read(&path).unwrap();
        let contains = |needle: &[u8]| file.windows(needle.len()).any(|w| w == needle);
        assert!(!contains(&hex::decode(K).unwrap()), "K must not be plaintext on disk");
        assert!(!contains(&hex::decode(OPC).unwrap()), "OPc must not be plaintext on disk");
    }
}
