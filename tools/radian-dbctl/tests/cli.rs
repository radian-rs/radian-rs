//! End-to-end CLI test (design/137 G23): provision through the built binary, then
//! prove the UDR's store reads it back — credentials decrypt under the matching KEK,
//! the profile documents are present, and a wrong KEK cannot decrypt.

use std::process::Command;

use subscriber_db::{DataSet, ProvisionedDataStore, RedbStore, SubscriberDb};

const BIN: &str = env!("CARGO_BIN_EXE_radian-dbctl");
/// A fixed 64-hex test key-encryption key.
const KEK: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const SUPI: &str = "imsi-999700000000042";

fn run(db: &str, args: &[&str]) -> std::process::Output {
    Command::new(BIN)
        .args(["--db", db, "--key", KEK])
        .args(args)
        .output()
        .expect("run radian-dbctl")
}

#[test]
fn add_list_remove_round_trips_through_the_store() {
    // A unique temp store path — no external dependencies; the file is created 0600.
    let path = std::env::temp_dir().join(format!("radian-dbctl-test-{}.redb", std::process::id()));
    let db = path.to_str().unwrap();
    let _ = std::fs::remove_file(db);

    // add — credentials (TS 35.208 test key) + a working profile.
    let out = run(
        db,
        &[
            "add", "--supi", SUPI,
            "--k", "465b5ce8b199b49faa5f0a2ee238a6bc",
            "--opc", "cd63cb71954a9f4e48a5994e37a02baf",
        ],
    );
    assert!(out.status.success(), "add failed: {}", String::from_utf8_lossy(&out.stderr));

    // The UDR (same store + KEK) reads it: credentials decrypt, profile documents present.
    {
        let store = RedbStore::open(db, subscriber_db::parse_kek_hex(KEK).unwrap()).unwrap();
        assert!(store.exists(SUPI), "credentials decrypt under the UDR's KEK");
        assert!(store.get_provisioned(DataSet::Am, SUPI, "99970").is_some(), "am-data");
        assert!(store.get_provisioned(DataSet::Sm, SUPI, "99970").is_some(), "sm-data");
        assert!(store.get_provisioned(DataSet::SmfSelection, SUPI, "99970").is_some(), "smf-selection");
    }
    // A wrong KEK cannot decrypt the credentials — encryption-at-rest holds through the CLI.
    {
        let wrong = RedbStore::open(db, [0xFFu8; 32]).unwrap();
        assert!(!wrong.exists(SUPI), "wrong KEK must not read the credentials");
    }

    // list shows the SUPI.
    let out = run(db, &["list"]);
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains(SUPI), "list shows the SUPI");

    // remove drops the subscriber and its profile.
    let out = run(db, &["remove", "--supi", SUPI]);
    assert!(out.status.success());
    {
        let store = RedbStore::open(db, subscriber_db::parse_kek_hex(KEK).unwrap()).unwrap();
        assert!(!store.exists(SUPI), "removed");
        assert!(store.get_provisioned(DataSet::Am, SUPI, "99970").is_none(), "profile removed too");
    }

    let _ = std::fs::remove_file(db);
}

#[test]
fn add_requires_a_key() {
    // Without --key (and no env), a write operation refuses rather than writing data
    // the UDR could never decrypt.
    let out = Command::new(BIN)
        .env_remove("RADIAN_UDR_MASTER_KEY")
        .args(["--db", "/tmp/radian-dbctl-nokey.redb", "add", "--supi", SUPI, "--k", "00", "--opc", "00"])
        .output()
        .expect("run");
    assert!(!out.status.success(), "add without a key must fail");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("key-encryption key is required"),
        "explains the missing key"
    );
}
