//! `radian-dbctl` — provision subscribers directly into the UDR's redb store.
//!
//! The ARPF-preserving provisioning path (design/137 G23, design/138 G40): the
//! long-term key **K never leaves this process** — it goes straight into the
//! encrypted-at-rest store, not over a Nudr wire — so provisioning keeps the same
//! boundary the running UDM/UDR enforce. This is the shape open5gs's `open5gs-dbctl`
//! uses (write the datastore directly), minus the wire.
//!
//! **Operational note:** redb takes an exclusive file lock, so run this while the UDR
//! is **stopped** (then start the UDR). The `--key`/`RADIAN_UDR_MASTER_KEY` must match
//! the UDR's, or the UDR cannot decrypt what you provision.

use anyhow::{bail, Result};
use clap::{Args, Parser, Subcommand};
use subscriber_db::{DataSet, ProvisionedDataStore, RedbStore, SubscriberDb};

const DB_ENV: &str = "RADIAN_UDR_DB";
const KEK_ENV: &str = "RADIAN_UDR_MASTER_KEY";
const DEFAULT_DB: &str = "radian-udr.redb";

#[derive(Parser)]
#[command(name = "radian-dbctl", about = "Provision subscribers into the radian-rs UDR store")]
struct Cli {
    /// redb store path (default: $RADIAN_UDR_DB, else radian-udr.redb).
    #[arg(long, global = true)]
    db: Option<String>,
    /// 64-hex key-encryption key. MUST match the UDR's RADIAN_UDR_MASTER_KEY, else the
    /// UDR can't decrypt what you provision (default: $RADIAN_UDR_MASTER_KEY).
    #[arg(long, global = true)]
    key: Option<String>,
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Provision (or overwrite) a subscriber: credentials + a working profile.
    Add(AddArgs),
    /// Delete a subscriber and all of its data.
    Remove {
        /// Subscriber SUPI, e.g. imsi-999700000000001.
        #[arg(long)]
        supi: String,
    },
    /// List the provisioned subscribers' SUPIs.
    List,
}

#[derive(Args)]
struct AddArgs {
    /// Subscriber IMSI as a SUPI, e.g. imsi-999700000000001.
    #[arg(long)]
    supi: String,
    /// Permanent key K (32 hex).
    #[arg(long)]
    k: String,
    /// OPc (32 hex).
    #[arg(long)]
    opc: String,
    /// Authentication Management Field (4 hex).
    #[arg(long, default_value = "8000")]
    amf: String,
    /// Serving PLMN the profile is keyed under (MCC+MNC), e.g. 99970.
    #[arg(long, default_value = "99970")]
    plmn: String,
    /// Slice SST.
    #[arg(long, default_value_t = 1)]
    sst: u8,
    /// Slice SD (6 hex); omit for an SST-only slice.
    #[arg(long)]
    sd: Option<String>,
    /// Data network name the subscriber may use.
    #[arg(long, default_value = "internet")]
    dnn: String,
    /// Session-AMBR uplink (e.g. "1 Gbps").
    #[arg(long, default_value = "1 Gbps")]
    ambr_up: String,
    /// Session-AMBR downlink.
    #[arg(long, default_value = "2 Gbps")]
    ambr_down: String,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let (db, key) = (cli.db, cli.key);
    let opener = |need_key| open(db.clone(), key.clone(), need_key);
    match cli.cmd {
        Command::List => list(&opener(false)?),
        Command::Remove { supi } => remove(&opener(true)?, &supi),
        Command::Add(args) => add(&opener(true)?, args),
    }
}

/// Open the store. `need_key` = the operation writes/reads credentials, so a stable
/// KEK matching the UDR's is mandatory — an ephemeral or wrong key would write data
/// the UDR can never decrypt. `list` reads only the plaintext SUPI keys, so it needs
/// no key.
fn open(db: Option<String>, key: Option<String>, need_key: bool) -> Result<RedbStore> {
    let db = db.or_else(|| std::env::var(DB_ENV).ok()).unwrap_or_else(|| DEFAULT_DB.to_string());
    let key_hex = key.or_else(|| std::env::var(KEK_ENV).ok());
    let kek = match key_hex {
        Some(h) => subscriber_db::parse_kek_hex(&h)
            .map_err(|e| anyhow::anyhow!("--key / {KEK_ENV}: {e}"))?,
        None if need_key => bail!(
            "a key-encryption key is required: set --key or {KEK_ENV} (64 hex) to the \
             UDR's key, else the UDR can't read what you provision"
        ),
        None => [0u8; 32], // list only reads plaintext SUPIs
    };
    RedbStore::open(&db, kek).map_err(|e| anyhow::anyhow!("open store {db}: {e}"))
}

fn add(store: &RedbStore, a: AddArgs) -> Result<()> {
    // Credentials first (K/OPc/AMF encrypted at rest under the KEK).
    store
        .provision_hex(&a.supi, &a.k, &a.opc, &a.amf)
        .map_err(|e| anyhow::anyhow!("provision credentials: {e}"))?;

    let snssai = match &a.sd {
        Some(sd) => serde_json::json!({ "sst": a.sst, "sd": sd }),
        None => serde_json::json!({ "sst": a.sst }),
    };
    let ambr = serde_json::json!({ "uplink": a.ambr_up, "downlink": a.ambr_down });

    // Nudm_SDM am-data: subscribed slice(s) + UE-AMBR.
    let am = serde_json::json!({
        "nssai": { "defaultSingleNssais": [snssai] },
        "subscribedUeAmbr": ambr,
    });

    // Nudm_SDM sm-data: one slice, one DNN, IPv4-default / IPv4v6-allowed, one default
    // (non-GBR, 5QI 9) QoS flow — enough to register and establish a PDU session.
    let mut dnn_configs = serde_json::Map::new();
    dnn_configs.insert(
        a.dnn.clone(),
        serde_json::json!({
            "pduSessionTypes": { "defaultSessionType": "IPV4", "allowedSessionTypes": ["IPV4", "IPV6"] },
            "sessionAmbr": ambr,
            "5gQosProfile": { "5qi": 9, "arp": { "priorityLevel": 8 } }
        }),
    );
    let sm = serde_json::json!([{ "singleNssai": snssai, "dnnConfigurations": dnn_configs }]);

    // Nudm_SDM smf-selection-data: which DNNs the subscriber may use per slice — the
    // SMF's CreateSMContext authorization gate. Slice key is "SST" or "SST-SD".
    let slice_key = match &a.sd {
        Some(sd) => format!("{}-{}", a.sst, sd),
        None => a.sst.to_string(),
    };
    let mut slice_infos = serde_json::Map::new();
    slice_infos.insert(slice_key.clone(), serde_json::json!({ "dnnInfos": [ { "dnn": a.dnn } ] }));
    let smf_sel = serde_json::json!({ "subscribedSnssaiInfos": slice_infos });

    store.put_provisioned(DataSet::Am, &a.supi, &a.plmn, &am).map_err(str_err)?;
    store.put_provisioned(DataSet::Sm, &a.supi, &a.plmn, &sm).map_err(str_err)?;
    store.put_provisioned(DataSet::SmfSelection, &a.supi, &a.plmn, &smf_sel).map_err(str_err)?;

    println!("provisioned {} (plmn {}, slice {}, dnn {})", a.supi, a.plmn, slice_key, a.dnn);
    Ok(())
}

fn remove(store: &RedbStore, supi: &str) -> Result<()> {
    if store.remove_subscriber(supi) {
        println!("removed {supi}");
    } else {
        println!("no such subscriber: {supi}");
    }
    Ok(())
}

fn list(store: &RedbStore) -> Result<()> {
    let supis = store.list_subscribers().map_err(|e| anyhow::anyhow!("list: {e}"))?;
    if supis.is_empty() {
        println!("(no subscribers)");
    }
    for s in supis {
        println!("{s}");
    }
    Ok(())
}

fn str_err(e: String) -> anyhow::Error {
    anyhow::anyhow!(e)
}
