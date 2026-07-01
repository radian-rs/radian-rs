# Building and Running

## Build

radiant-rs is a standard Cargo workspace:

```
cargo build
```

This produces one binary per NF under `target/debug/` (`nf-nrf`, `nf-amf`,
`nf-smf`, `nf-upf`, `nf-ausf`, `nf-udm`, …). For quick verification of the unit
tests, run everything except the privileged integration crate:

```
cargo test --workspace --exclude bdd
```

The [`bdd`](ch-04-01-bdd-tests.md) crate is a netns-based integration suite that
needs `sudo` and Linux; it is run separately with `cargo test -p bdd`.

## Running the control plane

Bring the NFs up in dependency order. The **NRF first** (others register with
it), then the data-management and authentication NFs, then the SMF and AMF.

```
# 1. NRF — discovery/registration bus
./target/debug/nf-nrf

# 2. UDM — with the demo subscriber provisioned (see below)
RADIANT_UDM_PROVISION_DEMO=1 \
RADIANT_UDM_DB=/tmp/radiant-udm.redb \
RADIANT_UDM_MASTER_KEY=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff \
  ./target/debug/nf-udm

# 3. AUSF — self-registers with the NRF
./target/debug/nf-ausf

# 4. UPF — needs CAP_NET_ADMIN for its N6 TUN
sudo ./target/debug/nf-upf

# 5. SMF — associates with the UPF over N4, registers with the NRF
./target/debug/nf-smf

# 6. AMF — terminates N2 (NGAP/SCTP) on :38412
./target/debug/nf-amf
```

Each NF logs a startup banner and a "listener up" line. The SMF logs
`PFCP association established with UPF` and `registered SMF with NRF`; the AUSF
logs `registered AUSF with NRF`. Once those appear, the control plane is ready
for a gNB to associate.

## The demo subscriber

The UDM ships a **demo subscriber** using a public TS 35.208 test key. It is
provisioned **only** when `RADIANT_UDM_PROVISION_DEMO=1` — a production build
never auto-creates a known-key account.

| Field | Value |
|-------|-------|
| SUPI | `imsi-999700000000001` |
| K | `465b5ce8b199b49faa5f0a2ee238a6bc` |
| OPc | `cd63cb71954a9f4e48a5994e37a02baf` |
| AMF (auth mgmt field) | `8000` |

A UE that presents this identity (PLMN MCC 999 / MNC 70, MSIN 0000000001) will
authenticate. This is exactly the subscriber the
[interop walkthrough](ch-04-00-free-ran-ue-interop.md) uses.

## The user plane

The UPF opens a TUN device (`n6upf0`, `10.45.0.1/16`) for N6, which requires
`CAP_NET_ADMIN` — hence `sudo`. Without it, the UPF still serves N4 and N3 but
logs `N6 TUN unavailable … user-plane forwarding disabled` and drops user
traffic. Its bind and advertised addresses are configurable:

```
RADIANT_UPF_BIND=127.0.0.1        # what to bind N3/N4 to (default 0.0.0.0)
RADIANT_UPF_N3_ADDR=10.0.1.1      # the N3 F-TEID address advertised to the gNB
```

## Persistence and the master key

The UDM stores credentials in an encrypted [redb](ch-02-01-subscriber-store.md)
file (`RADIANT_UDM_DB`). Records are AES-256-GCM encrypted under a key-encryption
key (`RADIANT_UDM_MASTER_KEY`, 64 hex chars). If the KEK is not set, the UDM uses
an **ephemeral** key and loudly warns — persisted records become unreadable after
a restart, so always set the KEK for a stable deployment.

## Bringing in a RAN

radiant-rs implements the core, not the radio. To exercise it end to end you
need a gNB and a UE. The [free-ran-ue](ch-04-00-free-ran-ue-interop.md) chapter
walks through pointing that simulator at your core, from NG Setup to a forwarded
`ping`.
