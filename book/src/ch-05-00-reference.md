# Network Functions, Ports, and Environment

A quick reference for the binaries, the ports they use, and the environment
variables that configure them.

## Binaries and ports

| NF | Binary | Listens on | Notes |
|----|--------|-----------|-------|
| NRF | `nf-nrf` | SBI `:8000` (h2c) | discovery/registration |
| SMF | `nf-smf` | SBI `:8002` (h2c) | PFCP client to the UPF |
| AUSF | `nf-ausf` | SBI `:8003` (h2c) | self-registers with NRF |
| UDM | `nf-udm` | SBI `:8004` (h2c) | encrypted redb store |
| AMF | `nf-amf` | N2 SCTP `:38412` (PPID 60) | terminates NGAP/NAS |
| UPF | `nf-upf` | N4 UDP `:8805`, N3 UDP `:2152`, N6 TUN | needs `CAP_NET_ADMIN` |

The `nf-udr` and `nf-pcf` binaries are scaffolding.

## Environment variables

**UDM (`nf-udm`)**

| Variable | Default | Meaning |
|----------|---------|---------|
| `RADIANT_UDM_PROVISION_DEMO` | unset | `1` provisions the TS 35.208 demo subscriber |
| `RADIANT_UDM_DB` | `radiant-udm.redb` | path to the encrypted store |
| `RADIANT_UDM_MASTER_KEY` | ephemeral (warns) | 64-hex KEK for encryption at rest |

**SMF (`nf-smf`)**

| Variable | Default | Meaning |
|----------|---------|---------|
| `RADIANT_SMF_UPF_N4` | `127.0.0.1:8805` | the UPF's N4 endpoint |
| `RADIANT_SMF_NRF` | `http://127.0.0.1:8000` | the NRF base URL |

**AUSF (`nf-ausf`)**

| Variable | Default | Meaning |
|----------|---------|---------|
| `RADIANT_AUSF_NRF` | `http://127.0.0.1:8000` | the NRF base URL |

**UPF (`nf-upf`)**

| Variable | Default | Meaning |
|----------|---------|---------|
| `RADIANT_UPF_BIND` | `0.0.0.0` | address to bind N3/N4 to |
| `RADIANT_UPF_N3_ADDR` | `127.0.0.1` | N3 F-TEID address advertised to the gNB |

**BDD suite (`bdd`)**

| Variable | Default | Meaning |
|----------|---------|---------|
| `FREE_RAN_UE_BIN` | unset | path to the free-ran-ue binary (enables the `@sim` feature) |
| `RADIANT_UPF_BIN` | `../target/debug/nf-upf` | UPF binary for the datapath feature |
| `RADIANT_TARGET_DIR` | `../target/debug` | dir holding the `nf-*` binaries |

## The demo subscriber

| Field | Value |
|-------|-------|
| SUPI | `imsi-999700000000001` |
| K | `465b5ce8b199b49faa5f0a2ee238a6bc` |
| OPc | `cd63cb71954a9f4e48a5994e37a02baf` |
| AMF | `8000` |
| PLMN | MCC 999 / MNC 70 |

## Standards touched

| Interface | Protocol | Spec |
|-----------|----------|------|
| N1 | NAS (5GMM + 5GSM) | TS 24.501 |
| N2 | NGAP (APER) | TS 38.413 |
| N3 / N9 | GTP-U | TS 29.281 |
| N4 | PFCP | TS 29.244 |
| SBI | HTTP/2 + JSON | TS 29.5xx / OpenAPI |
| Auth | 5G-AKA, key derivation | TS 33.501, TS 35.208 |
| NRF | NF management/discovery | TS 29.510 |

## Deferred by design

These are known gaps, called out where they arise in the book:

- **SBI security** — no TLS, no OAuth2 (TS 33.501).
- **N4 / N3 security** — no IPsec; relies on network isolation.
- **SUCI** — only the null scheme; ECIES (Profile A/B) not implemented.
- **5G-AKA** — no SQN resynchronisation (AUTS).
- **NAS** — algorithms fixed at NIA2/NEA2, no negotiation.
- **Sessions** — one PDU session per UE, IPv4 only, DNN `internet`.
- **Credentials** — KEK from the environment (HSM/KMS seam ready), no rotation;
  data behind the UDM rather than a separate UDR.
