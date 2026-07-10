# Network Functions, Ports, and Environment

A quick reference for the binaries, the ports they use, and the environment
variables that configure them.

## Binaries and ports

| NF | Binary | Listens on | Notes |
|----|--------|-----------|-------|
| NRF | `nf-nrf` | SBI `:8000` (h2c) | discovery/registration |
| AMF | `nf-amf` | N2 SCTP `:38412` (PPID 60), SBI `:8001` | terminates NGAP/NAS; `:8001` is the callback surface |
| SMF | `nf-smf` | SBI `:8002` (h2c) | PFCP client to the UPF |
| AUSF | `nf-ausf` | SBI `:8003` (h2c) | self-registers with NRF |
| UDM | `nf-udm` | SBI `:8004` (h2c) | stateless `Nudr` front-end |
| UDR | `nf-udr` | SBI `:8005` (h2c) | subscriber store (encrypted redb) + ARPF |
| PCF | `nf-pcf` | SBI `:8006` (h2c) | SM + AM policy |
| CHF | `nf-chf` | SBI `:8007` (h2c) | converged charging |
| UPF | `nf-upf` | N4 UDP `:8805`, N3 UDP `:2152`, N6 TUN | needs `CAP_NET_ADMIN` |

Every SBI NF self-registers with the NRF on startup. All except the UPF speak SBI.

## Environment variables

**UDR (`nf-udr`)** — owns the subscriber store + ARPF

| Variable | Default | Meaning |
|----------|---------|---------|
| `RADIAN_UDR_PROVISION_DEMO` | unset | `1` provisions the TS 35.208 demo subscriber |
| `RADIAN_UDR_DB` | `radian-udr.redb` | path to the encrypted store |
| `RADIAN_UDR_MASTER_KEY` | ephemeral (warns) | 64-hex KEK for encryption at rest |
| `RADIAN_UDR_NRF` | `http://127.0.0.1:8000` | the NRF base URL |

**UDM (`nf-udm`)** — stateless front end, holds no store

| Variable | Default | Meaning |
|----------|---------|---------|
| `RADIAN_UDM_UDR` | `http://127.0.0.1:8005` | the UDR base URL to relay `Nudr` to |
| `RADIAN_UDM_NRF` | `http://127.0.0.1:8000` | the NRF base URL |

**PCF (`nf-pcf`)** and **CHF (`nf-chf`)**

| Variable | Default | Meaning |
|----------|---------|---------|
| `RADIAN_PCF_NRF` / `RADIAN_CHF_NRF` | `http://127.0.0.1:8000` | the NRF base URL |

**SMF (`nf-smf`)**

| Variable | Default | Meaning |
|----------|---------|---------|
| `RADIAN_SMF_UPF_N4` | `127.0.0.1:8805` | the UPF's N4 endpoint |
| `RADIAN_SMF_NRF` | `http://127.0.0.1:8000` | the NRF base URL |

**AUSF (`nf-ausf`)**

| Variable | Default | Meaning |
|----------|---------|---------|
| `RADIAN_AUSF_NRF` | `http://127.0.0.1:8000` | the NRF base URL |

**UPF (`nf-upf`)**

| Variable | Default | Meaning |
|----------|---------|---------|
| `RADIAN_UPF_BIND` | `0.0.0.0` | address to bind N3/N4 to |
| `RADIAN_UPF_N3_ADDR` | `127.0.0.1` | N3 F-TEID address advertised to the gNB |

**BDD suite (`bdd`)**

| Variable | Default | Meaning |
|----------|---------|---------|
| `FREE_RAN_UE_BIN` | unset | path to the free-ran-ue binary (enables the `@sim` feature) |
| `RADIAN_UPF_BIN` | `../target/debug/nf-upf` | UPF binary for the datapath feature |
| `RADIAN_TARGET_DIR` | `../target/debug` | dir holding the `nf-*` binaries |

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
