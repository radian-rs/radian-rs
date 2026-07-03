# Allowed NSSAI at Registration — Implementation Notes

> Built 2026-07-03 on branch `feat/allowed-nssai`. Closes the top "next step" of
> [31](31-requested-snssai.md): the AMF starts consuming **am-data** — slice
> admission now begins at registration, not only at session establishment.

## What was built

- **Nudm_SDM `am-data`** (`sbi_core::nudm`) — `GET /nudm-sdm/v2/{supi}/am-data`
  proxying the UDR's Access-and-Mobility document (same `plmn-id` query and
  `sdm_fetch` path as sm-data); `NudmClient::get_am_data`. The demo document has
  been provisioned since [26](26-udr-nudr-relocation.md) — this makes it readable.
- **`nas` NSSAI IE plumbing** — `nssai_value` / `parse_nssai_value` encode and
  decode the TS 24.501 §9.11.3.37 value (length-prefixed S-NSSAIs, SST-only and
  SST+SD forms; mapped-HPLMN forms skipped). `registration_accept` gains an
  `allowed_nssai` parameter, emitted as IEI **0x15** when non-empty;
  `allowed_nssai_from_registration_accept` for the UE side/tests.
- **AMF registration leg** — on Security Mode Complete the AMF discovers the UDM
  via the NRF, fetches am-data, and derives the allowed NSSAI from
  `nssai.defaultSingleNssais` (requested-NSSAI intersection is future — we grant
  the subscribed defaults). It is stored in `UeContext` and sent in the
  Registration Accept. **Fail-open:** a failed fetch logs a warning, the accept
  goes out without the IE, and admission falls back to the SMF's check —
  registration never blocks on the UDM.
- **Local slice admission at PDU establishment** — a requested S-NSSAI outside
  the UE's allowed NSSAI is rejected by the AMF directly (5GSM cause **#70** +
  T3396 back-off) with **no SMF round trip**; unknown allowed NSSAI falls
  through to the SMF's subscription gate.

## Verification

- `cargo test --workspace --exclude bdd` — green. New/updated:
  - `sbi-core::nudm::sdm_am_data_proxies_the_udr_document` — real h2c UDR→UDM
    chain; per-PLMN and unknown-SUPI 404s.
  - `nas`: NSSAI value round trip (SST-only + SST+SD, truncation-safe parse);
    Registration Accept carries and yields the allowed NSSAI (and omits the IE
    when empty).
  - `nf-amf::full_registration_completes` — the UE-side decode now asserts the
    allowed NSSAI arrives through NAS security.
- **BDD, 5 scenarios / 25 steps green** (with `FREE_RAN_UE_BIN`) — the live
  free5GC-based UE decodes the Registration Accept **with the new 0x15 IE**
  (wire-compat confirmed), registers, and completes its session + ping.
- **Loopback log confirmation** (fail-open means e2e success alone doesn't prove
  population): AMF logs `sending Registration Accept (allowed NSSAI:
  [(1, Some([1, 2, 3]))])`, and the corporate-DNN UE passes the local slice gate
  then gets the SMF's refusal as cause #70 + back-off.

## Known limitations / next steps

- **No requested-NSSAI intersection** — the Registration Request's requested
  NSSAI is ignored; the allowed NSSAI is simply the subscribed defaults. No
  rejected-NSSAI IE either.
- **Allowed NSSAI is per-registration only** — not re-fetched on am-data change
  (no Nudm_SDM subscriptions / UE Configuration Update for slices).
- **UE-AMBR from am-data still unread** (the accept has no UE-AMBR concept; it
  would feed the RAN via NGAP — future).
- **AMF-side SMF selection** by (S-NSSAI, DNN) remains open (design/27).
