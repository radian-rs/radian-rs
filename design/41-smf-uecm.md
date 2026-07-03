# SMF-Side UECM + Config Advertise Address — Implementation Notes

> Built 2026-07-03 on branch `feat/smf-uecm`. Two follow-ups from
> [40](40-uecm.md): the SMF now records itself as the serving SMF per PDU session
> (Nudm_UECM `smf-registrations`), and the AMF's callback advertise address is
> config-derived so it works off-loopback.

## Config advertise address (commit 1)

The AMF's NRF-profile IP and its `deregCallbackUri` host were both hardcoded to
`127.0.0.1`. `RADIAN_AMF_ADVERTISE_ADDR` (default `127.0.0.1`) now supplies the
advertised host for both; `register_with_nrf` takes a host string. Single-host
runs are unchanged; multi-host deployments set the env so the UDR's withdrawal
callback reaches the right AMF.

## SMF-side UECM (commit 2)

Mirrors the AMF UECM slice ([40](40-uecm.md)) for the session layer:

- **`subscriber-db`** — the `smf_registrations` table keyed `(SUPI, PDU session
  id)` behind `get/put/remove_smf_registration`; `remove_subscriber` purges all
  of a SUPI's entries (redb collects the per-SUPI session ids, then removes).
- **`sbi_core::nudr`** — TS 29.505 context-data routes
  `…/context-data/smf-registrations/{pduSessionId}` (PUT/GET/DELETE) + client.
- **`sbi_core::nudm`** — **Nudm_UECM** `PUT/DELETE
  /nudm-uecm/v1/{supi}/registrations/smf-registrations/{pduSessionId}` with
  `SmfRegistration {smfInstanceId, pduSessionId, dnn}`, proxied to the UDR;
  `NudmClient::uecm_register_smf / uecm_deregister_smf`.
- **`nf-smf`** — a stable `SMF_INSTANCE_ID`; `SmContext` now carries `supi` /
  `pdu_session_id` / `dnn`. On CreateSMContext it registers (discover UDM via the
  NRF — the same path Nudm_SDM already uses); on ReleaseSMContext it purges.
  Both best-effort, spawned off the signaling path — the session's success
  never hinges on the UDM.

## Verification

- `cargo test --workspace --exclude bdd` — green (26 suites). New/updated:
  - `subscriber-db::smf_registration_crud_and_persistence` (per-session keying,
    reopen, per-session purge) + wiped by `remove_subscriber`.
  - `sbi-core::nudr::smf_uecm_registration_roundtrips_through_udm_and_udr` — full
    chain: register via the UDM front → per-session document at the UDR → purge
    → 404 on re-purge; a different PDU session is independent.
  - `nf-smf` create/update test now spins the UDR/UDM chain and asserts the
    serving-SMF registration appears after CreateSMContext (dnn + pduSessionId)
    and is gone after ReleaseSMContext.
- **Live loopback demo**: with a full free-ran-ue session, the SMF logs "UECM:
  registered as the serving SMF psi=4" and the UDM logs the registration with
  the stable instance id; a graceful UE deregistration releases the session and
  the SMF logs "serving-SMF registration purged psi=4" (UDM confirms).
  (free-ran-ue uses PDU session id 4.)
- **BDD, 5 scenarios / 25 steps green** (regression).

## Known limitations / next steps

- **Advertise address is host-only over http** — no TLS/apiRoot scheme handling;
  arrives with SBI security hardening.
- **No cross-NF consistency on stale registrations** — if the SMF crashes
  mid-session the registration lingers until the subscriber is withdrawn (no
  UECM heartbeat/expiry, unlike the NRF).
- Multiple PDU sessions per UE, UE-AMBR from am-data, AMF-side SMF selection,
  and SBI security hardening remain open.
