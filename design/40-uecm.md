# UECM Serving-AMF Tracking — Implementation Notes

> Built 2026-07-03 on branch `feat/uecm`. Closes the "one AMF assumed" gap from
> [38](38-network-dereg.md): the UDR no longer notifies the *first NRF-discovered*
> AMF on a withdrawal — it notifies **the serving AMF recorded via Nudm_UECM**
> (TS 29.503 §5.3), at the deregistration callback that AMF registered.

This also lands the fourth data class from the [24](24-db-subscriber-nf.md)
partitioning: dynamic **context data** (`amf-3gpp-access`), written at
registration and purged at deregistration.

## What was built

- **`subscriber-db`** — the `amf_3gpp_reg` table (SUPI → JSON, per doc 24's
  sketch) behind `get/put/remove_amf_registration`; `remove_subscriber` wipes it
  with everything else.
- **`sbi_core::nudr`** — TS 29.505 context-data routes:
  `PUT/GET/DELETE …/subscription-data/{ueId}/context-data/amf-3gpp-access`,
  plus `UdrClient` methods. The withdrawal handler now reads the registration's
  **`deregCallbackUri`** (before the wipe) and POSTs `DeregistrationData` there —
  `router_with_notify` and the NRF-discovery heuristic are gone; a subscriber
  with no serving AMF notifies nobody.
- **`sbi_core::nudm`** — **Nudm_UECM**: `PUT/DELETE
  /nudm-uecm/v1/{supi}/registrations/amf-3gpp-access` with
  `Amf3GppAccessRegistration {amfInstanceId, deregCallbackUri}` proxied to the
  UDR (trim: deregistration is a DELETE, not the spec's purge-flag PATCH);
  `NudmClient::uecm_register_amf / uecm_deregister_amf`.
- **AMF** — a stable `AMF_INSTANCE_ID` (one UUID for the NRF profile and every
  UECM registration). On **Registration Complete** it records itself as the
  serving AMF (callback `…:8001/namf-callback/v1/{supi}/dereg-notify`); on every
  deregistration completion — UE-initiated, network-initiated accept, T3522
  abort — it purges the registration. All best-effort, spawned off the
  signaling path. (#62-rejected UEs never reach Registration Complete, so
  nothing to purge.)

## Verification

- `cargo test --workspace --exclude bdd` — green. New/updated:
  - `subscriber-db::amf_registration_crud_and_persistence` (+ wiped by
    `remove_subscriber`).
  - `sbi-core::nudr::uecm_registration_roundtrips_through_udm_and_udr` — the
    full UECM chain: register via the UDM front → readable at the UDR → purge →
    404 on re-purge.
  - `subscription_withdrawal_notifies_the_serving_amf` (reworked) — the stored
    callback fires exactly once; a subscriber with **no** UECM registration
    notifies nobody.
- **Live loopback demo**: at registration the UDM logs "serving AMF registered
  (UECM)" with the stable instance id; `curl GET context-data` returns the
  stored document; `curl DELETE` → UDR logs "serving AMF **notified**" (the
  discovery path no longer exists — success proves the stored URI) and the AMF
  starts the T3522-supervised deregistration.
- **BDD, 5 scenarios / 25 steps green** (regression).

## Security: the callback is a bounded SSRF surface

The `deregCallbackUri` is written through **unauthenticated** SBI endpoints and
then POSTed to by the UDR on withdrawal — server-side request forgery (flagged
by the commit security review). Mitigations landed: the URI is restricted to
`http`/`https` (rejected with `400` at the UECM front, re-checked at call time so
a raw context-data PUT can't bypass it), and the callback client does **not**
follow redirects. The residual risk — steering the callback at an internal
*HTTP* target — is only fully closed by SBI mutual auth (the deferred TS 33.501
hardening: only a cert-holding AMF may register a callback). Host allowlisting
isn't viable here because the legitimate AMF shares the private/loopback space
with any internal target. Documented in `sbi_core::nudr`'s `# Security` note.

## Known limitations / next steps

- **The callback URI is loopback-built** (`127.0.0.1:8001`) — fine for the
  single-host deployment; a config-derived advertise address arrives with
  multi-host work.
- **No UECM for the SMF** (smf-registrations) — sessions are still tracked only
  in AMF/SMF memory.
- Multiple PDU sessions, UE-AMBR from am-data, AMF-side SMF selection, and SBI
  security hardening remain open.
