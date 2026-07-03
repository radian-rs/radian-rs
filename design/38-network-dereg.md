# Network-Initiated Deregistration (Subscription Withdrawal) — Implementation Notes

> Built 2026-07-03 on branch `feat/network-dereg`. Closes the "network-initiated
> deregistration" gap from [37](37-deregistration.md): withdrawing a subscription
> at the UDR now chases the UE off the network — TS 24.501 §5.5.2.3 / TS 23.502
> §4.2.2.3.3, trimmed.

The trigger chain: `DELETE /nudr-dr/v2/subscription-data/{ueId}` at the UDR →
the store is wiped → the UDR notifies the serving AMF (a `DeregistrationData`
callback) → the AMF sends the UE a **Deregistration Request (UE terminated)**,
releases the PDU session and both UE contexts.

## What was built

- **`subscriber-db`** — `SubscriberDb::remove_subscriber`: credentials, SQN, and
  every provisioned document for the SUPI go (both backends; redb collects the
  `(supi, plmn)` keys per doc table and removes them in one write txn).
- **`sbi_core::nudr`** — `DELETE …/subscription-data/{ueId}` (404 when unknown)
  plus `router_with_notify(store, nrf_base)`: a successful withdrawal spawns a
  best-effort notification — discover the AMF via the NRF, POST
  `{"deregReason": "SUBSCRIPTION_WITHDRAWN"}` to
  `/namf-callback/v1/{supi}/dereg-notify`. **Deviation:** TS 23.502 mediates
  this through UDM data-change subscriptions; we collapse UDR→UDM→AMF to
  UDR→AMF. `UdrClient::delete_subscriber` for ops/tests; `nf-udr` enables the
  notifier with its NRF base.
- **The AMF grows an SBI surface** — first HTTP server in the AMF
  (`namf-callback`, **:8001**), registered with the NRF via
  `register_and_maintain` (every SBI NF now self-registers). The callback
  resolves the SUPI through a new **`UE_DIRECTORY`** (SUPI → AMF-UE-NGAP-ID +
  the owning association's channel) and answers 404 for unserved UEs.
- **Reaching into the association** — UE contexts live inside each gNB's SCTP
  task, so `serve_gnb` now `select!`s between `sctp_recv` and a per-association
  deregistration channel; directory entries are added when a UE is identified
  and removed on every context-drop path (UE dereg, #62 reject, network dereg,
  association loss).
- **`on_network_deregistration`** — release the SM context at the SMF (best
  effort), NAS-protect a Deregistration Request (UE terminated, re-registration
  not required), send the UEContextReleaseCommand (cause *deregister*), drop the
  contexts. **Deviation:** no T3522 retransmission / waiting for the UE's
  Deregistration Accept — cleanup is immediate.

## Verification

- `cargo test --workspace --exclude bdd` — green. New:
  - `subscriber-db::remove_subscriber_withdraws_everything` (both backends).
  - `sbi-core::nudr::subscription_withdrawal_notifies_the_amf` — real
    UDR + NRF + mock-AMF chain over h2c: DELETE wipes the store (AV generation
    dies, second DELETE 404s) and the AMF callback fires exactly once.
  - `nf-amf::subscription_withdrawal_deregisters_the_ue` — the callback router
    turns the POST into the association-channel message (unknown SUPI 404s);
    the dereg flow emits [DeregistrationRequest, UEContextReleaseCommand
    (cause deregister)], the UE-side unprotect sees the UE-terminated request,
    and both the context and directory entry are gone.
- **Live loopback demo**: full free-ran-ue session, then
  `curl -X DELETE …/subscription-data/imsi-999700000000001` → `204`; UDR logs
  "subscription withdrawn" + "AMF notified"; AMF logs "deregistering UE 1" →
  SM release → DeregistrationRequest → UEContextReleaseCommand; SMF logs the N4
  deletion; the UE logs the arriving protected NAS bytes (free-ran-ue doesn't
  implement UE-terminated dereg — the delivery is what's observable).
- **BDD, 5 scenarios / 25 steps green** (regression).

## Known limitations / next steps

- **No T3522** — the request is not retransmitted and the UE's accept is not
  awaited; an unreachable UE just loses its contexts immediately.
- **One AMF assumed** — the UDR notifies the first NRF-discovered AMF; real
  UECM registration (which AMF serves this SUPI) is unmodeled.
- **UE_DIRECTORY is per-process** — fine for one AMF instance.
- UE-AMBR from am-data, AMF-side SMF selection, and back-off enforcement remain
  open.
