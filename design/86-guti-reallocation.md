# GUTI Reallocation on a Registration Update

> Built 2026-07-04 on branch `feat/guti-reallocation`. Designs
> [76](76-mobility-registration-update.md)/[85](85-periodic-registration.md)
> handled mobility and periodic registration updating but **kept the same
> 5G-GUTI** — a boundary both noted. A real AMF reallocates the 5G-GUTI on a
> registration update (TS 24.501 §5.4.1.3), handing the UE a fresh 5G-TMSI to
> limit long-term traceability. This does that, re-keying the TMSI-indexed
> stores.

## What was built

### `nas`

`guti_tmsi_from_registration_accept` — reads the 5G-TMSI from a Registration
Accept's 5G-GUTI IE (the UE / test side of a reallocation), mirroring the
existing request-side parser.

### `nf-amf` — `on_service_request`

On a **registration update** (mobility or periodic — not a Service Request, which
is a resume, not a registration), the AMF now assigns a **fresh 5G-TMSI** = this
connection's AMF-UE-NGAP-ID (the same scheme initial registration uses,
design/77), and:

- puts it in the Registration Accept's 5G-GUTI (`reg_tmsi`);
- **re-keys `GUTI_DIRECTORY`**: drops the SUPI's old TMSI, inserts `new_tmsi →
  SUPI`, so a later GUTI re-registration (design/60) resolves the new one;
- sets `ctx.guti_tmsi = new_tmsi`, so the **`RETAINED` store re-keys naturally**
  on the next AN release (which retains under `ctx.guti_tmsi`) — and the UE's next
  Service Request presents the new 5G-S-TMSI, which finds the re-keyed retained
  context.

A Service Request keeps the GUTI unchanged (`reg_tmsi = tmsi`).

## Boundaries / notes

- **No Registration Complete tracking.** Per spec the reallocation completes when
  the UE confirms with a Registration Complete; here the AMF commits the new GUTI
  immediately and the UE is expected to adopt it (the old GUTI is not kept valid in
  parallel). free-ran-ue can't drive this path anyway.
- **Always reallocates** on a registration update — a real AMF applies an operator
  policy (periodically, on TAI change, …); the demo reallocates every time so the
  behaviour is observable.
- The TMSI = AMF-UE-NGAP-ID scheme is the existing single-AMF convention; a real
  AMF allocates from a managed 5G-TMSI space.

## Verification

- `cargo test --workspace --exclude bdd` — green (**174** tests). Extended:
  - nas `registration_accept_builds_and_decodes` — the assigned 5G-GUTI's TMSI
    reads back via `guti_tmsi_from_registration_accept`.
  - nf-amf `periodic_registration_update_refreshes_without_reauth` — the periodic
    accept now carries a **new** 5G-TMSI (≠ the one the UE presented);
    `ctx.guti_tmsi` is the new value; `GUTI_DIRECTORY` has the old TMSI removed and
    `new → SUPI` inserted; the UE reads the new GUTI out of the accept.
- `cargo clippy --workspace --exclude bdd` — clean.
- **BDD 2 features / 5 scenarios / 25 steps green** — the initial-registration @sim
  path is unaffected (no registration update there).
- Not sim-drivable — free-ran-ue can't go CM-IDLE / re-register (design/64/65
  precedent); integration-tested end to end.

## Known limitations / next steps

- **Registration Complete tracking** for the reallocation (keep both GUTIs valid
  until confirmed).
- **Operator reallocation policy** instead of always-reallocate.
- **Uplink Data Status** — a registration update requesting immediate UP for
  listed sessions (the remaining design/76 follow-up).
