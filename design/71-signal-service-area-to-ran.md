# Signal the Service Area List to the RAN — Mobility Restriction List

> Built 2026-07-03 on branch `feat/signal-service-area-to-ran`. Design
> [70](70-signal-rfsp-to-ran.md) signalled the AM-policy **RFSP** to the NG-RAN; this
> does the same for the other main AM-policy output — the **service area restriction**
> (the tracking areas a UE is allowed / forbidden to be served in, TS 23.501
> §5.3.4.1). The AMF now hands the RAN a **Mobility Restriction List** (TS 38.413
> §9.2.5.3) carrying the allowed / non-allowed TACs, sourced per-subscriber from the
> PCF AM policy (UDR am-policy-data, design [68](68-udr-am-policy-data.md)).

## Why DownlinkNASTransport

The NGAP *Mobility Restriction List* IE (which contains the Service Area Information)
rides on `DownlinkNASTransport`, `InitialContextSetupRequest`, and `HandoverRequest`.
radian already sends the **Registration Accept** in a `DownlinkNASTransport`, and
TS 38.413 §9.2.5.3 lets that message carry the Mobility Restriction List — so the RAN
learns the UE's service-area restriction with the accept, no new procedure and no
Initial Context Setup needed. free-ran-ue *fully processes* this message (it delivers
the NAS to the UE), so — unlike the RFSP UE Context Modification the sim ignored
(design/70) — its successful decode is a real oxirush↔free5gc wire-compat check.

## What was built

### PCF / UDR (`sbi_core::npcf_am`, `nf-udr`)

- New `ServiceAreaRestriction { restriction_type, tacs }` DTO (TS 29.571):
  `restrictionType` is `ALLOWED_AREAS` / `NOT_ALLOWED_AREAS`, `tacs` are hex TAC
  strings ("000001").
- `PolicyAssociation` + `AmPolicyConfig` gained `servAreaRes` (TS 29.507 field name);
  `AmPolicyConfig::demo()` allows only the serving area (TAC 000001).
- `nf-udr` provisions the demo subscriber's am-policy-data with the same
  `servAreaRes`, so the restriction is sourced from the UDR (design/68 path).

### `ngap`

- `downlink_nas_transport_with_area_restriction(amf, ran, nas, mcc, mnc,
  allowed_tacs, not_allowed_tacs)` — builds the Registration Accept transport plus a
  `MobilityRestrictionList` whose Service Area Information carries the allowed /
  non-allowed TACs (3-octet). An empty side omits that IE.
- `area_restriction_from_downlink_nas` — extracts `(allowed, non_allowed)` (RAN
  side / tests).

### `nf-amf`

- `UeContext.area_restriction: Option<(allowed, non_allowed)>`.
- `parse_tac` (6 hex → 3 octets) + `area_restriction_tacs` — split the PCF
  `servAreaRes` into allowed / non-allowed TAC lists, dropping malformed entries.
- `on_security_mode_complete` stores the restriction and, when present, builds the
  Registration Accept with `downlink_nas_transport_with_area_restriction` instead of
  the plain transport.

## Boundaries / notes

- **Single Service Area Information item**, keyed by the serving PLMN. Forbidden-area
  info, RAT restrictions, equivalent PLMNs, and `maxNumOfTAs` are not modelled.
- **Applied at registration only.** A mid-connection `servAreaRes` change (via the
  design/69 UpdateNotify) is not yet carried to the RAN — the Mobility Restriction
  List would ride the Configuration Update Command's DownlinkNASTransport (follow-up).
- **The RAN enforces it.** The AMF signals the restriction; the gNB is responsible for
  honouring the allowed/non-allowed areas (out of scope for the core).

## Verification

- `cargo test --workspace --exclude bdd` — green (**152** tests). New:
  - ngap `downlink_nas_with_area_restriction_roundtrips` — allowed TAC 000001 +
    non-allowed 00000a survive APER encode→decode; a plain transport has no
    restriction.
  - nf-amf `service_area_restriction_reaches_the_ran` — `servAreaRes` → allowed /
    non-allowed TACs (malformed dropped, `ALLOWED`/`NOT_ALLOWED` bucketing), then the
    Registration Accept transport carries them and the RAN reads them back.
  - npcf_am / registration tests extended: the demo policy's `servAreaRes` survives
    the h2c round trip and parses to the allowed TAC.
- `cargo clippy --workspace --exclude bdd` — clean.
- **BDD 2 features / 5 scenarios / 25 steps green** — the live `@sim` registration
  now carries the Mobility Restriction List on the Registration Accept and the real
  free-ran-ue UE still registers + pings (its free5gc decoder accepts the IE).
- **Live loopback (real NRF+UDR+UDM+AUSF+PCF+AMF + free-ran-ue)** — the AMF logs
  *"AM policy service area restriction — allowed TACs [[0, 0, 1]], non-allowed []"*
  (sourced from the UDR demo am-policy-data via the PCF), sends the Registration
  Accept, and the UE logs *"UE Registration finished"* — proving the free5gc gNB
  decoded the Mobility-Restriction-List-carrying message.

## Known limitations / next steps

- **Carry a `servAreaRes` change mid-connection** (design/69 UpdateNotify → a
  Mobility Restriction List on the Configuration Update Command).
- **Richer restrictions** — forbidden areas, RAT restrictions, per-slice areas.
- **A full Initial Context Setup procedure** would carry the Mobility Restriction List
  (and RFSP + security context) at the UE-context level, as in a production AMF.
