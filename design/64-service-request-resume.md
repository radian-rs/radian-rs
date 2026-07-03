# Service Request — CM-IDLE → CM-CONNECTED Resume

> Built 2026-07-03 on branch `feat/service-request`. **Idle-mode arc slice 2.**
> Slice 1 ([63](63-an-release-cm-idle.md)) took a UE to CM-IDLE on AN release but
> left it stuck — nothing brought it back. This adds the **Service Request**
> (TS 23.502 §4.2.3.2): a CM-IDLE UE returns, the AMF restores its retained
> context and **re-activates its PDU sessions' user plane**, moving back to
> CM-CONNECTED. The full idle→resume loop now closes.

## What was built

### AMF-wide retained-context store (`nf-amf`)

The crux slice 1 flagged. A `RETAINED: Mutex<HashMap<u32, UeContext>>` keyed by
**5G-TMSI** holds CM-IDLE contexts. On AN release the context is **moved** out of
the per-association map into `RETAINED` (and its `UE_DIRECTORY` reachability entry
dropped — the UE is unreachable over N2 while idle). It is keyed by the UE's
assigned **5G-GUTI TMSI** (`UeContext.guti_tmsi`, recorded at Registration
Accept), *not* the per-N2-connection AMF-UE-NGAP-ID — so the key is stable across
repeated idle/resume cycles and matches what the UE presents. The store is
AMF-wide, so a UE can resume on **any** gNB association, not just the one it left.

### Service Request handling (`nf-amf`)

`handle_ngap`'s InitialUEMessage arm first checks the NGAP **5G-S-TMSI** IE
(cleartext, from RRC) against `RETAINED`; a hit routes to `on_service_request`
instead of a fresh registration. It:

1. takes the retained context and **verifies** the integrity-protected Service
   Request NAS with its NAS security keys (a failure re-retains it);
2. restores the context under a fresh AMF-UE-NGAP-ID, sets the new RAN-UE-NGAP-ID,
   re-adds `UE_DIRECTORY`, and marks it **CM-CONNECTED**;
3. sends a **Service Accept**;
4. re-activates each PDU session — `AmfSmf::activate_up_connection` (Nsmf
   UpdateSMContext `upCnxState=ACTIVATING`) returns the retained UPF N3 F-TEID +
   QoS, and the AMF re-sends the **N2 PDU Session Resource Setup**. The gNB's new
   F-TEID comes back through the existing setup-response path → UpdateSMContext
   re-installs the UPF downlink that AN release had dropped.

### SMF (`nf-smf`) + NAS/NGAP

- SMF: `UpdateSMContext {upCnxState: "ACTIVATING"}` returns the session's N2 info
  (the shape CreateSMContext returns), rebuilt from the stored context — which now
  keeps `n3_addr` + `snssai`. The response parser is factored into
  `parse_sm_context_created`, shared by create and activate.
- nas: `service_request` / `service_request_info` (service type + 5G-TMSI packed
  in octet 4) and `service_accept`.
- ngap: `initial_ue_message_with_stmsi` + `fiveg_s_tmsi_from_initial_ue`.

## Boundaries / notes

- **No N1 SM on the resume N2 setup** — the Service Accept goes as a standalone
  DownlinkNASTransport; the re-sent PDU Session Resource Setup carries an empty
  NAS-PDU (structurally valid for the codec; a real gNB tolerates it). MO-data /
  signalling-only service types aren't distinguished — every resume reactivates
  all sessions.
- **Not driven by free-ran-ue** — the sim implements neither idle mode nor Service
  Request, so the procedure is unit/integration-tested plus a real-binary SMF↔UPF
  smoke.
- **No paging** — this is UE-initiated resume (mobile-originated). Network-initiated
  resume (downlink data → paging) is slice 3.
- No **T3512 / mobile-reachable timer** — a UE that never returns lingers in
  `RETAINED` indefinitely (eviction is a follow-up).

## Verification

- `cargo test --workspace --exclude bdd` — green (**139** tests). New:
  - nas `service_request_round_trips`, ngap `initial_ue_with_stmsi_roundtrips`.
  - nf-amf `service_request_resumes_a_cm_idle_ue` — a retained CM-IDLE context +
    a protected Service Request restores under a fresh AMF-UE-NGAP-ID, the SMF is
    asked to re-activate, and the downlinks are `ServiceAccept` +
    `PDUSessionResourceSetupRequest (resume)`; the UE decodes the Service Accept.
    The AN-release test now asserts the context lands in `RETAINED` (keyed by
    5G-TMSI), not the association map.
- **BDD 2 features / 5 scenarios / 25 steps green** — unaffected.
- **Live (real binaries)** — driving the SMF through **create → activate →
  deactivate (AN release) → `ACTIVATING` → re-install**, the `ACTIVATING` response
  returns the retained `upN3Teid`/`upN3Addr`/`ueIpv4Addr` + `sessionAmbr` +
  `qosFlows` (including the GBR flow), and the SMF log shows the downlink dropped
  then re-installed to a *new* gNB tunnel — the exact N2 info the AMF rebuilds the
  setup from, end to end over the real SMF↔UPF.

## Known limitations / next steps

- **Paging + DL buffering + Downlink Data Notification** — slice 3: BUFF at the
  UPF (with a BAR), a PFCP Session Report (DL data) → SMF → AMF → NGAP Paging →
  the UE answers with this Service Request path.
- **Retained-context eviction** (T3512 / implicit deregistration) so a UE that
  never comes back doesn't leak.
- **Service type differentiation** (signalling-only vs data) and carrying the
  reactivation result in the Service Accept's PDU-session-status IEs.
