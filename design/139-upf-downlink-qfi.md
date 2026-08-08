# UPF downlink QFI marking (design/137 G11)

> Built 2026-08-08 on branch `free5gc`. Closes **G11** from
> [137](137-free5gc-422-gap-survey.md) §8 — the one gap the free5gc and open5gs
> surveys ([137](137-free5gc-422-gap-survey.md)/[138](138-open5gs-gap-survey.md))
> agree radian is missing against *every* reference stack.

## The gap

A UPF must stamp every **downlink** G-PDU with a **DL PDU Session Information**
frame (a PDU Session Container GTP-U extension header, TS 38.415 §5.5.2.1)
carrying the packet's **QFI**. The gNB reads that QFI to map the QoS flow onto a
DRB — without it, a conformant gNB has no way to place downlink traffic on the
right radio bearer. Both reference UPFs do this on **every** downlink packet,
including buffered packets when they flush and End Markers:

- free5gc's gtp5g: always marks (`lib/pfcp/handler.c:255` in open5gs terms;
  gtp5g writes the PDU Session Container unconditionally).
- open5gs: `lib/pfcp/handler.c:255-262` sets the container from `pdr->qer->qfi`
  on every forwarded downlink, on buffered flush (same path), and on End Markers.

radian had `gtpu::encap_dl_qfi()` (and `psup::dl_frame()`) but **no caller** —
the UPF's uplink already parsed the QFI out of the container, but the downlink
path used the plain `gtpu::encap()`, so the gNB received unmarked G-PDUs. This
was a real-gNB correctness bug, not a robustness nicety.

## What this slice does

The UPF now marks every downlink G-PDU it sends to a gNB with the packet's QFI:

- **Live downlink** (`n6::downlink`, IPv4 and IPv6): the anchor's N6→N3 path now
  emits `gtpu::encap_dl_qfi(teid, qfi, rqi=false, pkt)`.
- **Buffered flush** (CM-IDLE → Service Request resume): each held packet is
  classified and stamped as it flushes, exactly like a live packet.
- **Router Advertisements** (SLAAC, design/131): the solicited and unsolicited
  RAs ride the default QoS flow, marked with `DEFAULT_QFI`.

### QFI selection

`Session::downlink_qfi(pkt)` returns:
- the QFI of the **GBR flow** whose SDF filter matches the packet
  (`flow_qers`, keyed by QFI already), else
- the session's **default QoS flow** QFI — [`pfcp::DEFAULT_QFI`] `= 1`.

The datapath calls it through two new routing methods,
`UpfState::route_downlink_marked{,_v6}`, which return `(teid, gnb_ip, qfi)` in
one session lookup (the plain `route_downlink{,_v6}` stay for the SMF tests and
other callers). `pending_flush` grew a QFI field so `take_flush` hands the
`nf-upf` loop `(teid, ip, qfi, pkt)`.

## Decisions

- **D1 — the default QFI is a stack convention, not carried over N4.** radian's
  SMF always assigns the default QoS flow QFI 1 (it hard-codes it in the NAS
  default QoS rule, `crates/nas`, and the SMF default flow, `nf-smf`), and the
  UPF is already co-designed with that SMF (design/137 §2). So `DEFAULT_QFI = 1`
  is a documented constant rather than a QER IE parsed off the wire. GBR flows
  *do* carry their QFI end-to-end (encoded in the per-flow QER id today).
  Carrying the default QFI as a proper `QER.qfi` IE — so a foreign SMF could set
  it — is **G18** (the generic N4 rule engine), not this slice. Marking the
  QFI is decoupled from that: the value is right for this stack today.
- **D2 — RQI is always false.** Reflective QoS is a documented both-sides
  non-gap (design/137 §5); radian never sets the Reflective QoS Indicator.
- **D3 — mark the buffered flush and RAs too**, matching gtp5g/open5gs ("always
  marks, incl. flushed buffers"). Keeps the gNB's DRB mapping uniform across a
  CM-IDLE resume and SLAAC.
- **D4 — the N9 chain's final hop is deferred.** In an ULCL / I-UPF chain the
  anchor marks its N9 downlink, but the intermediate UPF decapsulates (which
  strips the container) and re-encapsulates plain toward the gNB, so a *chained*
  gNB still sees no QFI. Re-marking on the I-UPF requires threading the
  direction through `n6::Uplink::Forward` (today it carries both the uplink→next
  and downlink→gNB cases). Out of scope here; the single-UPF anchor path — the
  one the datapath BDD exercises and the dominant deployment — is fully covered.
  Tracked with the chain work (design/134 follow-ups / G18).

## Why this is safe on the receive side

radian's `gtpu::parse` already walks the extension-header chain and reads the
QFI (`N3Message::GPdu { qfi, .. }`), and both consumers tolerate the container:

- radian's gNB `handle_n3` (`ran/gnb/src/lib.rs`) already destructures `qfi`.
- `gtpu::decap` skips the container and returns the inner payload, so every
  existing `decap`-based datapath test stays valid unchanged.
- The external free-ran-ue (`@sim` tier) is a conformant gNB; the DL PDU Session
  Container is mandatory in real deployments, so it expects it.

## Tests

- `crates/n6`: `downlink_marks_default_qfi` (a plain downlink → QFI 1, and the
  inner payload survives the container) and `downlink_marks_matched_gbr_flow_qfi`
  (a packet matching a GBR flow's SDF filter → that flow's QFI; a non-matching
  one → the default). Both parse the produced G-PDU back with `gtpu::parse`.
- `crates/pfcp`: the existing
  `an_release_buffers_downlink_reports_and_flushes_on_resume` now asserts each
  flushed tuple carries `DEFAULT_QFI`.
- `pfcp` 25, `n6` 20, `nf-smf` 32 green; clippy clean on `pfcp`/`n6`/`nf-upf`.

## Follow-ups

- The N9-chain final hop (D4) — mark the I-UPF's re-encap toward the gNB.
- Carry the default QFI as a `QER.qfi` IE over N4 (G18) so a foreign SMF can set
  a non-default value; today it's the `DEFAULT_QFI` convention.
