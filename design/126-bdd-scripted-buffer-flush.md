# BDD Scripted Buffer Flush on Resume (CM-IDLE datapath arc complete)

> Built 2026-07-09 on branch `feat/bdd-scripted-flush`. Ninth BDD slice of the design/116
> plan, and the completion of the CM-IDLE datapath arc (design/65): a downlink packet
> buffered while a UE is CM-IDLE is **flushed to the UE's N3 tunnel when it resumes**, driven
> and asserted end-to-end from the scripted tier. Pure test code; no crate behaviour changed.

## What was built (all in `bdd`)

Extends design/125's paging trigger into the full arc:

- **`datapath::bind_gnb_n3` + `datapath::recv_downlink_gpdu`** — bind the gNB's N3 socket
  early (it must be listening when the flush arrives) and receive a downlink G-PDU on it,
  returning the inner IP packet when its TEID matches.
- **Steps**: "the gNB opens its N3 tunnel" (bind + hold the socket in the World) and "the
  buffered downlink packet arrives on the gNB's N3 tunnel" (receive the flushed G-PDU and
  assert the inner IP packet is addressed to the UE and carries the injected marker payload).
- **Scenario** "A buffered downlink packet flushes to the UE on resume" in
  `scripted_datapath.feature`: register → PDU session → open the N3 tunnel → AN release →
  inject a downlink packet → the gNB is paged → the UE resumes with a Service Request → the
  buffered packet flushes to the gNB's N3 tunnel.

The flush is a real side effect of the resume: the AMF's `on_initial_context_setup_response`
installs the reactivated session's downlink via `UpdateSMContext` → the UPF installs the gNB
F-TEID and flushes its buffered packet as a G-PDU (design/65).

## The paging-only scenario was folded in

The standalone paging-only scenario from design/125 was **removed** and its coverage folded
into this fuller one. Reason: a paging-only scenario leaves its UE **retained but never
resumed**; since every scripted UE reuses the demo SUPI, a later scenario's `page_ue` (which
resolves SUPI → retained 5G-TMSI) would find the *stale* UE first and page the wrong TMSI.
This scenario resumes the UE, so it leaves no dangling retained context. (This is a test
hygiene constraint, not a core bug — a real deployment never has two CM-IDLE UEs sharing one
SUPI, and the stale one would be evicted by implicit deregistration.)

## Verification

- **`cargo test -p bdd` — 3 features / 17 scenarios / 175 steps GREEN** (deterministic across
  three runs, including the timing-sensitive flush): the new scenario drives the full CM-IDLE
  datapath arc against the live core; the rest of the suite is unaffected.
- `cargo clippy -p bdd --tests` — no net-new warnings (1 site before == after; the new
  receive helper's nested `if` was collapsed to keep parity).
- No workspace crate changed.

## Significance

The CM-IDLE arc is now proven **end to end including the user plane**: AN release → buffer →
paging → resume → **the buffered packet actually reaches the UE**. Combined with the datapath
echo (design/124), the scripted tier now covers every user-plane path the core implements,
CI-runnable, with no external simulator.

## Next

The remaining design/116 fronts are **T3513** paging retransmission (design/74 — shrink
`RADIAN_AMF_T3513_SECS`, count the repeated pagings), **per-flow QoS / GBR** traffic policing
over the datapath (designs 49/51 — drive rate-limited/classified traffic), and the
**handover / lifecycle** features.
