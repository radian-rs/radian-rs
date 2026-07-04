# PFCP Uplink F-TEID CHOOSE Flag (UPF-Assigned N3)

> Built 2026-07-04 on branch `feat/pfcp-fteid-choose`. The interop audit
> (`gap.txt`) Gap 2: radian-rs's SMF sent a **zero-address placeholder** uplink PDI
> F-TEID (`Fteid::ipv4(0, smf_ip)`, CH=0) yet expected the UPF to allocate the N3
> F-TEID and report it in the Created PDR. CH=0 is the *SMF-assigned* semantics (TS
> 29.244 §8.2.3), so a strict UPF would not allocate — the ask was non-standard.
> This sets the **CHOOSE (CH)** flag, the standard "UPF-assigned F-TEID" signal.

## What was built (`crates/pfcp`)

- `upf_chooses_fteid()` — a helper building a CHOOSE-IPv4 F-TEID
  (`FteidBuilder::new().choose_ipv4().teid(0)`): CH + V4 flags set, no SMF-assigned
  address. The UPF allocates the TEID and its N3 address and reports both in the
  Created PDR.
- Both uplink-PDI placeholders now use it: the main
  `session_establishment_request` (N3) and `session_establishment_request_indirect_
  forwarding` (the indirect-forwarding ingress F-TEID).

The **UPF is unchanged** — `handle_n4` already allocates the F-TEID and returns a
Created PDR; it now does so in response to a proper CH signal rather than a
placeholder. The SMF still reads the allocated F-TEID from the Created PDR. So the
radian SMF↔UPF handshake is unchanged in effect, now standardly signalled — and a
strict/free5GC-style UPF is now correctly told to allocate.

## Boundaries / notes

- **rs-pfcp encoding quirk:** rs-pfcp emits the 4-octet TEID field for a CHOOSE
  F-TEID (strict TS 29.244 omits it when CH=1). The **CH flag** is the signal a peer
  acts on, and rs-pfcp↔rs-pfcp (radian SMF↔UPF) is self-consistent, but a strict
  decoder should be verified to tolerate the extra 4 octets. Flag for the MUP-C.
- The **UPF still allocates regardless of CH** (it ignores the incoming F-TEID). Full
  standards symmetry — the UPF honouring CH=0 to accept an *SMF-assigned* F-TEID (so
  radian's UPF interops with a free5GC-style SMF) — is a separate follow-up, not
  needed for the MUP-C (which is a UPF).
- Addresses audit Gap 2. Gap 3's End Marker remains open.

## Verification

- `cargo test --workspace --exclude bdd` — green (**187** tests). New:
  - pfcp `uplink_fteid_requests_upf_allocation` — the uplink PDR's PDI F-TEID has
    CH + V4 set and no address; end to end, the UPF still allocates a non-zero TEID
    and reports its chosen N3 address in the Created PDR, and the SMF reads it back.
- `cargo clippy --workspace --exclude bdd` — clean.
- **BDD 2 features / 5 scenarios / 25 steps green** — the full `@sim` e2e ran: a
  live PDU session establishment (SMF sends the CHOOSE F-TEID → UPF allocates →
  SMF installs the datapath) and **the UE pings the data network**. End-to-end
  proof the CHOOSE handshake is correct through radian's real SMF↔UPF.

## Known limitations / next steps

- **UPF honours CH** — allocate on CH=1, accept the SMF-assigned F-TEID on CH=0
  (full standards symmetry; lets radian's UPF interop with a self-allocating SMF).
- **Gap 3 (End Marker)** — GTP-U End Marker on a downlink path switch.
- A strict TS 29.244 CHOOSE encoding (no TEID octets) would need an rs-pfcp fix or
  a hand-marshalled F-TEID.
