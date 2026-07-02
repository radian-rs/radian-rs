# End-to-End with free-ran-ue

radian-rs implements the core, not the radio. To drive it from the outside it
uses [**free-ran-ue**](https://github.com/free-ran-ue/free-ran-ue) — an
independent, Go, free5GC-based gNB **and** UE simulator. Interop against a
foreign implementation is the real test: it exercises the wire formats, not just
radian-rs's own assumptions. This chapter is the walkthrough, from NG Setup to a
forwarded `ping`.

## What interop proved

Driving free-ran-ue surfaced (and radian-rs fixed) exactly the gaps a real UE
hits that a self-test does not:

- **NG Setup** and the full NAS transport exchange interoperate out of the box —
  radian-rs's NGAP (`oxirush-ngap`) and NAS (`oxirush-nas`) are wire-compatible
  with the free5GC libraries.
- **Registration** needed [SUCI deconcealment](ch-01-03-suci-deconcealment.md) and
  the [UE-capability replay](ch-01-02-nas-security.md) in the Security Mode
  Command.
- **The PDU session** needed a post-registration Configuration Update Command and
  a real [N1 SM Accept](ch-03-00-pdu-session.md) (a UE reads its IP, DNN, S-NSSAI,
  and QoS from it).

With those in place, a free5GC-based UE registers, establishes a PDU session, and
pings the data network through radian-rs.

## Credentials must match

The simulator's UE must present the [demo subscriber](ch-00-02-building-and-running.md):
PLMN **999/70**, MSIN **0000000001** (→ `imsi-999700000000001`), key
`465b5ce8…`, OPc `cd63cb71…`, AMF `8000`, and an **SQN of 0** (radian-rs has no
AUTS/resync, so the UE must not be ahead of the network). It must advertise a
single ciphering and integrity algorithm — **NEA2** and **NIA2**.

## Why network namespaces

The UE brings up its **own** TUN (`ueTun0`) with the assigned IP, and the UPF has
**its** TUN (`n6upf0`) — both in `10.45.0.0/16`. In a single namespace the kernel
would short-circuit the two and the traffic would never traverse the RAN. So the
UE and the UPF must live in **separate network namespaces**, which is exactly the
topology free-ran-ue's namespace script sets up:

```
 ┌───────────────────────┐  veth  ┌──────────────────────┐  veth  ┌──────────────┐
 │ host: radian core     │10.0.1.1│ free-ran-ns: gNB     │10.0.2.1│ free-ue-ns   │
 │ NRF UDM AUSF SMF AMF    ├────────┤ 10.0.1.2             ├────────┤ UE 10.0.2.2  │
 │ UPF + N6 TUN 10.45.0.1  │        │                      │        │ ueTun0       │
 └───────────────────────┘        └──────────────────────┘        └──────────────┘
```

## Walkthrough

Build free-ran-ue (Go), then:

```
# 1. Namespaces (host ↔ RAN ↔ UE)
sudo bash script/namespace-script/free-ran-ue-namespace.sh up
sudo ip netns exec free-ran-ns ip link set lo up
sudo ip netns exec free-ue-ns  ip link set lo up

# 2. radian core, in the host. UPF advertises the host N3 address.
./target/debug/nf-nrf &
RADIAN_UDM_PROVISION_DEMO=1 RADIAN_UDM_DB=/tmp/udm.redb \
  RADIAN_UDM_MASTER_KEY=<64-hex> ./target/debug/nf-udm &
./target/debug/nf-ausf &
sudo env RADIAN_UPF_N3_ADDR=10.0.1.1 ./target/debug/nf-upf &
RADIAN_SMF_UPF_N4=127.0.0.1:8805 RADIAN_SMF_NRF=http://127.0.0.1:8000 \
  ./target/debug/nf-smf &
./target/debug/nf-amf &

# 3. gNB in the RAN namespace, UE in the UE namespace
sudo ip netns exec free-ran-ns build/free-ran-ue gnb -c config/gnb.yaml &
sudo ip netns exec free-ue-ns  build/free-ran-ue ue  -c ue.yaml &

# 4. Once the UE brings up ueTun0, route the DN subnet out of it and ping
sudo ip netns exec free-ue-ns ip route add 10.45.0.0/16 dev ueTun0
sudo ip netns exec free-ue-ns ping -c 3 -I 10.45.0.2 10.45.0.1
```

The ping to `10.45.0.1` — the UPF's N6 gateway — travels UE → gNB → N3 → UPF →
N6 → the host kernel and all the way back:

```
64 bytes from 10.45.0.1: icmp_seq=1 ttl=64 time=0.415 ms
64 bytes from 10.45.0.1: icmp_seq=2 ttl=64 time=0.624 ms
64 bytes from 10.45.0.1: icmp_seq=3 ttl=64 time=0.413 ms
3 packets transmitted, 3 received, 0% packet loss
```

## Don't do this by hand every time

This whole walkthrough — namespaces, the core, the simulator, the ping, and
teardown — is automated as a BDD scenario. See [BDD Tests](ch-04-01-bdd-tests.md).
