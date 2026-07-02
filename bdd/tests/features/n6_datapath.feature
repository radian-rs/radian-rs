@serial
@n6_datapath
Feature: N6 user-plane datapath forwards a real packet
  As a radian-rs developer
  I want the UPF to forward a real IP packet between N3 (GTP-U) and N6 (a TUN)
  So that a signaled PDU session actually moves user traffic.

  Topology (the test process plays the SMF and the gNB):
  ```
   ┌──────────────────────────┐   veth   ┌───────────────────────────────┐
   │ test process (host)      │ 10.0.1.1 │ namespace <tag>_upf            │
   │  SMF: PFCP  → N4          ├──────────┤ 10.0.1.2  nf-upf               │
   │  gNB: GTP-U ↔ N3          │          │           N4 :8805  N3 :2152   │
   └──────────────────────────┘          │           N6 TUN n6upf0        │
                                          │              10.45.0.1/16      │
                                          └───────────────────────────────┘
  ```

  The gNB GTP-U-encapsulates an ICMP echo (UE 10.45.0.2 → gateway 10.45.0.1) on the
  UPF-allocated uplink TEID. The UPF decaps it to n6upf0; the namespace kernel answers the
  ping; the UPF routes the reply back by UE IP and GTP-U-encaps it to the installed gNB
  F-TEID. Receiving the reply proves the full N3 → N6 → N3 round trip.

  Scenario: A UE packet round-trips through the N3/N6 datapath
    Given a clean test environment
    When I set up the UPF namespace
    And I start the UPF with its N6 TUN
    And I establish a PFCP session for UE "10.45.0.2"
    And the UE sends an ICMP echo to the gateway "10.45.0.1"
    Then the datapath forwards the packet round trip

  Scenario: Teardown topology
    Given the datapath topology exists
    When I stop the UPF
    And I delete the UPF namespace
    Then the test environment should be clean
