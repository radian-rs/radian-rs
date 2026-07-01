@serial
@sim
@datapath_e2e
Feature: End-to-end datapath with the free-ran-ue simulator
  As a radiant-rs developer
  I want a real UE/gNB to register, establish a PDU session, and forward a packet
  So that the whole control + user plane is exercised against the greenfield core.

  Requires the free-ran-ue simulator binary via FREE_RAN_UE_BIN (the scenario is skipped
  otherwise). Topology (matching the simulator's namespace layout):
  ```
   ┌───────────────────────┐  veth  ┌──────────────────────┐  veth  ┌──────────────┐
   │ host: radiant core     │10.0.1.1│ ns <tag>_ran: gNB    │10.0.2.1│ ns <tag>_ue  │
   │ NRF UDM AUSF SMF AMF    ├────────┤ 10.0.1.2             ├────────┤ UE 10.0.2.2  │
   │ UPF + N6 TUN 10.45.0.1  │        │                      │        │ ueTun0       │
   └───────────────────────┘        └──────────────────────┘        └──────────────┘
  ```

  The UE (credentials match the radiant UDM demo subscriber) registers via 5G-AKA,
  establishes a PDU session (getting an IP on ueTun0), then pings the UPF's N6 gateway —
  a full trip UE → gNB → N3 → UPF → N6 → kernel → back.

  Scenario: A UE registers, establishes a PDU session, and pings the data network
    Given a clean test environment
    And the free-ran-ue simulator is available
    When I set up the RAN and UE namespaces
    And I start the radiant core
    And I start the gNB in the RAN namespace
    And I start the UE in the UE namespace
    Then the UE can ping the data network gateway "10.45.0.1"

  Scenario: Teardown topology
    Given the e2e topology exists
    When I stop the simulator and core
    And I delete the RAN and UE namespaces
    Then the test environment should be clean
