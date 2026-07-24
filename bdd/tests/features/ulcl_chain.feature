@serial
@ulcl_chain
Feature: ULCL / N9 — a PDU session chained through an intermediate UPF
  As a radian-rs developer
  I want a scripted UE's packet to traverse two UPFs over N9
  So that the SMF's multi-UPF chaining (design/134 Phases 1a/1b) is proven end-to-end
  with real nf-upf processes, not just the in-process control-plane unit tests.

  Like @scripted_datapath this needs no free-ran-ue and no namespaces: the whole core runs
  on the host loopback. A second nf-upf binds 127.0.0.3 as the intermediate UPF (I-UPF),
  which relays N3↔N9 only and has no N6 TUN; the SMF chains every session
  gNB → I-UPF (127.0.0.3) → N9 → anchor (127.0.0.2) → N6. Because the SMF hands the gNB the
  I-UPF's N3 F-TEID, the same scripted signalling and datapath echo drive the whole chain
  and the reply returns through it.

  Scenario: A registered UE moves a real packet through the I-UPF and back
    Given a clean test environment
    When I start the radian core with an intermediate UPF
    And the scripted gNB connects and completes NG Setup
    And the scripted UE sends its registration request from TAC "000001"
    Then the AMF challenges the UE with 5G-AKA
    When the scripted UE answers the challenge with RES*
    Then the AMF selects NEA2/NIA2 in a security mode command
    When the scripted UE completes the security mode procedure
    Then the AMF sets up the initial context carrying the registration accept
    When the gNB confirms the context and the UE completes the registration
    Then the AMF nudges the registered UE with a configuration update
    When the scripted UE requests a PDU session
    Then the AMF sets up the PDU session at the gNB
    And the UE is assigned an IP address in "10.45.0.0/16"
    And the UE can reach the data network gateway "10.45.0.1" over the datapath

  Scenario: Teardown topology
    Given the scripted core is running
    When I stop the radian core
    Then the test environment should be clean
