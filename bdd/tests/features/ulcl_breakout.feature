@serial
@ulcl_breakout
Feature: ULCL breakout — one PDU session reaches two data networks with real packets
  As a radian-rs developer
  I want a UE's uplink split across two anchors by destination, over real nf-upf processes
  So that design/134 Phase 2's uplink classifier is proven end-to-end, not just unit-tested.

  Three UPFs on the host loopback: the anchor (127.0.0.2, DN gateway 10.45.0.1), the
  classifier / I-UPF (127.0.0.3, no TUN), and the breakout anchor (127.0.0.4, its own DN
  gateway 10.99.0.1 on n6upf1). The SMF loads a topology config whose route steers
  10.99.0.0/16 to the breakout anchor; everything else takes the default anchor. One PDU
  session, one UE address — traffic to 10.45.0.1 returns via the anchor and traffic to
  10.99.0.1 via the breakout anchor, each proven with an ICMP echo. (A host source route
  keeps the two anchors off each other's UE-pool return path — see the harness.)

  Scenario: A UE reaches both the default DN and the breakout DN
    Given a clean test environment
    When I start the radian core with an uplink-classifier breakout
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
    And the UE can reach the data network gateway "10.99.0.1" over the datapath

  Scenario: Teardown topology
    Given the scripted core is running
    When I stop the radian core
    Then the test environment should be clean
