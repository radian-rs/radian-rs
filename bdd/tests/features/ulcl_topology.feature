@serial
@ulcl_topology
Feature: UP topology config — a chained session driven by a JSON topology file
  As a radian-rs developer
  I want the SMF to load a JSON UP-topology config and route a session through it
  So that the operator-facing config file (design/134 Phase 3b) is proven to load and
  carry real traffic, not just unit-tested at the SMF boundary.

  Same two-UPF chain and datapath as @ulcl_chain, but the SMF is wired from a JSON
  `upNodes`/`links` config (RADIAN_SMF_TOPOLOGY) instead of the RADIAN_SMF_IUPF_N4 env var:
  the topology names the anchor (127.0.0.2, serving DNN "internet"), the intermediate
  (127.0.0.3), and the gNB → iupf → anchor links. The SMF selects the path per DNN, hands
  the gNB the I-UPF's F-TEID, and the same scripted echo traverses the whole chain.

  Scenario: A registered UE moves a packet through a config-driven chain
    Given a clean test environment
    When I start the radian core from a UP topology config
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
