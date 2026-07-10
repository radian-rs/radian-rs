@serial
@scripted_datapath
Feature: Scripted gNB/UE — user-plane datapath through the signalled stack
  As a radian-rs developer
  I want a scripted UE/gNB to register, establish a PDU session, and move a real packet
  So that the whole control + user plane is proven end-to-end with no external simulator.

  Unlike the `datapath_e2e` (@sim) feature, this needs no free-ran-ue and no namespaces:
  the whole core runs on the host, the UPF binds a distinct loopback alias (127.0.0.2) for
  its N3/N4, and the scripted gNB plays real GTP-U on 127.0.0.1:2152. The session is
  signalled the normal way (register → PDU session → the AMF installs the UPF F-TEID and
  the gNB's DL F-TEID), then the gNB tunnels an ICMP echo through it.

  Scenario: A registered UE moves a real packet end-to-end
    Given a clean test environment
    When I start the radian core
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

  Scenario: A downlink packet to a CM-IDLE UE triggers paging
    Given the scripted core is running
    When the scripted gNB connects and completes NG Setup
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
    When the gNB releases the UE context via AN release
    And a downlink packet arrives for the UE on the data network
    Then the gNB is paged for the UE in TAC "000001"

  Scenario: Teardown topology
    Given the scripted core is running
    When I stop the radian core
    Then the test environment should be clean
