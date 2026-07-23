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

  # design/131 Phase B: the same round trip over an IPv6 PDU session — the UPF routes
  # the UE's /64 to its N6 TUN (v6 gateway 2001:db8::1) and back. The UE forms its
  # address from the accept's interface identifier + the deterministic pool prefix
  # (the RA that carries the prefix is Phase C).
  Scenario: A registered UE moves a real IPv6 packet end-to-end
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
    When the scripted UE requests an "IPV6" PDU session
    Then the AMF sets up the PDU session at the gNB
    And the UE reads an "IPV6" PDU address
    And the UE can reach the data network gateway "2001:db8::1" over the IPv6 datapath

  # The full CM-IDLE datapath arc: paging (a downlink packet to a CM-IDLE UE) AND
  # the buffer flush on resume. The UE resumes here, so it leaves no dangling
  # retained context — unlike a paging-only scenario, whose never-resumed UE would
  # share the demo SUPI with a later scenario's UE and mis-resolve paging.
  Scenario: A buffered downlink packet flushes to the UE on resume
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
    When the gNB opens its N3 tunnel
    And the gNB releases the UE context via AN release
    And a downlink packet arrives for the UE on the data network
    Then the gNB is paged for the UE in TAC "000001"
    When the scripted UE resumes with a Service Request
    Then the AMF re-establishes the context and reactivates the session
    And the buffered downlink packet arrives on the gNB's N3 tunnel

  # This UE never answers the page, so the AMF retransmits under T3513 up to its
  # max-sends. It runs last (before teardown): its unresumed context stays retained,
  # so a later same-SUPI scenario would mis-resolve paging (see the flush scenario).
  Scenario: An unanswered page is retransmitted under T3513
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
    Then the gNB is paged 3 times for the UE

  Scenario: Teardown topology
    Given the scripted core is running
    When I stop the radian core
    Then the test environment should be clean
