@serial
@gnb
Feature: Standalone radian-gnb — a real network element between the UE and the core
  As a radian-rs developer
  I want the standalone `radian-gnb` binary (design/128 Phase 0) to terminate N2, N3,
  and a fake Uu, relaying a scripted UE's NAS to the live core
  So that the gNB is proven as its own process — not fused into the test — running the
  same registration, datapath, and paging flows as the scripted tier.

  The whole radian core runs as host processes (loopback SBI; the AMF's N2 SCTP on
  :38412; the UPF on the 127.0.0.2 alias). The `radian-gnb` binary connects to the AMF,
  completes NG Setup, and listens on its Uu (127.0.0.1:4997) and N3 (127.0.0.1:2152).
  A scripted UE — holding the demo subscriber's USIM key — camps on the Uu and drives
  5G-AKA end to end; every NAS message crosses a real gNB process both ways.

  Scenario: A UE registers via 5G-AKA through the standalone gNB
    Given a clean test environment
    When I start the radian core
    And the standalone gNB connects and completes NG Setup
    And a UE camps on the gNB and registers from TAC "000001"
    Then the gNB relays the AMF's 5G-AKA challenge to the UE
    When the UE answers the challenge through the gNB
    Then the gNB relays the security mode command to the UE
    When the UE completes the security mode procedure through the gNB
    Then the gNB relays the registration accept to the UE
    When the UE completes the registration through the gNB
    Then the gNB relays a configuration update to the UE
    And the "amf" log should contain "REGISTERED"

  Scenario: A registered UE moves a real packet through the gNB datapath
    Given the scripted core is running
    And the standalone gNB is running
    When a UE camps on the gNB and registers from TAC "000001"
    Then the gNB relays the AMF's 5G-AKA challenge to the UE
    When the UE answers the challenge through the gNB
    Then the gNB relays the security mode command to the UE
    When the UE completes the security mode procedure through the gNB
    Then the gNB relays the registration accept to the UE
    When the UE completes the registration through the gNB
    Then the gNB relays a configuration update to the UE
    When the UE requests a PDU session through the gNB
    Then the UE is assigned an IP address in "10.45.0.0/16" through the gNB
    And the UE can reach the data network gateway "10.45.0.1" through the gNB datapath

  # Runs last (before teardown): the UE goes idle and is paged but never resumes, so
  # its retained context would mis-resolve a later same-SUPI page (see scripted_datapath).
  Scenario: An idle UE is paged through the gNB when downlink data arrives
    Given the scripted core is running
    And the standalone gNB is running
    When a UE camps on the gNB and registers from TAC "000001"
    Then the gNB relays the AMF's 5G-AKA challenge to the UE
    When the UE answers the challenge through the gNB
    Then the gNB relays the security mode command to the UE
    When the UE completes the security mode procedure through the gNB
    Then the gNB relays the registration accept to the UE
    When the UE completes the registration through the gNB
    Then the gNB relays a configuration update to the UE
    When the UE requests a PDU session through the gNB
    Then the UE is assigned an IP address in "10.45.0.0/16" through the gNB
    When the UE goes idle and the gNB releases it
    And a downlink packet arrives for the UE on the data network
    Then the gNB pages the UE

  Scenario: Teardown topology
    Given the scripted core is running
    When I stop the standalone gNB and the radian core
    Then the test environment should be clean
