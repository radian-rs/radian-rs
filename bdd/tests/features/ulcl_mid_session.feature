@serial
@ulcl_mid_session
Feature: Mid-session ULCL insertion — a breakout added to a live PDU session with real packets
  As a radian-rs developer
  I want a breakout inserted onto an already-running session to steer new traffic live
  So that design/134 Phase 3e's dynamic ULCL insertion is proven end-to-end, not just
  unit-tested — the Session Modification path Phase 2 leaves inert.

  Same three UPFs as @ulcl_breakout — the anchor (10.45.0.1), the classifier, and the
  breakout anchor (10.99.0.1 on n6upf1) — but the topology carries NO route, so the session
  is established as a plain chain. The UE reaches the default DN. Then the OAM endpoint
  inserts a breakout for 10.99.0.0/16, and the UE reaches the breakout DN that was
  unreachable a moment earlier — the classifier's branch was added mid-session. (The OAM
  call stands in for NEF/AF traffic influence; the N4 mechanism is the same.)

  Scenario: A breakout inserted mid-session steers new traffic to a second DN
    Given a clean test environment
    When I start the radian core with a deferred breakout anchor
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
    When I insert a breakout for "10.99.0.0/16" via "edge"
    Then the UE can reach the data network gateway "10.99.0.1" over the datapath

  Scenario: Teardown topology
    Given the scripted core is running
    When I stop the radian core
    Then the test environment should be clean
