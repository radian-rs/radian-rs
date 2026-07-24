@serial
@nef
Feature: NEF — AF traffic influence steers a live session's traffic to a local edge
  As a radian-rs developer
  I want an AF's traffic-influence request, through the NEF, to change the datapath live
  So that design/135 Phase 1 (NEF → SMF → ULCL) is proven end-to-end with real packets —
  the production front door for the mid-session breakout of design/134 Phase 3e.

  Same three UPFs as @ulcl_mid_session — the anchor (10.45.0.1), the classifier, and the
  breakout anchor (10.99.0.1 on n6upf1) exposing DNAI "mec" — plus a running NEF. The
  topology carries no route, so the session is a plain chain reaching the default DN. Then
  an AF posts a traffic-influence subscription to the NEF ("steer 10.99.0.0/16 to DNAI
  mec"); the NEF resolves it to the SMF's breakout trigger, and the UE reaches the edge DN
  that was unreachable a moment earlier — the NEF drove a live ULCL insertion.

  Scenario: An AF influences a live session's traffic to a breakout edge
    Given a clean test environment
    When I start the radian core with a NEF
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
    When the AF requests traffic influence for "10.99.0.0/16" to DNAI "mec"
    Then the UE can reach the data network gateway "10.99.0.1" over the datapath

  Scenario: Teardown topology
    Given the scripted core is running
    When I stop the radian core
    Then the test environment should be clean
