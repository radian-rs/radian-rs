@serial
@scripted_reg
Feature: Scripted gNB/UE — full 5G-AKA registration against the live core
  As a radian-rs developer
  I want the test process itself to play the gNB and the UE (design/116 Tier B)
  So that every registration message is field-asserted against the live core,
  with no external simulator binary.

  The whole radian core runs as real host processes (loopback SBI; the AMF's N2
  SCTP on :38412). The scenario speaks APER NGAP as the gNB and NAS as the UE,
  holding the demo subscriber's USIM key — the same 5G-AKA the network runs
  through NRF → AUSF → UDM → UDR, mirrored UE-side, with the derived keys
  cross-checked at every hop (NAS MACs both ways, K_gNB in the context setup).

  Scenario: A scripted UE registers via 5G-AKA and is context-established
    Given a clean test environment
    When I start the radian core
    And the scripted gNB connects and completes NG Setup
    And the scripted UE sends its registration request from TAC "000001"
    Then the AMF challenges the UE with 5G-AKA
    When the scripted UE answers the challenge with RES*
    Then the AMF selects NEA2/NIA2 in a security mode command
    When the scripted UE completes the security mode procedure
    Then the AMF sets up the initial context carrying the registration accept
    And the accept grants the subscribed slice, a GUTI, and the registration area
    When the gNB confirms the context and the UE completes the registration
    Then the AMF nudges the registered UE with a configuration update
    And the "amf" log should contain "REGISTERED"

  Scenario: Requested NSSAI is intersected with the subscription (D8)
    Given the scripted core is running
    When the scripted gNB connects and completes NG Setup
    And the scripted UE sends its registration request requesting slices "1:010203,2"
    Then the AMF challenges the UE with 5G-AKA
    When the scripted UE answers the challenge with RES*
    Then the AMF selects NEA2/NIA2 in a security mode command
    When the scripted UE completes the security mode procedure
    Then the AMF sets up the initial context carrying the registration accept
    And the accept allows slice "1:010203" and rejects slice "2"

  Scenario: A UE whose only requested slice is unsubscribed is rejected (D7)
    Given the scripted core is running
    When the scripted gNB connects and completes NG Setup
    And the scripted UE sends its registration request requesting slices "2"
    Then the AMF challenges the UE with 5G-AKA
    When the scripted UE answers the challenge with RES*
    Then the AMF selects NEA2/NIA2 in a security mode command
    When the scripted UE completes the security mode procedure
    Then the AMF rejects the registration with 5GMM cause 62 and a back-off timer

  Scenario: A UE that fails authentication is rejected and released (D6)
    Given the scripted core is running
    When the scripted gNB connects and completes NG Setup
    And the scripted UE sends its registration request from TAC "000001"
    Then the AMF challenges the UE with 5G-AKA
    When the scripted UE answers the challenge with a wrong RES*
    Then the AMF rejects authentication and releases the UE

  Scenario: A UE with a stale sequence number resynchronises via AUTS (D5)
    Given the scripted core is running
    When the scripted gNB connects and completes NG Setup
    And the scripted UE's USIM is ahead of the network
    And the scripted UE sends its registration request from TAC "000001"
    Then the AMF challenges the UE with 5G-AKA
    When the scripted UE rejects the stale challenge with an AUTS
    Then the AMF challenges the UE with 5G-AKA
    When the scripted UE answers the challenge with RES*
    Then the AMF selects NEA2/NIA2 in a security mode command

  Scenario: A registered UE establishes a PDU session (116c)
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

  Scenario: A UE goes CM-IDLE and resumes with a Service Request (116d)
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
    And the scripted UE resumes with a Service Request
    Then the AMF re-establishes the context and reactivates the session
    And the UE reads the service accept

  Scenario: A UE re-registers with its 5G-GUTI and is re-authenticated (D3)
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
    When the scripted UE re-registers with its 5G-GUTI
    Then the AMF challenges the UE with 5G-AKA
    When the scripted UE answers the challenge with RES*
    Then the AMF selects NEA2/NIA2 in a security mode command
    When the scripted UE completes the security mode procedure
    Then the AMF sets up the initial context carrying the registration accept
    And the accept grants the subscribed slice, a GUTI, and the registration area

  Scenario: An unknown 5G-GUTI triggers an Identity Request, then registration (D4)
    Given the scripted core is running
    When the scripted gNB connects and completes NG Setup
    And the scripted UE registers with an unknown 5G-GUTI
    Then the AMF requests the UE's identity
    When the scripted UE answers with its SUCI
    Then the AMF challenges the UE with 5G-AKA
    When the scripted UE answers the challenge with RES*
    Then the AMF selects NEA2/NIA2 in a security mode command
    When the scripted UE completes the security mode procedure
    Then the AMF sets up the initial context carrying the registration accept
    And the accept grants the subscribed slice, a GUTI, and the registration area

  Scenario: The registration area is the gNB's TA union the UE's TAI (D9)
    Given the scripted core is running
    When the scripted gNB connects and completes NG Setup
    And the scripted UE sends its registration request from TAC "000002"
    Then the AMF challenges the UE with 5G-AKA
    When the scripted UE answers the challenge with RES*
    Then the AMF selects NEA2/NIA2 in a security mode command
    When the scripted UE completes the security mode procedure
    Then the AMF sets up the initial context carrying the registration accept
    And the accept's registration area covers TACs "000001,000002"

  Scenario: A PDU session for an unsubscribed DNN is rejected (D10)
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
    When the scripted UE requests a PDU session for DNN "corporate"
    Then the AMF rejects the PDU session with 5GSM cause 27 and a back-off timer

  Scenario: Teardown topology
    Given the scripted core is running
    When I stop the radian core
    Then the test environment should be clean
