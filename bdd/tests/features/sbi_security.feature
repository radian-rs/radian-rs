@serial
@sbi_security
Feature: SBI OAuth2 security — the secured mesh end-to-end
  As a radian-rs developer
  I want the full register + PDU-session flow to work with SBI security ON
  So that OAuth2 enforcement (design/149), consumer token attachment (design/150), and
  per-scope authorization (design/154) are proven together across real NF processes,
  in both signing modes — not just in unit tests.

  This is the cross-process test of the secured mesh. Every NF is spawned with the same
  SBI security config, so the NRF issues access tokens at /oauth2/token, each producer's
  router rejects a call without a valid audience+scope token (oauth::protect), and each
  consumer attaches an NRF-issued token to its outbound calls. A registration plus
  PDU-session establishment exercises every protected edge — AMF→AUSF, AMF→UDM, AMF→NSSF,
  AMF→SMF, AMF→PCF(AM), SMF→PCF(SM), SMF→CHF, SMF→UDM, AUSF→UDM, UDM→UDR — so reaching an
  assigned IP proves the whole token flow end-to-end.

  The outline runs it in both modes: `shared` (HS256, one secret held by every NF) and
  `asymmetric` (ES256; the NRF signs with a private key and publishes its public key at
  /oauth2/jwks, which resource servers fetch and verify — no shared secret). Each mode is
  an independent scenario that cleans the environment first.

  Scenario Outline: A UE registers and establishes a PDU session with <mode> SBI security
    Given a clean test environment
    When I start the radian core with SBI security "<mode>"
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

    Examples:
      | mode       |
      | shared     |
      | asymmetric |

  Scenario: Teardown topology
    Given the scripted core is running
    When I stop the radian core
    Then the test environment should be clean
