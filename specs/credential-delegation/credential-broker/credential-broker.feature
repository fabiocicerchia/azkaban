@domain:credential-delegation @area:credential-broker @from:azkaban/credentialbroker
Feature: Brokering a GitHub credential into the jail
  Lets an operator give a jailed agent git access to GitHub under a read-only-by-default route policy while the real token stays on the host and never enters the jail.

  @id:credential-delegation.credential-broker.004 @rule:credential.broker.push-allowed-with-write @verified @source:credentialbroker.go#startCredentialBroker @test:credentialbroker_test.go#TestBrokerAllowsPushWhenAskedFor
  Scenario: Push goes through when the operator opts into write access
    Given the operator's config file has the line "credential github write"
    And the host session has GH_TOKEN set to a GitHub token
    When the jailed tool runs a git push through the broker
    Then the push is forwarded to github.com with the real credential attached
    And the terminal shows "azkaban: brokering the github credential (read-write); the token never enters the jail" at start

  @id:credential-delegation.credential-broker.005 @rule:credential.broker.refuses-to-start-misconfigured @verified @source:credentialbroker.go#startCredentialBroker @test:credentialbroker_test.go#TestBrokerRefusesToStartWithNoCredentialOnTheHost @test:credentialbroker_test.go#TestBrokerRejectsAnUnknownProvider @test:credentialbroker_test.go#TestCredentialDirectiveParsing
  Scenario Outline: A credential that cannot be brokered stops the run before the jail starts
    Given the operator passes --credential "<directive>"
    And the host session has <host token>
    When the operator starts the jail
    Then the run stops with exit status <exit> and an error containing "<message>"
    And no jail is started

    Examples:
      | directive        | host token                            | exit | message                                                             |
      | github           | neither GH_TOKEN nor GITHUB_TOKEN set | 1    | no github credential on the host: set one of GH_TOKEN, GITHUB_TOKEN |
      | gitlab           | GH_TOKEN set                          | 1    | unknown credential provider "gitlab"; known: github                 |
      | github readwrite | GH_TOKEN set                          | 2    | unknown credential option "readwrite"; only `write` is understood   |
      |                  | GH_TOKEN set                         | 2    | credential needs a provider name                                    |
