@domain:credential-delegation @area:credential-broker @from:azkaban/azkaban
Feature: Brokering a credential into the jail
  Lets an operator let a jailed tool use a service token without the token ever entering the jail.

  @id:credential-delegation.credential-broker.001 @rule:azkaban.credentials.broker-announced @inferred @source:main.go#outer
  Scenario Outline: A brokered credential is announced with its access mode
    Given the operator's config brokers the github credential <access>
    When the operator runs a command in the jail
    Then azkaban prints "brokering the github credential (<mode>); the token never enters the jail"
    And the tool is pointed at a broker on 127.0.0.1 instead of being given the token

    Examples:
      | access            | mode       |
      | read-only         | read-only  |
      | with write access | read-write |

  @id:credential-delegation.credential-broker.002 @rule:azkaban.credentials.broker-reachable-under-port-limits @inferred @source:main.go#outer
  Scenario: The credential broker stays reachable when outbound ports are restricted
    Given the operator's config brokers the github credential
    And the operator passes --net-ports 443
    When the jailed tool connects to the broker on 127.0.0.1
    Then the connection is allowed
    And a connection to port 8080 is still refused

  @id:credential-delegation.credential-broker.003 @rule:azkaban.credentials.malformed-directive-refused @inferred @source:main.go#outer
  Scenario: A malformed credential line in the config is refused
    Given the operator's config has a credential line azkaban cannot parse
    When the operator runs a command in the jail
    Then the command does not run
    And azkaban prints a message starting "credential:"
    And azkaban exits with status 2
