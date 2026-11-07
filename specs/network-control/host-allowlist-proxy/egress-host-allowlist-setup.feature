@domain:network-control @area:host-allowlist-proxy @from:azkaban/azkaban
Feature: Restricting outbound traffic to approved hosts
  Lets an operator limit a jailed tool to approved hostnames, and refuses combinations where that limit would not be enforced.

  Background:
    Given the operator's config names api.example.com with a net line

  @id:network-control.host-allowlist-proxy.001 @rule:azkaban.egress.host-allowlist-needs-enforcement @inferred @source:main.go#outer
  Scenario Outline: A host allowlist is refused when it could not be enforced or contradicts no networking
    Given the operator passes <flag>
    When the operator runs a command in the jail
    Then the command does not run
    And azkaban prints a message containing "<message>"
    And azkaban exits with status 2

    Examples:
      | flag          | message                                             |
      | --no-landlock | net host filtering needs the landlock stage         |
      | --no-net      | --no-net and a net host allowlist are contradictory |

  @id:network-control.host-allowlist-proxy.002 @rule:azkaban.egress.only-proxy-port-reachable @inferred @source:main.go#outer
  Scenario: With a host allowlist, the egress proxy port replaces any port allowlist
    Given the operator also passes --net-ports 443,80
    When the operator runs a command in the jail
    Then the tool sees HTTP_PROXY and HTTPS_PROXY pointing at the proxy on 127.0.0.1
    And the tool sees NO_PROXY set to localhost,127.0.0.1
    And a direct TCP connection to port 443 is refused
    And the proxy port is the only TCP port the tool can connect to
