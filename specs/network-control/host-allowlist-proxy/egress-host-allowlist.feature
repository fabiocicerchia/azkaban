@domain:network-control @area:host-allowlist-proxy @from:azkaban/egressproxy
Feature: Restricting outbound traffic to approved hosts
  Lets an operator confine a jailed AI tool's outbound connections to a named set of hostnames, so a token it can read cannot be sent anywhere else and the cloud metadata service and LAN stay out of reach.

  Background:
    Given the operator started the jail with an egress allowlist of "api.example.com" and "*.githubusercontent.example"
    And the jailed tool reaches the network only through the azkaban egress proxy

  @id:network-control.host-allowlist-proxy.003 @rule:network.egress-proxy.only-allowlisted-hosts @verified @source:egressproxy.go#hostAllowed @test:egressproxy_test.go#TestHostAllowlistMatchesExactlyAndByWildcard @test:egressproxy_test.go#TestWildcardDoesNotCoverTheBareDomain @test:egressproxy_test.go#TestEgressProxyEndToEnd
  Scenario Outline: Only hosts on the allowlist can be reached
    Given the jailed tool presents the per-run proxy token
    When the jailed tool opens an HTTPS tunnel to <host>
    Then the host is <decision> by the allowlist
    And a refused host gets 403 with "host is not on the egress allowlist"

    Examples:
      | host                                  | decision |
      | api.example.com                       | allowed  |
      | API.Example.COM                       | allowed  |
      | api.example.com.                      | allowed  |
      | raw.githubusercontent.example         | allowed  |
      | objects.raw.githubusercontent.example | allowed  |
      | githubusercontent.example             | refused  |
      | example.com                           | refused  |
      | evil-api.example.com                  | refused  |
      | api.example.com.evil.test             | refused  |

  @id:network-control.host-allowlist-proxy.004 @rule:network.egress-proxy.no-internal-destinations @verified @source:egressproxy.go#unroutable @test:egressproxy_test.go#TestUnroutableRefusesTheAddressesThatDefeatAnAllowlist @test:egressproxy_test.go#TestUnroutableAllowsOrdinaryPublicAddresses
  Scenario Outline: An allowed name that resolves to an internal address is refused
    Given "api.example.com" resolves to <address> among its addresses
    When the jailed tool opens an HTTPS tunnel to api.example.com
    Then the tunnel is refused with 403
    And the reason names the address and says it is <kind>
    And no connection is made to any of the name's addresses

    Examples:
      | address         | kind                           |
      | 169.254.169.254 | link-local                     |
      | 127.0.0.1       | loopback                       |
      | ::1             | loopback                       |
      | 10.0.0.5        | private                        |
      | 192.168.1.1     | private                        |
      | fc00::1         | private                        |
      | 0.0.0.0         | not a routable unicast address |
      | 239.1.2.3       | not a routable unicast address |

  @id:network-control.host-allowlist-proxy.005 @rule:network.egress-proxy.loopback-only @verified @source:egressproxy.go#startEgressProxy @test:egressproxy_test.go#TestEgressProxyListensOnLoopbackOnly
  Scenario: The egress proxy cannot be reached from the network
    When the operator starts a jail with a host allowlist
    Then the proxy listens only on 127.0.0.1 on a port chosen for this run
    And machines on the LAN cannot connect to it
