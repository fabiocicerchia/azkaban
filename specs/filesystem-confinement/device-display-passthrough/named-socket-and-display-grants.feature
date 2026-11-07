@domain:filesystem-confinement @area:device-display-passthrough @from:azkaban/azkaban
Feature: Granting named sockets and the display
  Lets an operator give a jailed tool one local service or the display without handing over the whole runtime directory.

  @id:filesystem-confinement.device-display-passthrough.001 @rule:azkaban.sockets.missing-socket-grant-refused @inferred @source:main.go#outer
  Scenario Outline: A socket grant that names nothing usable is refused
    Given <path> <state>
    When the operator runs the jail with <flag> <path>
    Then the command does not run
    And azkaban prints "<message>"
    And azkaban exits with status 1

    Examples:
      | flag              | path               | state                      | message                                            |
      | --unix-socket     | /tmp/.s.PGSQL.5432 | does not exist             | --unix-socket: no socket at /tmp/.s.PGSQL.5432     |
      | --unix-socket-dir | /tmp/tool.sock     | is a file, not a directory | --unix-socket-dir: not a directory: /tmp/tool.sock |

  @id:filesystem-confinement.device-display-passthrough.002 @rule:azkaban.display.only-display-sockets-shared @verified @source:main.go#outer @test:sandbox_test.go#TestDisplay_BindsNamedSocketsNotTheWholeRuntimeDir
  Scenario: Sharing the display exposes only display sockets, not the agent, dbus or container sockets
    Given the runtime directory /run/user/1000 holds wayland-0, the dbus bus, a Docker socket and an SSH agent socket
    When the operator runs the jail with --display
    Then the jail sees /run/user/1000 as otherwise empty
    And only the matching display sockets such as wayland-0 are bound into it
    And the dbus bus, Docker socket, gpg agent and SSH agent socket are not present
