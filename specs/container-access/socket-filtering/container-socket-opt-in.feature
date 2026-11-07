@domain:container-access @area:socket-filtering @from:azkaban/azkaban
Feature: Opting in to a container socket
  Lets an operator give a jailed tool Docker or Podman only on request, through a filtering proxy by default, and warns loudly when that socket gives the tool more power.

  @id:container-access.socket-filtering.001 @rule:azkaban.containers.no-socket-by-default @verified @source:main.go#outer @test:sandbox_test.go#TestRuntime_NoSocketIsBoundByDefault
  Scenario: No container socket is reachable unless the operator asks for one
    Given a Docker socket exists on the host
    When the operator runs a command in the jail without --bind-docker or --bind-podman
    Then no Docker or Podman socket is bound into the jail
    And DOCKER_HOST and CONTAINER_HOST are not set

  @id:container-access.socket-filtering.002 @rule:azkaban.containers.socket-behind-filter @verified @source:main.go#outer @test:sandbox_test.go#TestRuntime_OptInBindsTheSocket
  Scenario Outline: A requested container socket is reached through the filtering proxy at the usual path
    Given a rootless <runtime> socket exists at <path>
    When the operator runs the jail with <flag>
    Then the jail sees a socket at <path> that is served by the filtering proxy
    And the tool sees <env> set to unix://<path>

    Examples:
      | runtime | path                              | flag          | env                            |
      | Docker  | /run/user/1000/docker.sock        | --bind-docker | DOCKER_HOST                    |
      | Podman  | /run/user/1000/podman/podman.sock | --bind-podman | DOCKER_HOST and CONTAINER_HOST |

  @id:container-access.socket-filtering.003 @rule:azkaban.containers.missing-runtime-refused @verified @source:main.go#outer @test:sandbox_test.go#TestRuntime_MissingSocketIsAnError
  Scenario: Asking for a container runtime that is not running is refused
    Given no podman socket exists on the host
    When the operator runs the jail with --bind-podman
    Then the command does not run
    And azkaban prints "no podman socket found" with the paths it looked in and that containerd is not offered
    And azkaban exits with status 1

  @id:container-access.socket-filtering.004 @rule:azkaban.containers.risky-socket-warned @inferred @source:main.go#outer
  Scenario Outline: A container socket that grants more power is announced with a warning
    Given <situation>
    When the operator runs the jail with <flags>
    Then azkaban prints "WARNING: <warning>"
    And the command still runs

    Examples:
      | situation                                                  | flags                                       | warning                                                                            |
      | only the rootful Docker socket /var/run/docker.sock exists | --bind-docker                               | no rootless docker; using ROOTFUL /var/run/docker.sock = host root inside the jail |
      | a rootless Docker socket exists                            | --bind-docker --unfiltered-container-socket | --unfiltered-container-socket binds the UNFILTERED socket                          |
