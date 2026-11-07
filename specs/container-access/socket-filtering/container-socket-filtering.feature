@domain:container-access @area:socket-filtering @from:azkaban/dockerproxy
Feature: Filtering container requests from the jail
  Lets operators give a jailed agent a working docker/podman CLI while refusing any request that would reach host files, gain host privilege, or destroy data that has no other copy.

  Background:
    Given Given a jail started for the project directory /home/dev/acme-app
    And And the container socket is shared into the jail through the filter

  @id:container-access.socket-filtering.005 @rule:container-access.socket-filtering.unmodelled-api-areas-refused @verified @source:dockerproxy.go#dockerFilterHandler @test:dockerproxy_destructive_test.go#TestDockerFilter_UnmodelledEndpointsAreRefused @test:dockerproxy_destructive_test.go#TestDockerFilter_LibpodAPIIsRefused @test:dockerproxy_destructive_test.go#TestDockerFilter_Ownership
  Scenario Outline: API areas outside everyday container, image and build work are refused
    When the jailed tool sends <request>
    Then the tool receives a 403 with the message "azkaban docker filter: the /<area> API is not reachable from inside the jail"
    And the container daemon never receives the request

    Examples:
      | request                               | area     |
      | POST /v1.45/swarm/init                | swarm    |
      | POST /v1.45/services/create           | services |
      | POST /v1.45/plugins/pull              | plugins  |
      | POST /v1.45/configs/create            | configs  |
      | GET /v1.45/nodes                      | nodes    |
      | POST /v4.0.0/libpod/containers/create | libpod   |
      | POST /v1.45/networks/create           | networks |

  @id:container-access.socket-filtering.006 @rule:container-access.socket-filtering.everyday-work-passes @verified @source:dockerproxy.go#dockerFilterHandler @test:dockerproxy_destructive_test.go#TestDockerFilter_EverydayEndpointsStillWork @test:dockerproxy_destructive_test.go#TestDockerFilter_OrdinaryCleanupStillWorks @test:dockerproxy_integration_test.go#TestDockerProxyIntegration
  Scenario Outline: Everyday container, image and build requests reach the daemon
    When the jailed tool sends <request>
    Then the request is forwarded to the container daemon
    And the tool receives the daemon's own answer
    And the run record lists the call as allowed with its method and path
    And nothing about the call is printed on the operator's terminal

    Examples:
      | request                                                     |
      | GET /_ping                                                  |
      | GET /v1.45/version                                          |
      | POST /v1.45/images/create?fromImage=alpine                  |
      | POST /v1.45/build                                           |
      | DELETE /v1.45/images/ubuntu:22.04?force=1                   |
      | POST /v1.45/containers/create with no host access requested |

  @id:container-access.socket-filtering.007 @rule:container-access.socket-filtering.unrecoverable-deletion-refused @verified @source:dockerproxy.go#destructiveReason @test:dockerproxy_destructive_test.go#TestDockerFilter_DestructiveCallsAreRefused
  Scenario Outline: Deleting a volume or pruning in bulk is refused
    When the jailed tool sends <request>
    Then the tool receives a 403 with the message "azkaban docker filter: <message>"
    And the container daemon never receives the request

    Examples:
      | request                             | message                                                                                                                        |
      | DELETE /v1.45/volumes/postgres-data | deleting volumes is not allowed from inside the jail: a named volume has no other copy. Remove it from outside if you mean to. |
      | POST /v1.45/volumes/prune           | bulk deletion (/v1.45/volumes/prune) is not allowed from inside the jail                                                       |
      | POST /v1.45/containers/prune        | bulk deletion (/v1.45/containers/prune) is not allowed from inside the jail                                                    |
      | POST /v1.45/images/prune            | bulk deletion (/v1.45/images/prune) is not allowed from inside the jail                                                        |
      | POST /v1.45/networks/prune          | bulk deletion (/v1.45/networks/prune) is not allowed from inside the jail                                                      |
      | POST /v1.45/build/prune             | bulk deletion (/v1.45/build/prune) is not allowed from inside the jail                                                         |

  @id:container-access.socket-filtering.008 @rule:container-access.socket-filtering.host-mounts-confined-to-project @verified @source:dockerproxy.go#containerReason @test:main_test.go#TestFilterReasonContainer @test:main_test.go#TestFilterReasonVolumeAndSymlink @test:dockerproxy_destructive_test.go#TestDockerFilter_DenialIsAWellFormedDockerError @test:dockerproxy_integration_test.go#TestDockerProxyIntegration
  Scenario Outline: A container may mount host paths only from inside the project directory
    When the jailed tool creates a container with <mount>
    Then <outcome>

    Examples:
      | mount                                                             | outcome                                                                                                                          |
      | -v /:/host                                                        | the tool receives a 403 with "azkaban docker filter: bind mount of host path outside the project dir: /"                         |
      | -v /etc:/etc:ro                                                   | the tool receives a 403 with "azkaban docker filter: bind mount of host path outside the project dir: /etc"                      |
      | --mount type=bind,source=/root                                    | the tool receives a 403 with "azkaban docker filter: bind mount of host path outside the project dir: /root"                     |
      | -v /home/dev/acme-app/escape:/x where escape is a symlink to /etc | the tool receives a 403 with "azkaban docker filter: bind mount of host path outside the project dir: /home/dev/acme-app/escape" |
      | -v /home/dev/acme-app/src:/app                                    | the container is created                                                                                                         |
      | --mount type=bind,source=/home/dev/acme-app                       | the container is created                                                                                                         |
      | an anonymous volume -v /data                                      | the container is created                                                                                                         |

  @id:container-access.socket-filtering.009 @rule:container-access.socket-filtering.no-named-volumes @verified @source:dockerproxy.go#containerReason @test:main_test.go#TestFilterReasonContainer @test:dockerproxy_destructive_test.go#TestDockerFilter_Ownership @questionable
  Scenario Outline: Named volumes cannot be created or used from inside the jail
    When the jailed tool sends <request>
    Then the tool receives a 403 with the message "azkaban docker filter: <message>"
    And the container daemon never receives the request

    Examples:
      | request                                                                                   | message                                                                           |
      | a container create with -v pgdata:/var/lib/postgresql/data                                | named volumes are not allowed inside the jail                                     |
      | a container create with --mount type=volume,source=pgdata                                 | named volumes and volume driver options are not allowed; use a project bind mount |
      | a container create with --mount type=volume and volume-opt device=/etc                    | named volumes and volume driver options are not allowed; use a project bind mount |
      | a container create with --mount type=volume and volume-opt device=/home/dev/acme-app/data | named volumes and volume driver options are not allowed; use a project bind mount |
      | POST /v1.45/volumes/create named pgdata                                                   | the /volumes API is not reachable from inside the jail                            |

  @id:container-access.socket-filtering.010 @rule:container-access.socket-filtering.no-host-privilege @verified @source:dockerproxy.go#hostConfigReason @test:main_test.go#TestFilterReasonContainer @test:dockerproxy_destructive_test.go#TestDockerFilter_Ownership
  Scenario Outline: A container or exec cannot be given host privilege or host namespaces
    When the jailed tool sends a <request> with <option>
    Then <outcome>

    Examples:
      | request                  | option                              | outcome                                                                                           |
      | container create         | --privileged                        | refused with "azkaban docker filter: --privileged is not allowed inside the jail"                 |
      | container create         | --device /dev/sda                   | refused with "azkaban docker filter: host device passthrough (--device) is not allowed"           |
      | container create         | --cap-add SYS_ADMIN                 | refused with "azkaban docker filter: --cap-add SYS_ADMIN is not allowed"                          |
      | container create         | --cap-add CAP_DAC_READ_SEARCH       | refused with "azkaban docker filter: --cap-add CAP_DAC_READ_SEARCH is not allowed"                |
      | container create         | --security-opt seccomp=unconfined   | refused with "azkaban docker filter: --security-opt seccomp=unconfined is not allowed"            |
      | container create         | --security-opt label=disable        | refused with "azkaban docker filter: --security-opt label=disable is not allowed"                 |
      | container create         | --pid=host                          | refused with "azkaban docker filter: --pid=host is not allowed"                                   |
      | container create         | --network=host                      | refused with "azkaban docker filter: --network=host is not allowed"                               |
      | container create         | --network=container:abc             | refused with "azkaban docker filter: --network=container:abc is not allowed"                      |
      | container create         | --network=prod_default              | refused with "azkaban docker filter: --network=prod_default is not allowed inside the jail"       |
      | container create         | an endpoint on network prod_default | refused with "azkaban docker filter: joining network prod_default is not allowed inside the jail" |
      | container create         | --volumes-from existing             | refused with "azkaban docker filter: --volumes-from is not allowed inside the jail"               |
      | container create         | --link existing:alias               | refused with "azkaban docker filter: --link is not allowed inside the jail"                       |
      | exec on an own container | --privileged                        | refused with "azkaban docker filter: docker exec --privileged is not allowed inside the jail"     |
      | container create         | --cap-add NET_ADMIN                 | the container is created                                                                          |
      | container create         | --network=bridge                    | the container is created                                                                          |
      | container create         | --security-opt no-new-privileges    | the container is created                                                                          |

  @id:container-access.socket-filtering.011 @rule:container-access.socket-filtering.unreadable-create-refused @verified @source:dockerproxy.go#dockerFilterHandler @test:main_test.go#TestFilterReasonContainer @test:dockerproxy_destructive_test.go#TestDockerFilter_CreateBodyIsSizeCapped
  Scenario Outline: A create request the filter cannot read is refused
    When the jailed tool sends <request>
    Then the tool receives a 403 with the message "azkaban docker filter: <message>"
    And the container daemon never receives the request

    Examples:
      | request                                            | message                          |
      | a container create whose body is not valid JSON    | unparsable container-create body |
      | an exec create whose body is not valid JSON        | unparsable exec-create body      |
      | a container create whose body is larger than 4 MiB | could not read request body      |

  @id:container-access.socket-filtering.012 @rule:container-access.socket-filtering.denial-explained @verified @source:dockerproxy.go#denyJSON @test:dockerproxy_destructive_test.go#TestDockerFilter_DenialIsAWellFormedDockerError @test:dockerproxy_integration_test.go#TestDockerProxyIntegration
  Scenario: A refused request tells both the tool and the operator why
    When the jailed tool runs a container with -v /:/host
    Then the tool receives a 403 whose JSON body has the message "azkaban docker filter: bind mount of host path outside the project dir: /"
    And the docker CLI inside the jail prints that message
    And the operator's terminal shows "azkaban: docker filter DENIED /v1.45/containers/create: bind mount of host path outside the project dir: /"
    And the run record gains a docker entry with decision denied, the method, the path and the reason
