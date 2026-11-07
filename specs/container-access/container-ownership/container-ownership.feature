@domain:container-access @area:container-ownership @from:azkaban/dockerownership
Feature: Acting only on the jail's own containers
  Lets operators give a coding agent the container socket, knowing it can only see and control the containers and exec sessions it created during this run, not other workloads on the host.

  Background:
    Given Given the jail was started with the filtered container socket

  @id:container-access.container-ownership.001 @rule:container.ownership.foreign-resources-refused @verified @source:dockerownership.go#authorize @test:dockerproxy_destructive_test.go#TestDockerFilter_Ownership
  Scenario Outline: Operations on containers and exec sessions the jail did not create are refused
    Given a container "external" and an exec session "external" exist on the host but were not created by this jail
    When the jailed tool requests <operation>
    Then the response is 403 with message "azkaban docker filter: <reason>"
    And the host's stderr shows "azkaban: docker filter DENIED" with the request path and reason
    And the operation is not passed to the container engine

    Examples:
      | operation                                        | reason                                           |
      | inspecting container "external"                  | container was not created by this jail           |
      | creating an exec session in container "external" | container was not created by this jail           |
      | removing container "external"                    | container was not created by this jail           |
      | starting exec session "external"                 | exec session was not created by this jail        |
      | committing container "external" to an image      | commit requires a container created by this jail |

  @id:container-access.container-ownership.002 @rule:container.ownership.references-pinned-to-created-id @verified @source:dockerownership.go#resolve @test:dockerproxy_destructive_test.go#TestDockerFilter_Ownership
  Scenario Outline: A container the jail created can be addressed by ID, name or short ID, and always means that same container
    Given the jail created container "abc123" with the name "owned"
    When the jailed tool asks to <operation> container "<reference>"
    Then the request is allowed
    And the container engine receives the operation for container "abc123"

    Examples:
      | operation | reference |
      | start     | abc123    |
      | start     | owned     |
      | stop      | abc       |

  @id:container-access.container-ownership.003 @rule:container.ownership.own-exec-sessions-usable @verified @source:dockerownership.go#authorize @test:dockerproxy_destructive_test.go#TestDockerFilter_Ownership
  Scenario Outline: Exec sessions the jail started in its own containers can be driven
    Given the jail created container "abc123"
    And the jail created exec session "exec123" in container "abc123"
    When the jailed tool asks to <operation> exec session "exec123"
    Then the request is allowed and reaches the container engine

    Examples:
      | operation |
      | start     |
      | inspect   |
      | resize    |

  @id:container-access.container-ownership.004 @rule:container.ownership.list-shows-only-own @verified @source:dockerownership.go#filterList @test:dockerownership_test.go#TestDockerOwnershipListIsFiltered
  Scenario: Listing containers shows only the containers this jail created
    Given the jail created container "owned"
    And container "external" also runs on the host
    When the jailed tool lists containers
    Then the list contains "owned"
    And the list does not contain "external"

  @id:container-access.container-ownership.005 @rule:container.ownership.unmodelled-operations-refused @inferred @source:dockerownership.go#authorize
  Scenario Outline: Container and exec operations the filter does not know are refused, even on the jail's own resources
    Given the jail created container "abc123" and exec session "exec123"
    When the jailed tool requests <request>
    Then the response is 403 with message "azkaban docker filter: <reason>"
    And the operation is not passed to the container engine

    Examples:
      | request                                 | reason                         |
      | POST /containers/abc123/update          | unmodelled container operation |
      | POST /containers/abc123/checkpoints/cp1 | unmodelled container endpoint  |
      | POST /exec/exec123/kill                 | unmodelled exec operation      |

  @id:container-access.container-ownership.006 @rule:container.ownership.scoped-to-one-run @inferred @source:dockerproxy.go#startDockerFilterProxy
  Scenario: Containers created in an earlier jail run are not the new run's own
    Given an earlier jail run created container "abc123"
    And that run has exited and a new jail run has started
    When the jailed tool asks to stop container "abc123"
    Then the response is 403 with message "azkaban docker filter: container was not created by this jail"
