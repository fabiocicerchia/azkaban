@domain:process-isolation @area:resource-limits @from:azkaban/helpers
Feature: Capping what a runaway tool can consume
  Operators get per-process caps on file size, process count, open files and core dumps, so an agent stuck in a write or fork loop cannot exhaust host RAM through the RAM-backed overlay.

  Background:
    Given the operator runs a tool inside the jail

  @id:process-isolation.resource-limits.006 @rule:jail.resources.rlimits-capped-by-default @verified @source:helpers.go#applyRlimits @test:sandbox_test.go#TestRlimit_FileSizeIsCapped @test:sandbox_test.go#TestRlimit_OversizedWriteIsRefused
  Scenario Outline: A jailed tool runs under file-size, process, open-file and core-dump caps by default
    Given the operator has not passed --no-rlimits
    When the jailed tool checks its resource limits
    Then its <limit> limit is <limit_value>
    And the soft and hard limits are both set to that value

    Examples:
      | limit          | limit_value |
      | file size      | 4 GiB       |
      | processes      | 4096        |
      | open files     | 8192        |
      | core dump size | 0           |

  @id:process-isolation.resource-limits.007 @rule:jail.resources.rlimits-opt-out @verified @source:helpers.go#applyRlimits @test:sandbox_test.go#TestRlimit_CanBeDisabled
  Scenario: The operator can lift the resource caps with --no-rlimits
    Given the operator passes --no-rlimits
    When the jailed tool checks its file-size limit
    Then the file-size limit is whatever the operator's shell had, for example unlimited

  @id:process-isolation.resource-limits.008 @rule:jail.resources.stricter-host-limit-kept @inferred @source:helpers.go#applyRlimits @questionable
  Scenario Outline: A hard limit the operator already set lower than the jail's cap is kept
    Given the operator's shell already has a hard limit on <limit> of <host_limit>, below the jail's cap
    When the operator starts the jail
    Then the jailed tool's hard limit on <limit> is still <host_limit>

    Examples:
      | limit      | host_limit |
      | open files | 1024       |
      | processes  | 512        |

  @id:process-isolation.resource-limits.009 @rule:jail.resources.unset-cap-warns @inferred @source:helpers.go#applyRlimits @questionable
  Scenario: A cap the jail cannot set is reported and the run continues
    Given the host refuses to let azkaban set the RLIMIT_NPROC cap
    When the operator starts the jail
    Then stderr shows "azkaban: warning: could not set RLIMIT_NPROC: <reason>"
    And the jailed tool still runs, without that cap
