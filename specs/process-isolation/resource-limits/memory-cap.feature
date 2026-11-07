@domain:process-isolation @area:resource-limits @from:azkaban/cgroups
Feature: Capping a jail's memory
  Lets an operator put a hard memory bound on a run, so an agent that writes into the RAM-backed throwaway overlay in a loop cannot exhaust the host, and refuses the run rather than pretend to cap it.

  Background:
    Given the operator runs azkaban on a Linux host

  @id:process-isolation.resource-limits.001 @rule:resources.memory.cap-enforced @verified @source:cgroups.go#setupCgroup @test:sandbox_test.go#TestMemMax_CapsTheOverlay
  Scenario: A memory cap bounds what the jail can write into its throwaway overlay
    Given the host delegates a cgroup v2 memory controller to the operator's session
    When the operator runs a tool with --mem-max 32M that writes a 256 MB file under $HOME/.cache
    Then the write fails before reaching 256 MB
    And the excess is refused rather than paged out to swap

  @id:process-isolation.resource-limits.002 @rule:resources.memory.unenforceable-cap-refused @inferred @source:cgroups.go#setupCgroup
  Scenario Outline: A memory cap that cannot be enforced refuses the run instead of running uncapped
    Given <host state>
    When the operator runs a tool with --mem-max 8G
    Then the tool is not started
    And azkaban exits with status 1
    And stderr reads "azkaban: --mem-max 8G cannot be enforced: <reason>"
    And the message tells the operator to delegate a cgroup v2 memory controller or drop --mem-max

    Examples:
      | host state                                           | reason                                                                                  |
      | the process is not in a cgroup v2 hierarchy          | no cgroup v2 mount for this process                                                     |
      | the parent cgroup has no memory controller delegated | no delegated memory controller at /sys/fs/cgroup/user.slice/user-1000.slice             |
      | the jail's cgroup cannot be created                  | cannot create /sys/fs/cgroup/user.slice/user-1000.slice/azkaban-4242: permission denied |

  @id:process-isolation.resource-limits.003 @rule:resources.memory.swap-not-disabled-warns @inferred @source:cgroups.go#setupCgroup @questionable
  Scenario: When swap cannot be turned off for the jail, the operator is warned that the cap will page out rather than refuse
    Given the host delegates a cgroup v2 memory controller
    And the host does not allow swap to be disabled for the jail's cgroup
    When the operator runs a tool with --mem-max 8G
    Then the tool runs with the memory cap applied
    And stderr shows "azkaban: WARNING: could not disable swap for the cgroup; --mem-max will page out rather than refuse."
    And the run record logs a degraded event "cgroup-swap"

  @id:process-isolation.resource-limits.004 @rule:resources.memory.cap-also-limits-processes @inferred @source:cgroups.go#setupCgroup @questionable
  Scenario: A memory-capped jail is also held to a fixed process count, and a process cap that cannot be set refuses the run
    Given the host delegates a cgroup v2 memory controller
    And the host refuses to set a process limit on the jail's cgroup
    When the operator runs a tool with --mem-max 8G
    Then the tool is not started
    And azkaban exits with status 1
    And stderr reads "azkaban: --pids-max cannot be enforced: could not set pids.max: <error>"

  @id:process-isolation.resource-limits.005 @rule:resources.memory.uncapped-by-default @inferred @source:cgroups.go#cgroupUnavailable @questionable
  Scenario: Without a memory cap the jail runs with no memory bound and no cgroup warning
    Given the host has no usable cgroup v2 memory controller
    When the operator runs a tool without --mem-max
    Then the tool runs
    And no cgroup is created for the jail
    And no warning that memory is not capped is printed
