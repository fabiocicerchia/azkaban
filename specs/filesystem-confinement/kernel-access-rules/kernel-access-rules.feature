@domain:filesystem-confinement @area:kernel-access-rules @from:azkaban/landlock
Feature: Enforcing kernel access rules inside the jail
  Gives operators a filesystem and outbound-TCP policy the jailed tool cannot undo, so a confused agent cannot write outside the project and scratch areas even where the mount layer would allow it.

  Background:
    Given the operator runs a tool under azkaban from a project directory
    And the kernel access rules stage is on (the operator did not pass --no-landlock)

  @id:filesystem-confinement.kernel-access-rules.001 @rule:jail.landlock.writes-confined-to-writable-set @verified @source:landlock.go#landlockStage @test:sandbox_test.go#TestWrite_OnlyIntendedPathsAreWritable @test:sandbox_test.go#TestWrite_LandlockIsTighterThanMounts
  Scenario Outline: The jailed tool can write only to the project, scratch areas and a few device nodes
    Given the jail's view of /run and $HOME is mounted writable
    When the jailed tool tries to write to <target>
    Then the write to <target> is <outcome>

    Examples:
      | target                           | outcome |
      | ./probe in the project directory | allowed |
      | /tmp/probe                       | allowed |
      | /dev/null                        | allowed |
      | /run/probe                       | denied  |
      | $HOME/probe                      | denied  |
      | /dev/azkaban-probe               | denied  |
      | $HOME/.config/azkaban/config     | denied  |

  @id:filesystem-confinement.kernel-access-rules.002 @rule:jail.landlock.cross-directory-moves-stay-inside-writable-set @verified @source:landlock.go#landlockStage @test:sandbox_test.go#TestWrite_CrossDirectoryLinkAndRename
  Scenario Outline: Files can be linked or moved between writable places but never out to a read-only one
    Given the project directory and /tmp are writable in the jail
    And /etc is read-only in the jail
    When the jailed tool <operation>
    Then the operation is <outcome>

    Examples:
      | operation                                       | outcome |
      | hard-links $HOME/.cache/a/f to $HOME/.cache/b/f | allowed |
      | moves ./mv-probe to /tmp/mv-probe               | allowed |
      | moves ./esc-probe to /etc/esc-probe             | denied  |

  @id:filesystem-confinement.kernel-access-rules.003 @rule:jail.landlock.pseudo-terminals-usable @verified @source:landlock.go#landlockStage @test:sandbox_test.go#TestRegression_PtyAllocationWorksUnderLandlock
  Scenario: A jailed tool can open a new pseudo-terminal
    When the jailed tool opens a new pseudo-terminal and writes to it
    Then the pseudo-terminal opens and the write to it succeeds

  @id:filesystem-confinement.kernel-access-rules.004 @rule:jail.landlock.outbound-tcp-limited-to-listed-ports @verified @source:landlock.go#landlockStage @test:sandbox_test.go#TestNetPorts_RestrictOutboundTCP
  Scenario: With a port allowlist, outbound TCP to any other port is refused
    Given a service is listening on 127.0.0.1:8080 on the host
    When the operator runs the jail with --net-ports 443 and the jailed tool connects to 127.0.0.1:8080
    Then the connection fails with permission denied
    And DNS lookups over UDP keep working

  @id:filesystem-confinement.kernel-access-rules.005 @rule:jail.landlock.start-up-refusals @inferred @source:landlock.go#landlockStage
  Scenario Outline: The jail refuses to start the tool when its rules or command are unusable
    When the operator runs the jail with <input>
    Then the tool does not run
    And azkaban prints <message> on stderr
    And the run exits with <code>

    Examples:
      | input                                    | message                                                        | code |
      | --net-ports 70000                        | azkaban: bad --net-ports entry: 70000                          | 2    |
      | --net-ports https                        | azkaban: bad --net-ports entry: https                          | 2    |
      | a command that is not on the PATH        | azkaban: command not found: <command>                          | 127  |

  @id:filesystem-confinement.kernel-access-rules.006 @rule:jail.landlock.policy-channel-hidden-from-tool @verified @source:landlock.go#landlockStage @test:sandbox_test.go#TestEnv_InternalLandlockChannelIsStripped
  Scenario: The jailed tool cannot read the allowlists from its environment
    When the jailed tool lists its environment variables
    Then no variable whose name starts with AZKABAN_LL_ is present

  @id:filesystem-confinement.kernel-access-rules.007 @rule:jail.landlock.degrades-on-older-kernels @inferred @source:landlock.go#landlockStage @questionable
  Scenario: On a kernel with weaker or no kernel access control, the tool still runs, with fewer rules and no warning
    Given the host kernel supports an older Landlock ABI, or none at all
    When the operator runs the jail with --net-ports 443
    Then the tool starts
    And rights the kernel cannot enforce are not applied (for example, no TCP port restriction below ABI v4)
    And azkaban prints no warning that rules were dropped
