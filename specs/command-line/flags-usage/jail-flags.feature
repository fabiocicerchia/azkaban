@domain:command-line @area:flags-usage @from:azkaban/flags
Feature: Requesting a jail from the command line
  Lets an operator describe one jailed run in flags, and refuses flag combinations that would quietly weaken or contradict the containment they asked for.

  Background:
    Given the operator runs azkaban from a project directory

  @id:command-line.flags-usage.001 @rule:cli.flags.unfiltered-socket-requires-runtime @inferred @source:flags.go#parseFlags
  Scenario: An unfiltered container socket must name which runtime it is for
    Given the operator has not passed --bind-docker or --bind-podman
    When the operator starts azkaban with --unfiltered-container-socket
    Then azkaban exits with status 2
    And stderr reads "azkaban: --unfiltered-container-socket says how to bind the socket, not which one: add --bind-docker or --bind-podman"
    And no jail is started

  @id:command-line.flags-usage.002 @rule:cli.flags.elevate-requires-landlock @inferred @source:flags.go#parseFlags
  Scenario: Runtime elevation is refused when the kernel access rules are switched off
    When the operator starts azkaban with --elevate and --no-landlock
    Then azkaban exits with status 2
    And stderr reads "azkaban: --elevate needs landlock as its floor; not usable with --no-landlock"
    And no jail is started

  @id:command-line.flags-usage.003 @rule:cli.flags.ssh-agent-modifiers-consistent @inferred @source:flags.go#parseFlags
  Scenario Outline: SSH agent modifiers are refused unless they describe one coherent way to forward the agent
    When the operator starts azkaban with <flags>
    Then azkaban exits with status 2
    And stderr reads "azkaban: <message>"
    And no jail is started

    Examples:
      | flags                                           | message                                                                                 |
      | --ssh-agent-raw                                 | --ssh-agent-raw/--ssh-agent-confirm say HOW to forward the agent; pair with --ssh-agent |
      | --ssh-agent-confirm                             | --ssh-agent-raw/--ssh-agent-confirm say HOW to forward the agent; pair with --ssh-agent |
      | --ssh-agent --ssh-agent-raw --ssh-agent-confirm | --ssh-agent-raw binds the real agent socket; nothing is left to confirm with            |

  @id:command-line.flags-usage.004 @rule:cli.flags.rollback-excludes-persist @inferred @source:flags.go#parseFlags
  Scenario: Rollback and persist cannot be asked for together
    When the operator starts azkaban with --rollback and --persist
    Then azkaban exits with status 2
    And stderr reads "azkaban: --rollback already means real writes; --persist is redundant with it"
    And no jail is started

  @id:command-line.flags-usage.005 @rule:cli.flags.both-runtimes-picks-podman @inferred @source:flags.go#parseFlags @questionable
  Scenario: Asking for both container sockets binds only the podman socket
    When the operator starts azkaban with --bind-docker and --bind-podman
    Then the jail is given the podman socket
    And the docker socket is not bound
    And no warning is shown

  @id:command-line.flags-usage.006 @rule:cli.flags.command-and-default-shell @inferred @source:flags.go#parseFlags
  Scenario Outline: Everything from the first non-flag argument is the jailed command, and with no command the operator's shell is started
    Given the operator's SHELL is <shell>
    When the operator starts azkaban with arguments <args>
    Then the jail runs <command>

    Examples:
      | shell    | args                       | command         |
      | /bin/zsh | --no-net -- claude --print | claude --print  |
      | /bin/zsh | claude --no-net            | claude --no-net |
      | /bin/zsh | --no-net                   | /bin/zsh        |
      | (unset)  | --no-net                   | bash            |

  @id:command-line.flags-usage.007 @rule:cli.flags.help-and-unknown-flags @inferred @source:flags.go#parseFlags
  Scenario Outline: Help prints the flag reference and exits cleanly, an unknown flag is refused
    When the operator starts azkaban with <arg>
    Then <outcome>
    And the exit status is <status>
    And no jail is started

    Examples:
      | arg          | outcome                                                            | status |
      | --help       | the flag reference is printed on stdout                            | 0      |
      | -h           | the flag reference is printed on stdout                            | 0      |
      | --no-network | stderr reads "azkaban: flag provided but not defined: -no-network" | 2      |
