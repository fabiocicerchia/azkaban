@domain:command-line @area:flags-usage @from:azkaban/usage
Feature: Reading the flag reference
  Gives the operator a flag reference that, for every risky default, says what changing it costs, before they hand a coding agent any access.

  Background:
    Given azkaban is installed on the operator's machine

  @id:command-line.flags-usage.008 @rule:cli.help.prints-reference-without-jailing @inferred @source:flags.go#parseFlags
  Scenario Outline: Asking for help prints the flag reference and starts no jail
    When the operator runs azkaban with <help-flag>
    Then the flag reference is printed, starting with "azkaban [flags] [--] <command> [args...]"
    And it lists the "azkaban why" and "azkaban rollback" subcommands
    And no jail is started and no command is run

    Examples:
      | help-flag |
      | -h        |
      | --help    |

  @id:command-line.flags-usage.009 @rule:cli.help.states-cost-of-risky-flags @inferred @source:usage.go#usage
  Scenario Outline: The flag reference says what each weakening flag gives away
    When the operator reads the flag reference
    Then the entry for <flag> warns that <cost>

    Examples:
      | flag                          | cost                                                                                                          |
      | --persist                     | writes to the $HOME allowlist dirs really land on disk instead of evaporating on exit                         |
      | --unfiltered-container-socket | the container socket is bound with NO filtering at all                                                        |
      | --ssh-agent-raw               | anything in the jail can add, remove or lock your keys as well as sign with them                              |
      | --ssh-agent                   | the signing oracle still authenticates as you to every host they open                                         |
      | --mem-max                     | a cap disables swap, so a workload that would have paged out is killed                                        |
      | --elevate                     | a denied read can be approved on the terminal; writes are never elevated and prompts are rate-limited to 10/s |
      | --net-ports                   | UDP and therefore DNS are unaffected                                                                          |
