@domain:process-isolation @area:namespaces-environment @from:azkaban/helpers
Feature: Jail hostname, name resolution and the shared terminal
  Operators get a jail whose own hostname and DNS keep working inside the private namespace, and they are told when the host kernel leaves the shared terminal open to command injection.

  Background:
    Given the operator runs a tool inside the jail

  @id:process-isolation.namespaces-environment.011 @rule:jail.network.own-hostname-resolves @inferred @source:helpers.go#writeHosts
  Scenario: The jail's own hostname resolves inside the jail
    Given the operator's /etc/hosts has no entry for "azkaban"
    When the jailed tool looks up the hostname "azkaban"
    Then it resolves to 127.0.0.1
    And every entry from the operator's /etc/hosts is still present in the jail's hosts file

  @id:process-isolation.namespaces-environment.012 @rule:jail.network.host-resolver-copied @inferred @source:helpers.go#writeResolv
  Scenario: The jail uses the operator's real DNS resolver configuration
    Given the operator's /etc/resolv.conf is a symlink into /run, for example to a systemd stub resolver
    When the jailed tool resolves example.com
    Then the jail's /etc/resolv.conf has the same contents as the symlink's target on the host

  @id:process-isolation.namespaces-environment.013 @rule:jail.network.unreadable-host-file-warns @inferred @source:helpers.go#writeHosts
  Scenario Outline: An unreadable host hosts or resolver file is warned about, not fatal
    Given the operator's <host_file> cannot be read
    When the operator starts the jail
    Then stderr shows a warning naming <host_file> and ending "<consequence>"
    And the jailed tool still runs

    Examples:
      | host_file        | consequence                         |
      | /etc/hosts       | the jail gets only its own hostname |
      | /etc/resolv.conf | the jail will have no resolver      |

  @id:process-isolation.namespaces-environment.014 @rule:jail.terminal.tiocsti-warning @inferred @source:helpers.go#warnTIOCSTI
  Scenario Outline: The operator is warned when the kernel lets the jail inject keystrokes into their terminal
    Given the kernel's legacy TIOCSTI setting is <tiocsti_setting>
    And the operator's input <is_terminal> a terminal
    When the operator starts the jail <mode>
    Then <warning_outcome>

    Examples:
      | tiocsti_setting                | is_terminal | mode           | warning_outcome                                                                                                                                                                            |
      | 1                              | is          | normally       | stderr shows "azkaban: WARNING: this kernel allows TIOCSTI; ... Close it host-wide with: sysctl -w dev.tty.legacy_tiocsti=0" and the run record logs a degraded event "tiocsti-permissive" |
      | absent (kernel older than 6.2) | is          | normally       | the same TIOCSTI warning is shown and recorded                                                                                                                                             |
      | 0                              | is          | normally       | no TIOCSTI warning is shown                                                                                                                                                                |
      | 1                              | is not      | normally       | no TIOCSTI warning is shown                                                                                                                                                                |
      | 1                              | is          | with --dry-run | no TIOCSTI warning is shown                                                                                                                                                                |
