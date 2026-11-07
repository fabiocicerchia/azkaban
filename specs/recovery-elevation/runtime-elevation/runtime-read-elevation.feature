@domain:recovery-elevation @area:runtime-elevation @from:azkaban/elevate
Feature: Approving a denied read while the run continues
  Lets an operator who passed --elevate approve, on their terminal, a read of a path outside the allowlist so an agent session doesn't have to be killed and restarted with a wider allowlist, while writes and anything the operator didn't approve stay blocked.

  Background:
    Given the operator started the jail with --elevate
    And Landlock is enforcing the jail's allowlist

  @id:recovery-elevation.runtime-elevation.001 @rule:elevation.scope.writes-never-elevated @verified @source:elevate.go#wantsWrite @test:elevate_test.go#TestOnlyAPlainReadIsEverElevated
  Scenario Outline: An attempt to write outside the allowlist is never offered for approval
    Given the file "/etc/hosts" is outside the allowlist
    When the tool in the jail opens "/etc/hosts" with <flags>
    Then the operator is not prompted
    And the jail's Landlock rules decide the open, which is refused because the path is outside the allowlist

    Examples:
      | flags             |
      | O_WRONLY          |
      | O_RDWR            |
      | O_RDONLY|O_CREAT  |
      | O_RDONLY|O_TRUNC  |
      | O_RDONLY|O_APPEND |
      | O_TMPFILE         |

  @id:recovery-elevation.runtime-elevation.002 @rule:elevation.grant.exact-existing-path-read-only @verified @source:elevate.go#openForJail @test:elevate_test.go#TestAnApprovedOpenIsReadOnlyAndRefusesASymlink @test:elevate_test.go#TestAnApprovedOpenNeverCreatesTheFile
  Scenario Outline: An approved read hands over only the exact existing file, read-only
    Given the operator has a terminal attached to the run
    And "<path>" is outside the allowlist
    When the operator approves the tool's read of "<path>"
    Then the tool sees <outcome>

    Examples:
      | path                                              | outcome                                                          |
      | /srv/shared/tool.conf (a regular file)            | the file's contents, and any write through that descriptor fails |
      | /srv/shared/link.conf (a symlink to another file) | "permission denied"                                              |
      | /srv/shared/missing.conf (does not exist)         | "permission denied", and no file is created                      |
      | a file the operator's own user cannot read        | "permission denied"                                              |
