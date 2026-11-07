@domain:recovery-elevation @area:rollback @from:azkaban/azkaban
Feature: Reporting what a rollback-enabled run changed
  Lets an operator let writes land for real while still learning straight away what was deleted or modified and how to review it.

  Background:
    Given the operator passes --rollback

  @id:recovery-elevation.rollback.001 @rule:azkaban.rollback.real-writes-announced @inferred @source:main.go#outer
  Scenario: A rollback run announces that its writes are real
    Given the writable home directories hold 120 files
    When the operator runs a command in the jail
    Then before the command starts azkaban prints "rollback: snapshotted 120 file(s); writes this run are REAL"

  @id:recovery-elevation.rollback.002 @rule:azkaban.rollback.change-summary-after-run @inferred @source:main.go#finishRollback
  Scenario Outline: After a rollback run, azkaban reports what changed, whatever the command's exit status
    Given the command <changes>
    And the command exits with status <status>
    When the operator runs the command in the jail
    Then azkaban prints "<summary>"
    And azkaban exits with status <status>

    Examples:
      | changes                        | status | summary                                                                                            |
      | changes nothing                | 0      | rollback: 20261107T104419Z — nothing was deleted or modified                                       |
      | deletes 2 files and modifies 1 | 1      | rollback: 20261107T104419Z — 2 deleted, 1 modified.                                             |
