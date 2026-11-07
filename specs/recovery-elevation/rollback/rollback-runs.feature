@domain:recovery-elevation @area:rollback @from:azkaban/rollback
Feature: Reviewing and undoing what a jailed run changed
  Operators who want a tool's writes to their home directory to be kept, without losing the ability to put back anything it deletes or overwrites.

  Background:
    Given the operator has a home directory with writable allowlisted entries such as ~/.claude

  @id:recovery-elevation.rollback.003 @rule:rollback.runs.snapshot-either-side-even-on-failure @inferred @source:main.go#finishRollback
  Scenario: A rollback run's real writes are snapshotted before and after, and the operator is told what was destroyed
    Given the operator starts a run with --rollback
    And the tracked entries hold ~/.claude/projects/a.jsonl and ~/.claude/history.jsonl
    When the jailed command deletes a.jsonl, edits history.jsonl and exits with status 1
    Then before the command starts the operator sees "azkaban: rollback: snapshotted 2 file(s); writes this run are REAL"
    And the deletion and the edit stay on the host after the run
    And on exit the operator sees "azkaban: rollback: 20261107T104500Z — 1 deleted, 1 modified." followed by "Review: azkaban rollback show 20261107T104500Z"
    And the run still exits with status 1

  @id:recovery-elevation.rollback.004 @rule:rollback.runs.incompatible-with-persist @inferred @source:flags.go#parseFlags
  Scenario: Asking for rollback and persist together is refused
    When the operator starts a run with both --rollback and --persist
    Then the run does not start
    And the operator sees "--rollback already means real writes; --persist is redundant with it"
    And the exit status is 2

  @id:recovery-elevation.rollback.005 @rule:rollback.snapshot.excludes-repos-build-output-and-links @verified @source:rollback.go#takeSnapshot @test:rollback_test.go#TestRollbackSkipsGitAndBuildOutput @test:rollback_test.go#TestRollbackDoesNotFollowSymlinksOutOfTheRoot @questionable
  Scenario Outline: Git data, build output and symlinks are never snapshotted, and a tree too large to snapshot is reported
    Given the operator starts a run with --rollback
    And a tracked entry contains <path>
    When the jail takes its snapshot
    Then <path> is <outcome>

    Examples:
      | path                                       | outcome                                                                                                                   |
      | src/main.go                                | recorded and restorable                                                                                                   |
      | .git/objects/ab/cdef                       | not recorded                                                                                                              |
      | node_modules/pkg/index.js                  | not recorded                                                                                                              |
      | a symlink to a directory outside the entry | not followed, and nothing behind it is recorded                                                                           |
      | the 20001st file of a single entry         | not recorded, and the run record warns "not snapshotted: <entry> (over 20000 files); changes there cannot be rolled back" |

  @id:recovery-elevation.rollback.006 @rule:rollback.review.list-sessions-newest-first @inferred @source:rollback.go#rollbackList
  Scenario: The operator can list recorded rollback sessions with their damage counts
    Given two --rollback runs have been recorded, the newer one deleted 3 files and modified 1
    When the operator runs azkaban rollback list
    Then the newer session is listed first as "<id>  2026-11-07 10:45  3 deleted, 1 modified  (claude --resume)"
    And with no recorded sessions the operator instead sees "no rollback sessions in /home/operator/.local/state/azkaban/rollback — run with --rollback first"

  @id:recovery-elevation.rollback.007 @rule:rollback.review.show-changes-filtered @verified @source:rollback.go#rollbackShow @test:rollback_test.go#TestRollbackRestoresWhatWasDeleted
  Scenario Outline: Showing a session lists what the run deleted, modified and added, optionally narrowed by path
    Given session 20261107T104500Z deleted ~/.claude/projects/a.jsonl, modified ~/.claude/history.jsonl and added ~/.claude/new.txt
    When the operator runs azkaban rollback show 20261107T104500Z <filter>
    Then the operator sees <listed>
    And the listing ends with "Put them back with:" followed by "azkaban rollback restore 20261107T104500Z [path-substring...]"

    Examples:
      | filter   | listed                                                    |
      |          | deleted a.jsonl, modified history.jsonl and added new.txt |
      | projects | only deleted a.jsonl                                      |

  @id:recovery-elevation.rollback.008 @rule:rollback.restore.puts-back-before-content-never-deletes @verified @source:rollback.go#restore @test:rollback_test.go#TestRollbackRestoresWhatWasDeleted @questionable
  Scenario: Restoring puts deleted and modified files back as they were before the run, and never deletes what the run added
    Given session 20261107T104500Z deleted ~/.claude/projects/a.jsonl, modified ~/.claude/history.jsonl and added ~/.claude/new.txt
    When the operator runs azkaban rollback restore 20261107T104500Z
    Then a.jsonl exists again with its content from before the run
    And history.jsonl holds its content from before the run again
    And new.txt is left in place
    And the operator sees "restored" next to a.jsonl and history.jsonl

  @id:recovery-elevation.rollback.009 @rule:rollback.restore.refuses-unverifiable-content @verified @source:rollback.go#restore @test:rollback_test.go#TestRollbackRefusesCorruptedContent
  Scenario Outline: A file whose original content cannot be verified is not restored
    Given session 20261107T104500Z deleted ~/models/<file>
    And <condition>
    When the operator runs azkaban rollback restore 20261107T104500Z
    Then <file> is not written
    And the operator sees "FAILED" next to <file> with "<reason>"
    And the other files in the session are still restored

    Examples:
      | file        | condition                                              | reason                                                                   |
      | weights.bin | the file was larger than 64 MiB when snapshotted       | no stored content (too large, or unreadable when the snapshot was taken) |
      | notes.txt   | its stored content has been altered since the snapshot | stored content does not match its hash; refusing to write it             |
      | notes.txt   | its stored content has been removed                    | is not in the store                                                      |

  @id:recovery-elevation.rollback.010 @rule:rollback.cleanup.keep-newest-sessions @inferred @source:rollback.go#rollbackCleanup @questionable
  Scenario Outline: Cleanup keeps the newest sessions and frees content that no kept session can restore
    Given 12 rollback sessions are recorded
    When the operator runs azkaban rollback cleanup <argument>
    Then the newest <kept> sessions remain listed
    And stored content only the dropped sessions needed is removed
    And the operator sees "kept the newest <kept> session(s); dropped 7 unreferenced object(s), 3.2 MiB"

    Examples:
      | argument | kept |
      | 3        | 3    |
      |          | 10   |
      | 0        | 10   |
      | abc      | 10   |
