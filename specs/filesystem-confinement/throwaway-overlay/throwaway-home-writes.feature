@domain:filesystem-confinement @area:throwaway-overlay @from:azkaban/azkaban
Feature: Throwaway writes to the home directory
  Lets an operator give a tool writable Claude, cache and similar directories without risking the real data, because by default every write and delete there is discarded when the jail exits.

  Background:
    Given the Claude directory in $HOME holds the tool's settings file
    And the Claude directory is on the writable allowlist

  @id:filesystem-confinement.throwaway-overlay.001 @rule:azkaban.overlay.home-writes-discarded-by-default @verified @source:main.go#outer @test:sandbox_test.go#TestOverlay_DestructionIsDiscardedByDefault @test:sandbox_test.go#TestOverlay_RmRfHomeLosesNothing @test:sandbox_test.go#TestOverlay_WritesSucceedButDoNotPersist
  Scenario: Writes and deletes in allowlisted home directories are discarded when the run ends
    Given the operator has not asked for real writes
    When the jailed tool edits the settings file, creates a new file in the Claude directory and then runs rm -rf ~
    Then inside the jail the edits read back and the files appear deleted
    And after the run the settings file on the host holds its original content
    And after the run the new file does not exist on the host

  @id:filesystem-confinement.throwaway-overlay.002 @rule:azkaban.overlay.persist-makes-writes-real @verified @source:main.go#outer @test:sandbox_test.go#TestPersist_ExitCodeIsNotEvidence
  Scenario: With --persist, deletes in allowlisted home directories are real
    Given the operator asks for real writes with --persist
    When the jailed tool runs rm -rf on the Claude directory
    Then rm exits non-zero but the Claude directory is empty inside the jail
    And the settings file is gone from the host
    And hidden home directories on the host are untouched

  @id:filesystem-confinement.throwaway-overlay.003 @rule:azkaban.overlay.persist-path-survives @verified @source:main.go#outer @test:sandbox_test.go#TestPersistPath_OneFileSurvivesTheOverlay
  Scenario: A single persisted path keeps its writes while the rest of its directory stays throwaway
    Given the tool's login token file in the Claude directory holds an old token
    When the operator runs the jail with --persist-path naming the login token file, and the tool writes a new token and edits the settings file
    Then the login token file on the host holds the new token
    And the settings file on the host holds its original content

  @id:filesystem-confinement.throwaway-overlay.004 @rule:azkaban.overlay.missing-persist-path-warns @verified @source:main.go#outer @test:sandbox_test.go#TestPersistPath_MissingSourceWarns
  Scenario: A persisted path that does not exist on the host is reported and skipped
    Given the path .claude/nope.json does not exist under the home directory
    When the operator runs the jail with --persist-path .claude/nope.json
    Then azkaban prints "WARNING: persist .claude/nope.json ignored: no such path on the host"
    And the command still runs

  @id:filesystem-confinement.throwaway-overlay.005 @rule:azkaban.overlay.old-bubblewrap-falls-back-to-real-writes @inferred @source:main.go#outer @questionable
  Scenario: On a bubblewrap without overlay support, home writes become real with a warning
    Given the installed bubblewrap has no --tmp-overlay option
    And the operator has not asked for real writes
    When the operator runs a command in the jail
    Then azkaban prints "WARNING: this bwrap has no --tmp-overlay; falling back to real writes"
    And the command runs and its writes to allowlisted home directories persist on the host
