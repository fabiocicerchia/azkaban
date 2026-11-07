@domain:transparency @area:run-record @from:azkaban/audit
Feature: Recording what each jail run had access to
  Gives the operator a per-run record they can read after the fact (what the jail could see, what weakened it, how it ended) without that record becoming a new place where credentials leak.

  Background:
    Given the operator runs azkaban on a Linux host

  @id:transparency.run-record.001 @rule:transparency.run-record.one-owner-only-jsonl-file-per-run @verified @source:audit.go#startAudit @test:audit_test.go#TestAuditWritesOneJSONLineAnEventAndClosesWithAnExit
  Scenario: Every run leaves its own record that ends with how the run exited
    Given the operator has a writable state directory
    When the operator runs a command in the jail and it exits with code 3
    Then a new file appears under "$XDG_STATE_HOME/azkaban/audit" (or "~/.local/state/azkaban/audit"), named after the UTC start time and the process id, e.g. "20261107T104419Z-4242.jsonl"
    And the file and its directory can only be read by the operator's own user
    And every line is a JSON object of its own with a "t" timestamp and an "event" name
    And the first line is a "start" event naming the command line, working directory and home
    And the last line is an "exit" event with "code" 3 and the run's "duration_ms"

  @id:transparency.run-record.002 @rule:transparency.run-record.on-unless-explicitly-turned-off @verified @source:main.go#main @test:audit_test.go#TestAuditIsOffWhenAskedAndOnOtherwise @test:audit_test.go#TestConfigCanTurnTheRecordOffAndATypoCannot
  Scenario Outline: The run record is on unless the operator explicitly turns it off
    Given the operator has a writable state directory
    And <setting>
    When the operator starts a jail <how>
    Then a run record <outcome> written

    Examples:
      | setting                            | how             | outcome |
      | the config has no audit line       | normally        | is      |
      | the config has no audit line       | with --no-audit | is not  |
      | the config has no audit line       | with --dry-run  | is not  |
      | the config contains "audit off"    | normally        | is not  |
      | the config contains "audit no"     | normally        | is      |
      | the config contains "audit 0"      | normally        | is      |
      | the config contains "audit ON"     | normally        | is      |
      | the config contains a bare "audit" | normally        | is      |

  @id:transparency.run-record.003 @rule:transparency.run-record.credentials-redacted-from-command-line @verified @source:audit.go#redactArgv @test:audit_test.go#TestRedactArgvKeepsCredentialsOutOfTheRecord @test:audit_test.go#TestRedactionErrsTowardsRedacting
  Scenario Outline: Credentials on the command line are not written into the record
    Given the run record is on
    When the operator runs "<command>" in the jail
    Then the record's command line reads "<recorded>"

    Examples:
      | command                                          | recorded                                       |
      | gh --token=ghp_averyrealtokenvalue               | gh --token=<redacted>                          |
      | deploy --api-key sk-live-1234 --region eu-west-1 | deploy --api-key <redacted> --region eu-west-1 |
      | tool --password whatever                         | tool --password <redacted>                     |
      | tool --AUTH-TOKEN whatever                       | tool --AUTH-TOKEN <redacted>                   |
      | tool --credential-file whatever                  | tool --credential-file <redacted>              |
      | curl -H not_a_real_token_0000000000000000000000  | curl -H <redacted>                             |
      | npm run build -- --watch                         | npm run build -- --watch                       |
      | cat /home/someone/projects/thing/src/main.go     | cat /home/someone/projects/thing/src/main.go   |

  @id:transparency.run-record.004 @rule:transparency.run-record.bearer-header-value-not-redacted @inferred @source:audit.go#redactArgv @questionable
  Scenario: A credential inside a quoted header value is written to the record in full
    Given the run record is on
    When the operator runs curl -H "Authorization: Bearer example-not-a-real-token-123" https://api.example.com in the jail
    Then the record's command line still contains "Authorization: Bearer example-not-a-real-token-123"

  @id:transparency.run-record.005 @rule:transparency.run-record.forwarded-env-recorded-by-name-only @verified @source:audit.go#envNames @test:audit_test.go#TestEnvNamesRecordsNamesAndNeverValues
  Scenario: Forwarded environment variables are recorded by name, never by value
    Given the operator's config forwards ANTHROPIC_API_KEY and EXAMPLE_ABSENT_VAR into the jail
    And ANTHROPIC_API_KEY is set on the host and EXAMPLE_ABSENT_VAR is not
    When the operator starts a jail
    Then the record lists "ANTHROPIC_API_KEY" as forwarded
    And the record does not list "EXAMPLE_ABSENT_VAR"
    And the value of ANTHROPIC_API_KEY appears nowhere in the record

  @id:transparency.run-record.006 @rule:transparency.run-record.unrecordable-run-still-starts @inferred @source:audit.go#startAudit
  Scenario Outline: A run that cannot be recorded still starts, with a warning
    Given the run record is on
    And <condition>
    When the operator starts a jail
    Then the terminal shows "<warning>"
    And the jailed command still runs

    Examples:
      | condition                                | warning                                                                                                         |
      | $XDG_STATE_HOME and $HOME are both unset | azkaban: warning: no state directory ($XDG_STATE_HOME and $HOME are both unset); this run is not being recorded |
      | the state directory cannot be created    | azkaban: warning: cannot create <dir>; this run is not being recorded                                           |
      | the record file cannot be opened         | azkaban: warning: cannot write the run record (<reason>); continuing                                            |
