@domain:transparency @area:in-jail-guidance @from:azkaban/azkaban
Feature: Telling the agent it is jailed
  Lets an agent inside the jail tell sandbox denials from ordinary errors by reading a description of its policy that it cannot change.

  @id:transparency.in-jail-guidance.001 @rule:azkaban.guidance.policy-placed-read-only @verified @source:main.go#outer @test:why_test.go#TestDryRunShowsTheGuidanceBinds @test:why_test.go#TestNoGuidanceLeavesThemOut
  Scenario Outline: The jail carries a read-only description of its own policy unless the operator turns it off
    Given the operator runs <flags>
    When the operator starts a command in the jail
    Then AZKABAN_JAIL and AZKABAN_POLICY are <env>
    And the policy file, README, Claude hook and azkaban binary in the guidance directory are <files>

    Examples:
      | flags               | env                  | files                 |
      | with no extra flags | set (AZKABAN_JAIL=1) | present and read-only |
      | with --no-guidance  | not set              | absent                |
