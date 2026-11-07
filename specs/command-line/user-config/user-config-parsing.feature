@domain:command-line @area:user-config @from:azkaban/cgroups
Feature: Reading the per-user configuration file
  Lets an operator add per-user paths, environment passthrough, masks and switches in ~/.config/azkaban/config without a typo stopping the jail or quietly turning a safeguard off.

  Background:
    Given the operator has a ~/.config/azkaban/config file

  @id:command-line.user-config.001 @rule:config.file.unknown-lines-ignored @verified @source:cgroups.go#parseUserBinds @test:main_test.go#TestParseUserBinds
  Scenario: Unknown or malformed config lines are skipped and the rest of the file still applies
    Given the config contains "ro .gitconfig", "rw .local/share/foo", "env ANTHROPIC_API_KEY" and the line "bogus line ignored"
    When the operator starts a jail
    Then the jail starts
    And ~/.gitconfig is available read-only and ~/.local/share/foo read-write
    And ANTHROPIC_API_KEY is passed into the jail
    And the bogus line has no effect

  @id:command-line.user-config.002 @rule:config.audit.only-exact-off-disables-record @verified @source:cgroups.go#parseUserBinds @test:audit_test.go#TestConfigCanTurnTheRecordOffAndATypoCannot
  Scenario Outline: Only the exact line "audit off" turns the run record off
    Given the config contains the line "<line>"
    When the operator starts a jail
    Then the run record is <state>

    Examples:
      | line      | state       |
      | audit off | not written |
      | audit no  | written     |
      | audit 0   | written     |
      | audit ON  | written     |
      | audit     | written     |

  @id:command-line.user-config.003 @rule:config.mask.named-path-unmasked @verified @source:cgroups.go#mentionedInConfig @test:main_test.go#TestMentionedInConfigCoversPersist
  Scenario Outline: A masked credential store that the config names with ro, rw or persist is left visible
    Given the operator's home is /home/alice and they have a GitHub CLI login under ~/.config/gh
    And the config contains "<line>"
    When the operator starts a jail
    Then ~/.config/gh is <visibility> inside the jail

    Examples:
      | line                      | visibility                     |
      | persist .config/gh        | visible with its real contents |
      | ro .config/gh             | visible with its real contents |
      | rw /home/alice/.config/gh | visible with its real contents |
      | persist .config/doctl     | masked empty                   |
