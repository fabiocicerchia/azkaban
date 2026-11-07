@domain:transparency @area:policy-query @from:azkaban/why
Feature: Asking the jail why a path, host or port is allowed
  Lets an operator, or a confused agent inside the jail, ask what the jail would do with one path, host or port and which rule decided, without reading the bind lists or starting a jail.

  @id:transparency.policy-query.001 @rule:transparency.why.unlisted-home-path-is-absent @verified @source:why.go#decide @test:why_test.go#TestWhyDefaultDenyIsAbsentNotDenied @test:why_test.go#TestSelfDistinguishesAbsentFromDenied
  Scenario: A home path no allowlist covers is reported absent, not denied
    Given the user's home directory holds "~/Documents/notes.txt"
    And no allowlist entry and no config line covers "~/Documents"
    When the operator asks why about path "~/Documents/notes.txt" for read
    Then the answer is ABSENT
    And the matched rule is "default deny"
    And the explanation says the path does not exist inside the jail, so a read fails as ENOENT rather than EACCES

  @id:transparency.policy-query.002 @rule:transparency.why.overlay-writes-do-not-survive @verified @source:why.go#decide @test:why_test.go#TestWhyOverlayIsWritableButDoesNotSurvive @test:why_test.go#TestWhyPersistFlipsSurvival @test:why_test.go#TestSelfSaysWhenAWriteWillBeDiscarded
  Scenario Outline: A write to an allowlisted home directory is allowed but discarded unless the run persists it
    Given "~/.claude" exists in the user's home directory
    And "~/.claude" is on the built-in read-write allowlist
    When the operator asks why about path "~/.claude" for write <run flag>
    Then the answer is ALLOWED
    And the matched rule is "rwPaths .claude"
    And the survives line reads "<survives>"

    Examples:
      | run flag            | survives                           |
      | with no extra flags | no — discarded when the jail exits |
      | with --persist      | yes — writes land on the host      |

  @id:transparency.policy-query.003 @rule:transparency.why.jail-config-is-frozen @verified @source:why.go#topLayer @test:why_test.go#TestWhyRoFreezeBeatsAWritableParent
  Scenario: The jail's own configuration is reported read-only even under a writable parent
    Given the user's home directory holds "~/.config/azkaban/config"
    And "~/.config" is on the built-in read-write allowlist
    When the operator asks why about path "~/.config/azkaban" for write
    Then the answer is DENIED
    And the matched rule names roFreeze
    And the explanation says it is frozen so a writable parent cannot be used to rewrite it

  @id:transparency.policy-query.004 @rule:transparency.why.credential-stores-masked @verified @source:why.go#topLayer @test:why_test.go#TestWhyMaskBeatsTheWritableParent @test:why_test.go#TestWhyConfigUnmasksACredentialStore @test:why_test.go#TestWhyAParentOfAMaskedPathIsStillWritable @test:why_test.go#TestWhySkipsAnEntryWithNoSourceOnTheHost @test:why_test.go#TestSelfLongestMatchWinsSoAMaskBeatsItsWritableParent @questionable
  Scenario Outline: A credential store inside a writable directory is reported masked unless the user's config names it
    Given "~/.config" exists and is on the built-in read-write allowlist
    And <host state>
    And <config>
    When the operator asks why about path "<path>" for <op>
    Then the answer is <decision>

    Examples:
      | host state                                             | config                                         | path         | op    | decision                                                 |
      | the GitHub CLI store "~/.config/gh" exists on the host | the user's config has no line for it           | ~/.config/gh | read  | DENIED (masked)                                          |
      | the GitHub CLI store "~/.config/gh" exists on the host | the user's config has the line "ro .config/gh" | ~/.config/gh | read  | ALLOWED                                                  |
      | the GitHub CLI store "~/.config/gh" exists on the host | the user's config has no line for it           | ~/.config    | write | ALLOWED                                                  |
      | there is no "~/.config/gh" on the host                 | the user's config has no line for it           | ~/.config/gh | read  | ALLOWED, and the explanation says the jail can create it |

  @id:transparency.policy-query.005 @rule:transparency.why.project-dir-writes-persist @verified @source:why.go#decide @test:why_test.go#TestWhyProjectDirIsRealAndNeverOverlaid @test:why_test.go#TestSelfNamesTheProjectAsTheOnePlaceWritesPersist
  Scenario: The project directory is reported writable with writes that land on the host
    Given the operator runs from the project directory "~/proj"
    When the operator asks why about path "~/proj/src/main.go" for write
    Then the answer is ALLOWED
    And the survives line reads "yes — writes land on the host"
    And the explanation says git is the safety net there, not the jail

  @id:transparency.policy-query.006 @rule:transparency.why.system-paths-follow-base-layout @verified @source:why.go#systemVerdict @test:why_test.go#TestWhySystemPathsFollowTheBaseLayout @questionable
  Scenario Outline: Paths outside the home directory follow the jail's fixed base layout
    Given the path is outside both the user's home directory and the project directory
    When the operator asks why about path "<path>" for <op>
    Then the answer is <decision>

    Examples:
      | path                      | op    | decision                                                   |
      | /etc/passwd               | read  | ALLOWED                                                    |
      | /etc/passwd               | write | DENIED                                                     |
      | /usr/bin/ls               | write | DENIED                                                     |
      | /tmp                      | write | ALLOWED, discarded when the jail exits                     |
      | /run/user/1000/agent.sock | read  | ABSENT                                                     |
      | /var/lib/whatever         | read  | ABSENT, with a hint to add it with --ro/--rw or the config |

  @id:transparency.policy-query.007 @rule:transparency.why.network-answer-follows-run-flags @verified @source:why.go#decideNet @test:why_test.go#TestWhyNetAnswersPortsAndIsHonestAboutHosts
  Scenario Outline: A port question is answered from the run's network flags
    Given the run would use <network flags>
    When the operator asks why about port <port>
    Then the answer is <decision>
    And the matched rule is "<rule>"

    Examples:
      | network flags                 | port | decision | rule               |
      | --net-ports 443,80            | 443  | ALLOWED  | --net-ports 443,80 |
      | --net-ports 443,80            | 22   | DENIED   | --net-ports 443,80 |
      | --no-net                      | 443  | DENIED   | --no-net           |
      | --net-ports 443 --no-landlock | 22   | ALLOWED  | --no-landlock      |
      | no network flags              | 22   | ALLOWED  | default            |

  @id:transparency.policy-query.008 @rule:transparency.why.host-question-ignores-host-allowlist @verified @source:why.go#decideNet @test:why_test.go#TestWhyNetAnswersPortsAndIsHonestAboutHosts @questionable
  Scenario: A host question is answered as unfiltered even when a host allowlist is configured
    Given the user's config has the line "net api.example.com"
    When the operator asks why about host "other.example.com"
    Then the answer is ALLOWED
    And the explanation says azkaban has no host or domain allowlist

  @id:transparency.policy-query.009 @rule:transparency.why.self-refuses-outside-a-jail @verified @source:why.go#loadSelfPolicy @test:why_test.go#TestSelfOutsideAJailSaysSoRatherThanGuessing @test:why_test.go#TestSelfInsideAJailWithNoPolicyBlamesNoGuidance
  Scenario Outline: Asking from inside the jail is refused with the reason when no jail policy is available
    Given <situation>
    When the operator asks why with --self about path "~/.cache"
    Then the command fails with exit status 1
    And the error says "<message>"

    Examples:
      | situation                               | message                                                                    |
      | the shell is not inside an azkaban jail | --self answers from inside a jail, and this is not one                     |
      | the jail was started with --no-guidance | The jail was started with --no-guidance, so it carries no self-description |
