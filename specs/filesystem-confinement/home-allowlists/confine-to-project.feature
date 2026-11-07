@domain:filesystem-confinement @area:home-allowlists @from:azkaban/azkaban
Feature: Confining a run to the project directory
  Lets an operator run an AI CLI so that only the project directory is really writable and the rest of $HOME stays out of reach, so a misread path cannot destroy or read personal data.

  Background:
    Given the operator's home directory is /home/alice
    And the operator's project is /home/alice/proj

  @id:filesystem-confinement.home-allowlists.001 @rule:azkaban.confinement.refuse-cwd-containing-home @verified @source:main.go#outer @test:sandbox_test.go#TestRefusal_CwdContainingHome
  Scenario Outline: A run from a directory that contains the home directory is refused
    Given the operator is in the directory <cwd>
    When the operator runs a command in the jail
    Then the command does not run
    And azkaban prints "refusing to run: <reason>"
    And azkaban exits with status 2

    Examples:
      | cwd         | reason                                           |
      | /           | cwd is / — only a project dir should be writable |
      | /home/alice | cwd (/home/alice) contains $HOME                 |
      | /home       | cwd (/home) contains $HOME                       |

  @id:filesystem-confinement.home-allowlists.002 @rule:azkaban.confinement.home-hidden-except-allowlist @verified @source:main.go#outer @test:sandbox_test.go#TestVisibility_SecretsAreHidden @test:sandbox_test.go#TestVisibility_AllowlistedPathsArePresent @test:sandbox_test.go#TestDestruction_HiddenDataSurvivesRecursiveDelete
  Scenario: Everything in the home directory outside the allowlist is invisible and survives deletion
    Given the home directory holds an SSH key directory, cloud credentials, a Documents folder and a sibling project
    And the git config, cache, config and Claude directories are on the allowlist
    When the jailed tool runs rm -rf on the SSH key directory, the cloud credentials, Documents and the sibling project
    Then inside the jail the SSH key directory, cloud credentials, Documents and the sibling project do not exist
    And inside the jail the allowlisted git config, cache, config and Claude directories are present
    And on the host every hidden file is unchanged

  @id:filesystem-confinement.home-allowlists.003 @rule:azkaban.confinement.project-dir-really-writable @verified @source:main.go#outer @test:sandbox_test.go#TestOverlay_ProjectDirIsReallyWritable
  Scenario: Writes and deletes in the project directory are real
    Given the project contains src.txt
    When the jailed tool writes out.txt and deletes src.txt in the project
    Then out.txt exists in the project on the host after the run
    And src.txt is gone from the project on the host

  @id:filesystem-confinement.home-allowlists.004 @rule:azkaban.confinement.writable-bind-cannot-reexpose-home @verified @source:main.go#outer @test:sandbox_test.go#TestConfig_RefusesBindsThatWouldUndoTheJail @test:sandbox_test.go#TestExtraBinds_PerRunFlags @test:main_test.go#TestBindSafe
  Scenario Outline: A writable grant that would re-expose the home directory or / is refused
    Given the operator asks for <grant>
    When the operator runs a command in the jail
    Then the command does not run
    And azkaban prints a message starting "<message>"
    And azkaban exits with status 2

    Examples:
      | grant                            | message                       |
      | the config line "rw /"           | refusing rw bind /            |
      | the config line "rw /home/alice" | refusing rw bind /home/alice  |
      | the config line "rw /home"       | refusing rw bind /home        |
      | the flag --rw .                  | refusing rw bind /home/alice  |
      | the flag --persist-path /home    | refusing persist bind /home   |
      | the flag --unix-socket-dir /     | --unix-socket-dir: refusing / |

  @id:filesystem-confinement.home-allowlists.005 @rule:azkaban.confinement.extra-read-only-path @verified @source:main.go#outer @test:sandbox_test.go#TestExtraBinds_PerRunFlags
  Scenario: An extra read-only path is visible in the jail but cannot be written
    Given ~/extra/f holds "VISIBLE" and is not on the allowlist
    When the operator runs the jail with --ro extra and the tool tries to overwrite ~/extra/f
    Then the tool can read "VISIBLE" from ~/extra/f
    And the write to ~/extra/f fails
    And ~/extra/f on the host still holds "VISIBLE"

  @id:filesystem-confinement.home-allowlists.006 @rule:azkaban.confinement.read-only-grant-of-home-not-refused @inferred @source:main.go#outer @questionable
  Scenario: A read-only grant of the whole home directory is accepted and exposes what the jail hides
    Given the home directory holds an SSH private key
    When the operator runs the jail with --ro /home/alice
    Then the run starts with no refusal
    And the jailed tool can read the SSH private key
