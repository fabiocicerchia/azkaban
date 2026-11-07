@domain:filesystem-confinement @area:home-allowlists @from:azkaban/config
Feature: Reaching only allowlisted parts of the home directory
  Gives operators running an AI CLI confidence that only a short list of home-directory entries the tool really needs is visible in the jail, and everything else is out of sight and safe from deletion.

  Background:
    Given the operator runs a command in the jail from a project directory inside their home

  @id:filesystem-confinement.home-allowlists.009 @rule:jail.home.unlisted-entries-absent @verified @source:config.go#rwPaths @test:sandbox_test.go#TestVisibility_SecretsAreHidden @test:sandbox_test.go#TestVisibility_SecretsUnreadableViaSymlink @test:why_test.go#TestWhyDefaultDenyIsAbsentNotDenied
  Scenario Outline: Home entries that are not on the allowlist do not exist inside the jail
    Given the operator's home holds <entry>
    And <entry> is on neither the read-write nor the read-only allowlist
    When the jailed tool checks whether <entry> exists
    Then <entry> does not exist inside the jail
    And its contents cannot be read even through a symlink planted in the project directory

    Examples:
      | entry                         |
      | the SSH key directory         |
      | the AWS credentials directory |
      | the GnuPG keyring directory   |
      | the Documents folder          |
      | a sibling project directory   |

  @id:filesystem-confinement.home-allowlists.010 @rule:jail.home.allowlisted-entries-present @verified @source:config.go#rwPaths @test:sandbox_test.go#TestVisibility_AllowlistedPathsArePresent
  Scenario Outline: Allowlisted home entries are available with their stated access
    Given the operator's home holds <entry>
    When the jailed tool opens <entry>
    Then <entry> is present inside the jail
    And <entry> is <access>

    Examples:
      | entry        | access    |
      | ~/.cache     | writable  |
      | ~/.config    | writable  |
      | ~/.claude    | writable  |
      | ~/.cargo     | writable  |
      | ~/.gitconfig | read-only |
      | ~/.local/bin | read-only |

  @id:filesystem-confinement.home-allowlists.011 @rule:jail.home.hidden-data-survives-deletion @verified @source:config.go#rwPaths @test:sandbox_test.go#TestDestruction_HiddenDataSurvivesRecursiveDelete
  Scenario: A recursive delete inside the jail leaves hidden home data intact
    Given the operator's home holds an SSH key, cloud credentials, a GPG keyring, documents and another project
    When the jailed tool runs a recursive delete over those home entries
    Then every one of those files is still on the host afterwards, with its original contents
