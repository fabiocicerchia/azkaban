@domain:filesystem-confinement @area:secret-masking @from:azkaban/azkaban
Feature: Protecting credentials and the jail's own policy
  Stops a jailed tool from reading API tokens that live inside allowlisted directories and from rewriting the config that decides the next jail.

  Background:
    Given the config directory in $HOME is on the writable allowlist

  @id:filesystem-confinement.secret-masking.001 @rule:azkaban.masking.jail-config-frozen @verified @source:main.go#outer @test:sandbox_test.go#TestConfig_JailCannotRewriteItsOwnBindList @test:sandbox_test.go#TestPersist_TrustedConfigIsStillFrozen @test:sandbox_test.go#TestWrite_OnlyIntendedPathsAreWritable
  Scenario Outline: The jail cannot change azkaban's own configuration, even with real writes on
    Given azkaban's config file holds "# legitimate"
    And the operator runs with <mode>
    When the jailed tool writes "rw /" into azkaban's config file and then deletes it
    Then after the run azkaban's config file still exists on the host
    And it still holds "# legitimate"

    Examples:
      | mode                         |
      | the default throwaway writes |
      | --persist                    |

  @id:filesystem-confinement.secret-masking.002 @rule:azkaban.masking.credential-stores-hidden @verified @source:main.go#outer @test:sandbox_test.go#TestMask_CredentialsInsideAllowlistedDirsAreHidden @test:sandbox_test.go#TestMask_UserConfigCanAddPaths
  Scenario Outline: Credential stores inside allowlisted directories cannot be read, and the host copy stays
    Given <store> on the host holds a token
    And it is masked <by>
    When the jailed tool reads <store>
    Then the tool gets no token content
    And after the run <store> on the host still holds the token

    Examples:
      | store                          | by                                             |
      | the GitHub CLI token file      | by default                                     |
      | the Docker registry login file | by default                                     |
      | the desktop keyring            | by default                                     |
      | the file .config/mytool/token  | by the config line "mask .config/mytool/token" |

  @id:filesystem-confinement.secret-masking.003 @rule:azkaban.masking.naming-a-path-unmasks-it @verified @source:main.go#outer @test:sandbox_test.go#TestMask_UserConfigCanOptOut @test:sandbox_test.go#TestPersistPath_UnmasksCredentialStore @test:main_test.go#TestMentionedInConfigCoversPersist
  Scenario Outline: Naming a masked credential store in the operator's grants makes it readable
    Given the GitHub CLI token file holds "oauth_token: NEEDED-BY-GH"
    And the operator grants the GitHub CLI config directory with <grant>
    When the jailed tool reads the GitHub CLI token file
    Then the tool reads "oauth_token: NEEDED-BY-GH"

    Examples:
      | grant                   |
      | a config ro line        |
      | the flag --persist-path |
      | the flag --rw           |
