@domain:filesystem-confinement @area:secret-masking @from:azkaban/config
Feature: Protecting credentials and the jail's own policy
  Stops a jailed tool from reading the token stores that sit inside wholesale-bound directories, and from rewriting the trusted azkaban config to escape on the next run.

  Background:
    Given the operator runs a command in the jail from a project directory inside their home

  @id:filesystem-confinement.secret-masking.004 @rule:jail.policy.trusted-config-frozen @verified @source:config.go#roFreeze @test:sandbox_test.go#TestConfig_JailCannotRewriteItsOwnBindList @test:sandbox_test.go#TestPersist_TrustedConfigIsStillFrozen @test:why_test.go#TestWhyRoFreezeBeatsAWritableParent
  Scenario Outline: The jail cannot change or delete its own trusted configuration
    Given the operator's azkaban user config holds their legitimate settings
    And the jail runs <mode>
    When the jailed tool tries to overwrite, append to or delete the azkaban user config
    Then the host's azkaban user config still holds exactly the operator's settings
    And `azkaban why` reports a write to the azkaban config directory as denied by the frozen list

    Examples:
      | mode                               |
      | with the default throwaway overlay |
      | with --persist                     |

  @id:filesystem-confinement.secret-masking.005 @rule:jail.secrets.credential-stores-masked @verified @source:config.go#maskPaths @test:sandbox_test.go#TestMask_CredentialsInsideAllowlistedDirsAreHidden @test:why_test.go#TestWhyMaskBeatsTheWritableParent
  Scenario Outline: Known credential stores inside allowlisted directories read as empty
    Given the operator's home holds a token in <store>
    When the jailed tool reads <store>
    Then the token's contents are not visible inside the jail
    And the host copy of <store> is unchanged

    Examples:
      | store                                  |
      | the GitHub CLI config                  |
      | the Google Cloud credentials directory |
      | the git credential store               |
      | the Docker registry auth file          |
      | the GNOME keyring directory            |
      | the Podman registry auth file          |
      | the DigitalOcean CLI config            |
      | the legacy hub config                  |

  @id:filesystem-confinement.secret-masking.006 @rule:jail.secrets.mask-opt-out-via-config @verified @source:config.go#maskPaths @test:sandbox_test.go#TestMask_UserConfigCanOptOut @test:why_test.go#TestWhyConfigUnmasksACredentialStore
  Scenario: Naming a credential store in the user config un-masks it
    Given the operator's home holds a GitHub CLI token
    And the operator's azkaban user config lists the GitHub CLI config directory as read-only
    When the jailed tool reads the GitHub CLI token
    Then the token's contents are visible inside the jail
