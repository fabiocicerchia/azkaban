@domain:process-isolation @area:namespaces-environment @from:azkaban/azkaban
Feature: Running the command in an isolated process and environment
  Lets an operator run a tool with no host secrets in its environment and no kernel-exploit footholds, while the run still behaves like the plain command to scripts.

  @id:process-isolation.namespaces-environment.001 @rule:azkaban.environment.host-env-cleared @verified @source:main.go#outer @test:sandbox_test.go#TestEnv_HostSecretsAreCleared
  Scenario: Host secrets in the environment do not reach the jailed tool
    Given the operator's shell exports ANTHROPIC_API_KEY, GITHUB_TOKEN, AWS_SECRET_ACCESS_KEY and SSH_AUTH_SOCK
    When the operator runs a command in the jail
    Then the tool sees ANTHROPIC_API_KEY, GITHUB_TOKEN, AWS_SECRET_ACCESS_KEY and SSH_AUTH_SOCK as empty
    And the tool sees HOME, PATH and TERM set

  @id:process-isolation.namespaces-environment.002 @rule:azkaban.environment.keep-env-inherits-everything @verified @source:main.go#outer @test:sandbox_test.go#TestEnv_KeepEnvRestoresInheritance
  Scenario: With --keep-env the tool inherits the whole host environment
    Given the operator's shell exports ANTHROPIC_API_KEY=sk-example
    When the operator runs the jail with --keep-env
    Then the tool sees ANTHROPIC_API_KEY=sk-example

  @id:process-isolation.namespaces-environment.003 @rule:azkaban.isolation.nested-user-namespaces-blocked @verified @source:main.go#outer @test:sandbox_test.go#TestUserns_NestingIsBlockedByDefault
  Scenario Outline: The jailed tool cannot create a nested user namespace unless the operator allows it
    Given the operator runs <flags>
    When the jailed tool tries to create a new user namespace
    Then the attempt <outcome>

    Examples:
      | flags               | outcome    |
      | with no extra flags | is refused |
      | with --allow-userns | succeeds   |

  @id:process-isolation.namespaces-environment.004 @rule:azkaban.isolation.sandbox-spec-hidden-from-jail @verified @source:main.go#outer @test:sandbox_test.go#TestProc_SandboxSpecIsNoLongerInCmdline @test:sandbox_test.go#TestProc_KernelSymbolsAreMasked
  Scenario: The jailed tool cannot read the jail's bind list or kernel symbol tables
    Given the jail is running
    When the jailed tool reads /proc/1/cmdline, /proc/kallsyms and /proc/modules
    Then /proc/1/cmdline contains no bind options and no Landlock allowlist
    And /proc/kallsyms and /proc/modules read as empty

  @id:process-isolation.namespaces-environment.005 @rule:azkaban.run.exit-code-propagated @verified @source:main.go#outer @test:sandbox_test.go#TestExitCode_IsPropagated
  Scenario: azkaban exits with the jailed command's exit status
    Given the jailed command exits with status 42
    When the operator runs the command in the jail
    Then azkaban exits with status 42

  @id:process-isolation.namespaces-environment.006 @rule:azkaban.run.unknown-command-refused @inferred @source:main.go#outer
  Scenario: A command that cannot be found on the host is refused before the jail starts
    Given no program named not-a-tool is on the operator's PATH
    When the operator runs not-a-tool in the jail
    Then azkaban prints "command not found: not-a-tool"
    And azkaban exits with status 127
