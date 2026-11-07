@domain:process-isolation @area:namespaces-environment @from:azkaban/config
Feature: Keeping host secrets out of the jail's environment and kernel views
  Makes sure the jailed tool inherits only a short list of harmless environment variables and cannot read kernel symbol tables, so host tokens and kernel layout do not leak in.

  Background:
    Given the operator runs a command in the jail from a project directory inside their home

  @id:process-isolation.namespaces-environment.007 @rule:jail.vars.host-secrets-dropped @verified @source:config.go#envKeep @test:sandbox_test.go#TestEnv_HostSecretsAreCleared @test:sandbox_test.go#TestEnv_HostEnvironmentIsNotReadableViaProc1
  Scenario: Host secrets in the environment do not reach the jailed tool
    Given the operator's shell exports ANTHROPIC_API_KEY, GITHUB_TOKEN, AWS_SECRET_ACCESS_KEY and SSH_AUTH_SOCK
    When the operator starts a tool in the jail
    Then each of those variables is empty inside the jail
    And HOME, PATH and TERM are still set inside the jail

  @id:process-isolation.namespaces-environment.008 @rule:jail.vars.config-admits-named-variable @verified @source:config.go#envKeep @test:sandbox_test.go#TestConfig_LegitimateEntriesStillWork
  Scenario: A variable named in the user config is passed into the jail
    Given the operator's shell exports MY_TOOL_TOKEN=passed-through
    And the operator's azkaban user config names MY_TOOL_TOKEN as a variable to forward
    When the operator starts a tool in the jail
    Then MY_TOOL_TOKEN reads passed-through inside the jail

  @id:process-isolation.namespaces-environment.009 @rule:jail.vars.keep-flag-inherits-all @verified @source:config.go#envKeep @test:sandbox_test.go#TestEnv_KeepEnvRestoresInheritance
  Scenario: The keep-environment flag passes the whole host environment through
    Given the operator's shell exports ANTHROPIC_API_KEY=sk-inherited
    When the operator starts a tool in the jail with the keep-environment flag
    Then ANTHROPIC_API_KEY reads sk-inherited inside the jail

  @id:process-isolation.namespaces-environment.010 @rule:jail.proc.kernel-symbols-masked @verified @source:config.go#procMask @test:sandbox_test.go#TestProc_KernelSymbolsAreMasked
  Scenario: Kernel symbol and module lists read as empty inside the jail
    Given the host exposes /proc/kallsyms and /proc/modules to normal users
    When the jailed tool reads /proc/kallsyms and /proc/modules
    Then both read as zero bytes
