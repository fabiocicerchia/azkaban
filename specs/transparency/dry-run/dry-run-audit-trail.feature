@domain:transparency @area:dry-run @from:azkaban/azkaban
Feature: Previewing the jail with a dry run
  Lets an operator audit exactly what a run would grant, as a copy-pasteable command, without running anything or exposing live secrets.

  Background:
    Given the operator passes --dry-run

  @id:transparency.dry-run.001 @rule:azkaban.dry-run.prints-command-runs-nothing @verified @source:main.go#outer @test:why_test.go#TestDryRunShowsTheGuidanceBinds
  Scenario: A dry run prints the full sandbox command and runs nothing
    Given the operator asks to run /bin/true
    When the operator runs the jail
    Then azkaban prints one shell-quoted bwrap command ending in the command to run
    And the printed command includes the in-jail guidance files and AZKABAN_JAIL
    And /bin/true is not started
    And no run record is written

  @id:transparency.dry-run.002 @rule:azkaban.dry-run.discloses-policy-with-placeholders @inferred @source:main.go#outer
  Scenario Outline: A dry run discloses brokers, egress filtering and the container socket without live values
    Given <setup>
    When the operator runs the jail
    Then the printed command shows <shown>
    And <note>

    Examples:
      | setup                                    | shown                                                                                     | note                                                                       |
      | the config brokers the github credential | AZKABAN_CREDENTIAL_GITHUB=<brokered at 127.0.0.1:<port>>                                  | no secret is read and no broker is started                                 |
      | the config allowlists api.example.com    | HTTP_PROXY=http://azkaban:<per-run token>@127.0.0.1:<port> and the port list <proxy port> | no proxy is started                                                        |
      | the operator passes --bind-docker        | the raw Docker socket as the bind source                                                  | azkaban notes that a real run substitutes the filtering proxy socket there |
