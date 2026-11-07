@domain:transparency @area:in-jail-guidance @from:azkaban/guidance
Feature: Describing the jail to the tool inside it
  Gives the confined agent (and the operator watching it) a read-only account of the jail's policy, so sandbox denials are not misdiagnosed as missing files, permission bugs or network outages.

  Background:
    Given the operator starts azkaban from a project directory /home/you/proj

  @id:transparency.in-jail-guidance.002 @rule:transparency.guidance.readme-explains-sandbox-errors @verified @source:guidance.go#guidanceText @test:why_test.go#TestGuidanceTextNamesAReachableCommand
  Scenario: The in-jail README tells the agent what sandbox errors look like and how to ask
    Given the jail was started with guidance
    When the agent reads /run/azkaban/README.md
    Then it says a missing path such as the SSH key directory may exist on the host and simply not be mounted, and is not a deleted file
    And it says EACCES on a write is usually the sandbox, that chmod will not fix it and sudo is inert
    And it says a failed connection may be a blocked port rather than a service being down
    And it gives the command "/run/azkaban/azkaban why --path <path> --op read|write --self --json" by absolute path
    And it tells the agent to say so to the user when a path is not reachable rather than trying another route

  @id:transparency.in-jail-guidance.003 @rule:transparency.guidance.lists-only-what-was-granted @verified @source:cgroups.go#presentUnder @test:why_test.go#TestPresentUnderSkipsWhatIsNotOnTheHost
  Scenario: The jail's self-description names only the home paths the jail actually received
    Given the built-in or configured allowlists name ~/.config and ~/.does-not-exist
    And only ~/.config exists on the host
    When the operator starts a jail
    Then the README and policy.json list /home/you/.config
    And they do not list /home/you/.does-not-exist
    And a path named twice is listed once
    And the project directory is listed first under Writable as the one place writes really persist

  @id:transparency.in-jail-guidance.004 @rule:transparency.guidance.readme-describes-network-mode @inferred @source:guidance.go#guidanceText
  Scenario Outline: The in-jail README states which network restriction applies
    Given the jail was started with <network option>
    When the agent reads /run/azkaban/README.md
    Then it says "<statement>"

    Examples:
      | network option                      | statement                                                                                                                    |
      | network isolation                   | There is no network. Nothing outbound will work.                                                                             |
      | a host allowlist of api.example.com | Outbound traffic goes through a filtering proxy (already in HTTPS_PROXY) and only these hosts are reachable: api.example.com |
      | outbound TCP restricted to port 443 | Outbound TCP is restricted to ports: 443. Other ports are refused by the kernel, which looks like a connection failure.      |
      | no network restriction              | (no network paragraph)                                                                                                       |

  @id:transparency.in-jail-guidance.005 @rule:transparency.guidance.readme-describes-overlay @verified @source:guidance.go#guidanceText @test:why_test.go#TestGuidanceTextNamesAReachableCommand @questionable
  Scenario Outline: The in-jail README warns about throwaway home writes
    Given the jail was started <overlay state>
    When the agent reads /run/azkaban/README.md
    Then <overlay paragraph>
    And it always says writes to the home directory usually succeed and are then discarded when the jail exits

    Examples:
      | overlay state                      | overlay paragraph                                                                                                                        |
      | with the default throwaway overlay | it says everything writable under /home/you except the persisted list is on a throwaway overlay and writes and deletes evaporate on exit |
      | with --persist                     | it has no throwaway-overlay paragraph                                                                                                    |

  @id:transparency.in-jail-guidance.006 @rule:transparency.guidance.policy-file-contract @verified @source:guidance.go#jailPolicy @test:why_test.go#TestSelfPolicyRoundTripsThroughJSON
  Scenario: The in-jail policy file is a machine-readable statement of what the jail allows
    Given the jail was started with guidance
    When a tool inside the jail reads /run/azkaban/policy.json
    Then it is JSON with version 1, home, project, writable, read_only, persisted, masked, overlay, landlock, network_isolated and env_forwarded
    And allowed_tcp_ports and allowed_hosts appear only when the run restricts them
    And frozen paths such as ~/.config/azkaban are listed under read_only
    And "azkaban why --self" answers from this file and reads back the same lists

  @id:transparency.in-jail-guidance.007 @rule:transparency.guidance.claude-hook-speaks-only-on-jail-failures @inferred @source:guidance.go#claudeHook @questionable
  Scenario Outline: The shipped Claude Code hook comments only on failures the jail could have caused
    Given the agent has installed /run/azkaban/claude-hook.sh as a PostToolUse hook
    And /run/azkaban/policy.json is readable
    When a tool call finishes with <outcome>
    Then the hook <response>

    Examples:
      | outcome                                          | response                                                                                                                                               |
      | success                                          | adds nothing                                                                                                                                           |
      | a failure mentioning "Permission denied"         | adds context saying the failure may be the sandbox, sudo is inert, and to run /run/azkaban/azkaban why --path <the path> --op read|write --self --json |
      | a failure mentioning "No such file or directory" | adds the same sandbox context                                                                                                                          |
      | a failure mentioning "Connection refused"        | adds the same sandbox context                                                                                                                          |
      | a failure with any other error text              | adds nothing                                                                                                                                           |
