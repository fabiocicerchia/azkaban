@domain:credential-delegation @area:ssh-agent-forwarding @from:azkaban/azkaban
Feature: Opting in to SSH agent forwarding
  Lets an operator push and pull over SSH from the jail without the private keys ever entering it.

  @id:credential-delegation.ssh-agent-forwarding.001 @rule:azkaban.ssh-agent.not-forwarded-by-default @verified @source:main.go#outer @test:sandbox_test.go#TestSSHAgent_NotForwardedByDefault
  Scenario: The host SSH agent is not reachable unless the operator asks for it
    Given the operator's shell has SSH_AUTH_SOCK pointing at a running agent
    When the operator runs a command in the jail without --ssh-agent
    Then no agent socket is bound into the jail
    And SSH_AUTH_SOCK is not set in the jail

  @id:credential-delegation.ssh-agent-forwarding.002 @rule:azkaban.ssh-agent.opt-in-forwards-agent-not-keys @verified @source:main.go#outer @test:sandbox_test.go#TestSSHAgent_OptInBindsSocketAndKnownHosts
  Scenario: With --ssh-agent the jail gets an agent socket and the known-hosts list but no key files
    Given the operator has a running SSH agent
    And the SSH directory holds a private key and a known-hosts file
    When the operator runs the jail with --ssh-agent
    Then the tool sees SSH_AUTH_SOCK pointing at an agent socket
    And the known-hosts file is readable in the jail
    And the private key is not present in the jail

  @id:credential-delegation.ssh-agent-forwarding.003 @rule:azkaban.ssh-agent.missing-agent-refused @verified @source:main.go#outer @test:sandbox_test.go#TestSSHAgent_MissingAgentIsAnError
  Scenario Outline: Asking for SSH agent forwarding with no agent is refused
    Given <agent state>
    When the operator runs the jail with --ssh-agent
    Then the command does not run
    And azkaban prints "<message>"
    And azkaban exits with status 1

    Examples:
      | agent state                                                            | message                                                    |
      | SSH_AUTH_SOCK is not set                                               | --ssh-agent: SSH_AUTH_SOCK is not set; no agent to forward |
      | SSH_AUTH_SOCK points at /run/user/1000/nope.sock, which does not exist | --ssh-agent: no socket at /run/user/1000/nope.sock         |
