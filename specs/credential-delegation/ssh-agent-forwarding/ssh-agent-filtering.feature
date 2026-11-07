@domain:credential-delegation @area:ssh-agent-forwarding @from:azkaban/sshagentproxy
Feature: Forwarding the SSH agent through a filter
  Lets an operator give the jailed tool enough SSH agent access to git push, without letting it change or lock the keys loaded on the host.

  Background:
    Given the operator's host ssh-agent has keys loaded
    And the operator runs the jail with --ssh-agent and without --ssh-agent-raw

  @id:credential-delegation.ssh-agent-forwarding.004 @rule:credentials.ssh-agent.confirm-requires-terminal @inferred @source:sshagentproxy.go#newSSHAgentProxy
  Scenario: Confirmation mode refuses to start without a terminal to ask on
    Given the operator also passed --ssh-agent-confirm
    And azkaban has no controlling terminal
    When the operator starts the jail
    Then azkaban exits with status 1 before the tool runs
    And the error reads "--ssh-agent: --ssh-agent-confirm needs a terminal to ask on"

  @id:credential-delegation.ssh-agent-forwarding.005 @rule:credentials.ssh-agent.socket-owner-only @verified @source:sshagentproxy.go#newSSHAgentProxy @test:sshagentproxy_test.go#TestTheJailFacingSocketIsNotReadableByOtherUsers
  Scenario: Only the operator's user can reach the filtered agent socket
    When the jail starts
    Then the agent socket handed to the jail is mode 0600
    And the directory holding it is mode 0700
    And other users on the host cannot connect to it to get signatures
