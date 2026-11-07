# Specifications of azkaban

What this code does, one atomic Gherkin scenario per behaviour, read from the code by code-atlas.
Tags: `@verified` a test asserts it · `@inferred` read from the code only · `@gap` an entry point no test covers · `@human` written or amended by a person, never rewritten.

## Command line and configuration
How users invoke the jail and set it up for their own setup.

- **Flags and usage**: [Reading the flag reference](command-line/flags-usage/flag-reference.feature) (2), [Requesting a jail from the command line](command-line/flags-usage/jail-flags.feature) (7)
- **User configuration file**: [Reading the per-user configuration file](command-line/user-config/user-config-parsing.feature) (3)

## Container access
Letting the jailed tool use Docker or Podman without giving it control of the host.

- **Container ownership**: [Acting only on the jail's own containers](container-access/container-ownership/container-ownership.feature) (6)
- **Container socket filtering**: [Filtering container requests from the jail](container-access/socket-filtering/container-socket-filtering.feature) (8), [Opting in to a container socket](container-access/socket-filtering/container-socket-opt-in.feature) (4)

## Credential delegation
Letting the jail use credentials without holding the secrets.

- **Credential broker**: [Brokering a credential into the jail](credential-delegation/credential-broker/brokered-credentials-setup.feature) (3), [Brokering a GitHub credential into the jail](credential-delegation/credential-broker/credential-broker.feature) (2)
- **SSH agent forwarding**: [Forwarding the SSH agent through a filter](credential-delegation/ssh-agent-forwarding/ssh-agent-filtering.feature) (2), [Opting in to SSH agent forwarding](credential-delegation/ssh-agent-forwarding/ssh-agent-opt-in.feature) (3)

## Developer tooling
Building, testing, linting and threat-sweeping the project.

- **Threat sweep**: [Sweeping a tree or binary for threats](developer-tooling/threat-sweep/threat-sweep.feature) (4)

## Filesystem confinement
What parts of the host filesystem the jailed tool can see, read and write, and how the main hazards are blocked.

- **Devices and display**: [Passing only display and audio sockets with --display](filesystem-confinement/device-display-passthrough/display-sockets.feature) (1), [Granting named sockets and the display](filesystem-confinement/device-display-passthrough/named-socket-and-display-grants.feature) (2)
- **Home directory allowlists**: [Confining a run to the project directory](filesystem-confinement/home-allowlists/confine-to-project.feature) (6), [Reaching only allowlisted parts of the home directory](filesystem-confinement/home-allowlists/home-allowlist.feature) (3), [Refusing binds that would undo the jail](filesystem-confinement/home-allowlists/unsafe-bind-refusal.feature) (2)
- **Kernel access rules**: [Enforcing kernel access rules inside the jail](filesystem-confinement/kernel-access-rules/kernel-access-rules.feature) (7)
- **Secret masking**: [Protecting credentials and the jail's own policy](filesystem-confinement/secret-masking/protecting-secrets-and-policy.feature) (3), [Protecting credentials and the jail's own policy](filesystem-confinement/secret-masking/secret-masking.feature) (3)
- **Throwaway writes**: [Throwaway writes to the home directory](filesystem-confinement/throwaway-overlay/throwaway-home-writes.feature) (5)

## Network control
Controlling which outbound connections the jail can make.

- **Host allowlist proxy**: [Restricting outbound traffic to approved hosts](network-control/host-allowlist-proxy/egress-host-allowlist-setup.feature) (2), [Restricting outbound traffic to approved hosts](network-control/host-allowlist-proxy/egress-host-allowlist.feature) (3)

## Process isolation
Isolating the jailed process from the host and capping the resources it can use.

- **Namespaces and environment**: [Keeping host secrets out of the jail's environment and kernel views](process-isolation/namespaces-environment/jail-environment.feature) (4), [Jail hostname, name resolution and the shared terminal](process-isolation/namespaces-environment/jail-hostname-resolver-terminal.feature) (4), [Running the command in an isolated process and environment](process-isolation/namespaces-environment/jail-process-and-environment.feature) (6)
- **Resource limits**: [Capping a jail's memory](process-isolation/resource-limits/memory-cap.feature) (5), [Capping what a runaway tool can consume](process-isolation/resource-limits/runaway-resource-caps.feature) (4)

## Recovery and elevation
Getting out of denials and undoing damage without losing the run.

- **Snapshot and rollback**: [Reporting what a rollback-enabled run changed](recovery-elevation/rollback/rollback-run-reporting.feature) (2), [Reviewing and undoing what a jailed run changed](recovery-elevation/rollback/rollback-runs.feature) (8)
- **Runtime elevation**: [Approving a denied read while the run continues](recovery-elevation/runtime-elevation/runtime-read-elevation.feature) (2)

## Policy transparency
Showing the user and the agent what the jail allows and what happened during a run.

- **Dry run**: [Previewing the jail with a dry run](transparency/dry-run/dry-run-audit-trail.feature) (2)
- **In-jail guidance**: [Describing the jail to the tool inside it](transparency/in-jail-guidance/in-jail-guidance.feature) (6), [Telling the agent it is jailed](transparency/in-jail-guidance/in-jail-policy-description.feature) (1)
- **Policy query**: [Asking the jail why a path, host or port is allowed](transparency/policy-query/policy-query.feature) (9)
- **Run record**: [Recording what each jail run had access to](transparency/run-record/run-record.feature) (6)
