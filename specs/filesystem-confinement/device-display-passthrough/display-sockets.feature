@domain:filesystem-confinement @area:device-display-passthrough @from:azkaban/config
Feature: Passing only display and audio sockets with --display
  Lets a GUI or audio tool work in the jail without opening the rest of the user's runtime directory, which holds agent, keyring and container sockets.

  @id:filesystem-confinement.device-display-passthrough.003 @rule:jail.display.named-sockets-only @verified @source:config.go#displaySockets @test:sandbox_test.go#TestDisplay_BindsNamedSocketsNotTheWholeRuntimeDir
  Scenario: --display exposes the display and audio sockets but not the rest of the runtime directory
    Given the operator's runtime directory holds Wayland, PulseAudio and PipeWire sockets alongside the session bus, a Docker socket, a GPG agent and an SSH agent
    When the operator previews a --display run with --dry-run
    Then the printed command covers the runtime directory with an empty tmpfs
    And it does not bind the session bus, the Docker or Podman socket, the GPG agent or the SSH agent socket
