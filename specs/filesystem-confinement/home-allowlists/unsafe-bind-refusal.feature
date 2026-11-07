@domain:filesystem-confinement @area:home-allowlists @from:azkaban/cgroups
Feature: Refusing binds that would undo the jail
  Protects the operator from a config line, flag or directory name that would hand the jail back the home directory or widen the kernel allowlist, by refusing the run outright.

  Background:
    Given the operator's home directory is /home/alice

  @id:filesystem-confinement.home-allowlists.007 @rule:binds.writable.no-home-or-root @verified @source:cgroups.go#bindSafe @test:main_test.go#TestBindSafe
  Scenario Outline: A writable bind of the root, the home directory or any of its ancestors is refused
    Given <source> names <path>
    When the operator starts a jail
    Then the tool is not started
    And azkaban exits with status 2
    And stderr reads "azkaban: <message>"

    Examples:
      | source                                    | path        | message                                                                               |
      | the config line "rw /"                    | /           | refusing rw bind /: it would re-expose $HOME (or /) that the jail just hid            |
      | the config line "rw /home/alice/"         | /home/alice | refusing rw bind /home/alice/: it would re-expose $HOME (or /) that the jail just hid |
      | the config line "persist /home"           | /home       | refusing persist bind /home: it would re-expose $HOME (or /) that the jail just hid   |
      | the config line "unix-socket /home/alice" | /home/alice | --unix-socket: refusing /home/alice                                                   |

  @id:filesystem-confinement.home-allowlists.008 @rule:binds.landlock.no-newline-in-path @inferred @source:cgroups.go#llJoin
  Scenario: A bind path containing a newline or NUL refuses the run instead of widening the kernel allowlist
    Given the operator's project directory is named "proj" followed by a newline and "/run"
    When the operator starts a jail from that project directory
    Then the tool is not started
    And azkaban exits with status 2
    And stderr starts "azkaban: refusing to run: RW path contains a newline or NUL, which would inject entries into the landlock allowlist:"
