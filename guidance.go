package main

// --------------------------------------------------------------------------- //
// Telling the tool it is in a jail.
//
// Inside the jail a denial is indistinguishable from an ordinary filesystem
// error. ~/.ssh does not exist because it was never mounted; a write outside
// the allowlist is EACCES from Landlock; a blocked host is a connection
// failure. Nothing says a sandbox produced any of it.
//
// So an agent misdiagnoses. It retries with sudo (present, and inert under
// NoNewPrivs), decides the file was deleted, "fixes" a permission problem that
// does not exist, or invents a workaround. Wasted turns at best; at worst it
// reports a confident wrong root cause to the user.
//
// The docker filter already does the right thing for its own surface — it
// answers with a Docker-shaped JSON body carrying a real reason rather than a
// bare 403. This extends that instinct to the filesystem and network layers.
//
// Everything written here is bound READ-ONLY, for the same reason
// ~/.config/azkaban is: a file that tells the agent what the policy is must not
// be a file the agent can rewrite.
// --------------------------------------------------------------------------- //

import (
	"encoding/json"
	"strings"
)

// guidanceDir is where the jail's own description lives. Under /run because it
// is a tmpfs the jail cannot otherwise write to, it is nobody's project
// directory, and it does not collide with anything a tool expects to find.
const guidanceDir = "/run/azkaban"

const (
	guidancePolicyPath = guidanceDir + "/policy.json"
	guidanceReadmePath = guidanceDir + "/README.md"
	// The binary, at a path that is certainly reachable. Telling the agent to
	// run `azkaban why` is only useful if `azkaban` is on its PATH, and whether
	// it is depends on where the user installed it — ~/go/bin is bound, /usr is
	// bound, a build in some other directory is not. An absolute path inside
	// the jail removes the question.
	guidanceBinPath = guidanceDir + "/azkaban"
)

// jailPolicy is the machine-readable half: what this jail allows, in the terms
// `azkaban why` answers in. Written by the outer stage, read by `why --self`.
//
// This is the same data --dry-run prints, minus the bwrap syntax. It is not a
// second source of truth — it is generated from the lists at the moment the
// binds are final.
type jailPolicy struct {
	Version int    `json:"version"`
	Home    string `json:"home"`
	Project string `json:"project"`

	Writable   []string `json:"writable"`
	ReadOnly   []string `json:"read_only"`
	Persisted  []string `json:"persisted"`
	Masked     []string `json:"masked"`
	Overlay    bool     `json:"overlay"`
	Landlock   bool     `json:"landlock"`
	NetIsolate bool     `json:"network_isolated"`
	NetPorts   string   `json:"allowed_tcp_ports,omitempty"`
	EnvNames   []string `json:"env_forwarded"`
}

// guidanceText is what a human — or an agent reading the file — sees.
//
// Written in the second person and kept short on purpose. A page of prose is a
// page an agent will summarise badly; the four facts that change behaviour are
// what it needs, and the last one is the instruction that stops the guessing.
func guidanceText(p jailPolicy) string {
	var b strings.Builder
	b.WriteString(`# You are running inside an azkaban jail

This machine's filesystem is not what you see. azkaban is a sandbox
(bubblewrap + Landlock) and it is deliberately invisible to the process it
confines, which means **errors here do not mean what they usually mean**:

- A path that "does not exist" may exist on the host and simply not be mounted.
  ` + "`~/.ssh`" + ` is the common case. That is ENOENT, not a deleted file, and
  creating it will not help.
- ` + "`EACCES`" + ` on a write is usually Landlock refusing, not Unix permissions.
  ` + "`chmod`" + ` will not fix it and ` + "`sudo`" + ` cannot: it exists here but is inert.
- A connection that fails may be a blocked port rather than a service being down.
- Writes to your home directory usually **succeed and are then discarded** when
  the jail exits. That is the overlay, and it is working as intended.

## Before you work around an error, ask

` + "```sh\n" + guidanceBinPath + ` why --path <path> --op read|write --self --json
` + "```" + `

It answers from this jail's own resolved policy: whether the path is writable,
whether it is overlaid, and which rule decided. If the answer is that the path
is not reachable, **say so to the user** rather than trying another route to it.

## What this jail allows

`)
	section := func(title string, items []string) {
		if len(items) == 0 {
			return
		}
		b.WriteString("**" + title + "**\n\n")
		for _, it := range items {
			b.WriteString("- `" + it + "`\n")
		}
		b.WriteString("\n")
	}
	b.WriteString("**Writable**\n\n- `" + p.Project + "` — your project, and the one place writes really persist\n")
	for _, it := range p.Writable {
		b.WriteString("- `" + it + "`\n")
	}
	b.WriteString("\n")
	section("Read-only", p.ReadOnly)
	section("Writes here outlive the jail", p.Persisted)
	section("Present but blanked out (credential stores)", p.Masked)

	if p.Overlay {
		b.WriteString("Everything writable under `" + p.Home + "` except the persisted list is on a\n" +
			"throwaway overlay: writes and deletes both evaporate on exit.\n\n")
	}
	if p.NetIsolate {
		b.WriteString("**There is no network.** Nothing outbound will work.\n\n")
	} else if p.NetPorts != "" {
		b.WriteString("Outbound TCP is restricted to ports: `" + p.NetPorts + "`. Other ports are\n" +
			"refused by the kernel, which looks like a connection failure.\n\n")
	}
	b.WriteString("Everything not listed above is **not present**. That is the design, not a fault.\n")
	return b.String()
}

func (p jailPolicy) json() string {
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return "{}"
	}
	return string(b) + "\n"
}

// claudeHook is the PostToolUse hook the docs tell people to install.
//
// Shipped as a file rather than a paragraph because the useful version is one
// someone can copy without translating it, and because a hook that reads the
// jail's own policy stays correct as the allowlist changes — a hand-written
// CLAUDE.md paragraph goes stale the first time anyone edits the config.
const claudeHook = `#!/usr/bin/env bash
# azkaban PostToolUse hook for Claude Code.
#
# Install by adding this to .claude/settings.json inside the jail:
#
#   { "hooks": { "PostToolUse": [ { "matcher": "Bash|Read|Write|Edit",
#       "hooks": [ { "type": "command", "command": "/run/azkaban/claude-hook.sh" } ] } ] } }
#
# It fires after a tool call and adds context ONLY when the call failed and the
# jail is the likely reason. A hook that comments on every success is noise the
# model learns to ignore.
set -uo pipefail

payload=$(cat)
POLICY=/run/azkaban/policy.json
[ -r "$POLICY" ] || exit 0

# Nothing to say about a call that worked.
case "$payload" in
  *'"success":true'*) exit 0 ;;
esac

# Only speak up for the error shapes the jail actually produces. Anything else
# is an ordinary bug and the model is better off reasoning about it directly.
case "$payload" in
  *"No such file or directory"*|*"Permission denied"*|*"EACCES"*|*"ENOENT"*| \
  *"Operation not permitted"*|*"Connection refused"*|*"Network is unreachable"*) ;;
  *) exit 0 ;;
esac

cat <<EOF
{"hookSpecificOutput":{"hookEventName":"PostToolUse","additionalContext":$(
  jq -Rs . <<'CTX'
That failure may be the azkaban sandbox, not a Unix permission problem or a
missing file. sudo is inert here and chmod will not help.

Run: /run/azkaban/azkaban why --path <the path> --op read|write --self --json

If it says the path is not reachable, tell the user it is outside the jail
rather than looking for another way to it. See /run/azkaban/README.md.
CTX
)}}
EOF
`
