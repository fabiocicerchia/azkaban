package main

// --------------------------------------------------------------------------- //
// `azkaban why` — the query side of the policy.
//
// --dry-run already prints the resolved policy, accurately and completely, but
// it prints a bwrap command line: that is an answer to "what is the whole
// policy", not to "what about this path". Working out whether ~/.claude/projects
// is writable, whether it is overlaid, and which entry decided means reading
// rwPaths, roPaths, roFreeze, maskPaths and the overlay loop in main.go.
//
// Nothing here is new policy. It is the same lists, walked in the same order
// the bind loops apply them, reporting the layer that ended up on top. The one
// rule this file has to keep is that order — see decide().
// --------------------------------------------------------------------------- //

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// verdict - What the jail would do with one path, host or port, and why.
//
// Decision is the answer; Mechanism is how the mount layer produces it; Rule
// names the list entry that matched, so a surprising answer can be traced to
// the line that caused it rather than to "the tool said so".
type verdict struct {
	Query     string `json:"query"`
	Op        string `json:"op,omitempty"`
	Decision  string `json:"decision"`
	Mechanism string `json:"mechanism"`
	Rule      string `json:"rule"`
	Detail    string `json:"detail,omitempty"`
	Survives  *bool  `json:"survives_exit,omitempty"`
}

// layer - One binding decision, in the order the bind loops apply them. Later
// layers win, exactly as later bwrap arguments do.
type layer struct {
	kind string // "ro", "rw", "persist", "freeze", "mask"
	rel  string // the $HOME-relative entry that matched
	list string // which list it came from, for the Rule string
}

func whyCommand(argv []string) {
	fs := flag.NewFlagSet("azkaban why", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fPath := fs.String("path", "", "")
	fOp := fs.String("op", "read", "")
	fHost := fs.String("host", "", "")
	fPort := fs.Int("port", 0, "")
	fJSON := fs.Bool("json", false, "")
	// Answer from inside the jail, off the policy the outer stage wrote there.
	// This is the variant that actually helps a confused agent: it is the one
	// that can run at the moment the error happened.
	fSelf := fs.Bool("self", false, "")
	// The same flags the run would take, so the question can be "would this be
	// allowed *if* I ran it that way" rather than only "is it allowed now".
	fPersist := fs.Bool("persist", false, "")
	fNoNet := fs.Bool("no-net", false, "")
	fNetPorts := fs.String("net-ports", "", "")
	fNoLandlock := fs.Bool("no-landlock", false, "")
	var fRO, fRW, fPersistPath stringList
	fs.Var(&fRO, "ro", "")
	fs.Var(&fRW, "rw", "")
	fs.Var(&fPersistPath, "persist-path", "")
	if err := fs.Parse(argv); err != nil {
		whyUsage()
		fatal(2, err.Error())
	}

	if *fPath == "" && *fHost == "" && *fPort == 0 {
		whyUsage()
		fatal(2, "nothing to answer: pass --path, --host or --port")
	}
	if *fOp != "read" && *fOp != "write" {
		fatal(2, "--op must be read or write, got "+*fOp)
	}

	var out []verdict
	if *fSelf {
		jp, err := loadSelfPolicy()
		if err != nil {
			fatal(1, err.Error())
		}
		if *fPath != "" {
			out = append(out, decideSelf(*fPath, *fOp, jp))
		}
		if *fHost != "" || *fPort != 0 {
			out = append(out, decideNet(*fHost, *fPort, jp.NetIsolate, jp.NetPorts, jp.Landlock))
		}
	} else {
		home, _ := os.UserHomeDir()
		cwd, _ := os.Getwd()
		uc := loadUserBinds(home)
		uc.ro = append(uc.ro, fRO...)
		uc.rw = append(uc.rw, fRW...)
		uc.persist = append(uc.persist, fPersistPath...)

		if *fPath != "" {
			out = append(out, decide(*fPath, *fOp, home, cwd, uc, !*fPersist))
		}
		if *fHost != "" || *fPort != 0 {
			out = append(out, decideNet(*fHost, *fPort, *fNoNet, *fNetPorts, !*fNoLandlock))
		}
	}

	if *fJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(out)
		return
	}
	for _, v := range out {
		printVerdict(v)
	}
}

// decide - The verdict for one path, walking the layers in application order.
//
// The order below is the whole correctness of this file, and it mirrors outer()
// exactly: tmpfs over $HOME hides everything, then ro binds, then rw binds
// (overlaid by default), then persist binds, then roFreeze, then masks. Later
// wins. Getting this out of step with the bind loops would make `why` confidently
// wrong, which is worse than not having it.
func decide(path, op, home, cwd string, uc userConf, overlay bool) verdict {
	p := abs(path, home)
	v := verdict{Query: p, Op: op}

	// The project directory is bound read-write and is never overlaid — it is
	// the workspace, and it has git behind it.
	if cwd != "" && under(p, cwd) {
		yes := true
		v.Decision, v.Mechanism, v.Survives = "allowed", "--bind (the project dir)", &yes
		v.Rule = "cwd"
		v.Detail = "the working directory is bound read-write and never overlaid; git is the safety net here, not the jail"
		return v
	}

	if !under(p, home) {
		return systemVerdict(p, op)
	}

	rel, _ := filepath.Rel(home, p)
	top := topLayer(rel, home, uc)

	if top == nil {
		v.Decision, v.Mechanism, v.Rule = "absent", "--tmpfs "+home, "default deny"
		v.Detail = "$HOME is an empty tmpfs in the jail and nothing on any allowlist covers this path, so it does not exist there — a read fails as ENOENT, not EACCES"
		return v
	}

	switch top.kind {
	case "mask":
		v.Decision, v.Mechanism = "denied", "masked (empty tmpfs or empty file)"
		v.Rule = top.list + " " + top.rel
		v.Detail = "a credential store inside a wholesale-bound directory; the jail sees it empty. Name it with `ro " + top.rel + "` in " + azkabanCfgDir + "/config to keep it"
	case "freeze":
		v.Decision = allowIf(op == "read")
		v.Mechanism, v.Rule = "--ro-bind (re-bound after the rw list)", top.list+" "+top.rel
		v.Detail = "frozen on purpose: it steers a tool into running code on the next invocation, so a writable parent must not be usable to rewrite it"
	case "ro":
		v.Decision = allowIf(op == "read")
		v.Mechanism, v.Rule = "--ro-bind", top.list+" "+top.rel
	case "persist":
		yes := true
		v.Decision, v.Survives = "allowed", &yes
		v.Mechanism, v.Rule = "--bind (real host inode)", top.list+" "+top.rel
		v.Detail = "exempt from the throwaway overlay: writes here land on the host and outlive the jail"
	case "rw":
		v.Decision = "allowed"
		v.Rule = top.list + " " + top.rel
		survives := !overlay
		v.Survives = &survives
		if overlay {
			v.Mechanism = "--overlay-src + --tmp-overlay (throwaway tmpfs upper layer)"
			v.Detail = "writable, but every write and every delete evaporates on exit; the host copy is untouched. `--persist` or `persist " + top.rel + "` makes it real"
		} else {
			v.Mechanism = "--bind (--persist: real writes)"
			v.Detail = "writes land on the host, and so do deletes"
		}
	}
	// The layer covers the path; whether anything is *there* is a separate
	// question. Under a writable overlay a missing file is one the jail can
	// simply create, and reporting that as "absent" would read as a denial.
	if !exists(p) && v.Decision == "allowed" {
		v.Detail = strings.TrimSuffix(v.Detail, ".") +
			". Nothing is at this path on the host yet — the mount covers it, so the jail can create it"
	} else if !exists(p) && top.kind != "mask" {
		v.Decision = "absent"
		v.Detail = "the mount covers it, but there is no such path on the host"
	}
	return v
}

// topLayer - The last layer that covers `rel`, or nil for default-deny.
//
// A layer covers a path when the path IS the entry or sits under it. A parent
// of an entry is deliberately not covered: ~/.config is writable even though
// ~/.config/gh inside it is masked.
func topLayer(rel, home string, uc userConf) *layer {
	var top *layer
	// Every bind loop in outer() skips an entry whose source is missing on the
	// host — a bind needs something to bind. Skipping it here too is what keeps
	// this answer equal to the one the jail would give.
	consider := func(kind, list string, entries []string) {
		for _, e := range entries {
			if covers(e, rel) && exists(filepath.Join(home, e)) {
				top = &layer{kind: kind, rel: e, list: list}
			}
		}
	}
	// Application order. Later calls overwrite earlier ones, which is precisely
	// what "bound last wins" means at the mount layer.
	consider("ro", "roPaths", roPaths)
	consider("ro", "config ro", uc.ro)
	consider("rw", "rwPaths", rwPaths)
	consider("rw", "config rw", uc.rw)
	consider("persist", "config persist", uc.persist)
	consider("freeze", "roFreeze", roFreeze)
	for _, e := range slices.Concat(maskPaths, uc.mask) {
		if !covers(e, rel) || !exists(filepath.Join(home, e)) {
			continue
		}
		// The documented opt-out: anything the trusted config names is left alone.
		if mentionedInConfig(e, filepath.Join(home, e), home, uc.ro, uc.rw, uc.persist) {
			continue
		}
		list := "maskPaths"
		if slices.Contains(uc.mask, e) {
			list = "config mask"
		}
		top = &layer{kind: "mask", rel: e, list: list}
	}
	return top
}

// decideNet - The verdict for a host or a port.
//
// The honest answer about hosts is that azkaban cannot express one. --net-ports
// is a Landlock ConnectTCP allowlist over ports, and saying anything else here
// would misrepresent the containment guarantee.
func decideNet(host string, port int, noNet bool, netPorts string, landlock bool) verdict {
	q := host
	if port != 0 {
		if q != "" {
			q += ":" + strconv.Itoa(port)
		} else {
			q = "port " + strconv.Itoa(port)
		}
	}
	v := verdict{Query: q}

	if noNet {
		v.Decision, v.Mechanism, v.Rule = "denied", "--unshare-net (no route out at all)", "--no-net"
		return v
	}
	if netPorts == "" {
		v.Decision, v.Mechanism, v.Rule = "allowed", "no egress filter", "default"
		v.Detail = "outbound TCP is unrestricted. azkaban has no host or domain allowlist — only --net-ports, and only over ports"
		return v
	}
	if !landlock {
		v.Decision, v.Mechanism, v.Rule = "allowed", "no egress filter", "--no-landlock"
		v.Detail = "--net-ports is enforced by Landlock, and the Landlock stage is off, so the port list is not applied"
		return v
	}
	if host != "" && port == 0 {
		v.Decision, v.Mechanism, v.Rule = "allowed", "not filtered", "--net-ports "+netPorts
		v.Detail = "hosts are never filtered: --net-ports restricts TCP ports at the kernel and cannot express a hostname. Ask again with --port"
		return v
	}
	allowed := slices.Contains(splitPorts(netPorts), port)
	v.Decision = allowIf(allowed)
	v.Mechanism, v.Rule = "landlock ConnectTCP allowlist", "--net-ports "+netPorts
	if allowed {
		v.Detail = "the port is on the list. The host is not checked — azkaban cannot express a host allowlist"
	} else {
		v.Detail = "the port is not on the list, so connect(2) is refused by the kernel. UDP, and therefore DNS, is unaffected either way"
	}
	return v
}

func splitPorts(list string) []int {
	var out []int
	for _, s := range strings.Split(list, ",") {
		if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
			out = append(out, n)
		}
	}
	return out
}

// systemVerdict - Paths outside $HOME, which are bound by the fixed base rather
// than by any allowlist.
func systemVerdict(p, op string) verdict {
	v := verdict{Query: p, Op: op}
	no := false
	switch {
	case p == "/tmp" || under(p, "/tmp"):
		v.Decision, v.Mechanism, v.Rule, v.Survives = "allowed", "--tmpfs /tmp", "base layout", &no
		v.Detail = "a fresh tmpfs per run; nothing written here survives the jail"
	case p == "/run" || under(p, "/run"):
		v.Decision, v.Mechanism, v.Rule = "absent", "--tmpfs /run", "base layout"
		v.Detail = "/run is an empty tmpfs. --display binds a few sockets back; everything else there, including ssh-agent, gpg-agent and rootless container sockets, stays hidden"
	case p == "/proc" || under(p, "/proc"):
		v.Decision, v.Mechanism, v.Rule = allowIf(op == "read"), "--proc /proc", "base layout"
	case p == "/dev" || under(p, "/dev"):
		v.Decision, v.Mechanism, v.Rule = "allowed", "--dev /dev", "base layout"
		v.Detail = "a minimal device set. Landlock allows writes only to the handful of nodes programs actually write (null, zero, tty, pts, shm, ...), not to /dev wholesale"
	case isSystemRO(p):
		v.Decision = allowIf(op == "read")
		v.Mechanism, v.Rule = "--ro-bind", "base layout"
	default:
		v.Decision, v.Mechanism, v.Rule = "absent", "not bound", "default deny"
		v.Detail = "outside $HOME, only /usr /etc /opt /sys /proc /dev /run /tmp and the working directory are bound. Add it for one run with --ro/--rw, or for every run in " + azkabanCfgDir + "/config"
	}
	if v.Decision != "absent" && !exists(p) {
		v.Decision = "absent"
		v.Detail = "the mount covers it, but there is no such path on the host"
	}
	return v
}

func isSystemRO(p string) bool {
	for _, root := range []string{"/usr", "/etc", "/opt", "/sys", "/bin", "/lib", "/lib64", "/sbin"} {
		if p == root || under(p, root) {
			return true
		}
	}
	return false
}

// covers - Whether the $HOME-relative entry `entry` binds `rel`.
func covers(entry, rel string) bool {
	entry = filepath.Clean(entry)
	rel = filepath.Clean(rel)
	return rel == entry || strings.HasPrefix(rel, entry+string(os.PathSeparator))
}

func under(p, root string) bool {
	return p == root || strings.HasPrefix(p, strings.TrimSuffix(root, "/")+string(os.PathSeparator))
}

// abs - The absolute path for a query, expanding a literal leading ~ so that a
// quoted argument behaves the same as an unquoted one.
func abs(p, home string) string {
	if p == "~" {
		return home
	}
	if after, ok := strings.CutPrefix(p, "~/"); ok {
		p = filepath.Join(home, after)
	}
	out, err := filepath.Abs(p)
	if err != nil {
		return filepath.Clean(p)
	}
	return out
}

func allowIf(ok bool) string {
	if ok {
		return "allowed"
	}
	return "denied"
}

func printVerdict(v verdict) {
	fmt.Printf("%s\n", v.Query)
	op := ""
	if v.Op != "" {
		op = " (" + v.Op + ")"
	}
	fmt.Printf("  %s%s\n", strings.ToUpper(v.Decision), op)
	fmt.Printf("  mechanism: %s\n", v.Mechanism)
	fmt.Printf("  matched:   %s\n", v.Rule)
	if v.Survives != nil {
		survives := "no — discarded when the jail exits"
		if *v.Survives {
			survives = "yes — writes land on the host"
		}
		fmt.Printf("  survives:  %s\n", survives)
	}
	if v.Detail != "" {
		fmt.Printf("  %s\n", v.Detail)
	}
	fmt.Println()
}

func whyUsage() {
	fmt.Fprint(os.Stderr, `azkaban why [flags]

  Explain what the jail would do with one path, host or port. Answers from the
  resolved policy — the built-in lists merged with ~/.config/azkaban/config and
  whatever run flags you repeat here — without starting a jail.

  --path PATH    the path to ask about ($HOME-relative and ~ both work)
  --op read|write   which access to ask about (default: read)
  --host HOST    the host to ask about
  --port N       the TCP port to ask about
  --json         machine-readable, for tooling and for an agent
  --self         answer from INSIDE a jail, off the policy it carries. This is
                 the variant that helps a confused agent: it runs at the moment
                 the error happened. Outside a jail it says so.

  The run flags below change the answer, so you can ask "would this be allowed
  if I ran it that way": --persist, --no-net, --net-ports, --no-landlock,
  --ro, --rw, --persist-path.

  Examples:
    azkaban why --path ~/.claude --op write
    azkaban why --path ~/.ssh/id_rsa --op read
    azkaban why --port 443 --net-ports 443,80
    azkaban why --path ~/.config/gh --json
`)
}

// --------------------------------------------------------------------------- //
// --self: answering from inside the jail.
//
// The outer stage cannot answer this one. Its lists describe the host, and
// inside the jail the only truth is what was actually bound — so `--self` reads
// the policy file the outer stage wrote in, rather than re-deriving anything.
//
// The AZKABAN_LL_* allowlists are deliberately stripped before the target
// execs, which is why this needs a file at all.
// --------------------------------------------------------------------------- //

// loadSelfPolicy reads the jail's own description.
func loadSelfPolicy() (jailPolicy, error) {
	path := os.Getenv("AZKABAN_POLICY")
	if path == "" {
		path = guidancePolicyPath
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.Getenv("AZKABAN_JAIL") == "" {
			return jailPolicy{}, fmt.Errorf(
				"--self answers from inside a jail, and this is not one. Drop --self to ask about the policy a jail would have")
		}
		return jailPolicy{}, fmt.Errorf(
			"cannot read %s: %v. The jail was started with --no-guidance, so it carries no self-description", path, err)
	}
	var jp jailPolicy
	if err := json.Unmarshal(data, &jp); err != nil {
		return jailPolicy{}, fmt.Errorf("%s is not readable as a policy: %v", path, err)
	}
	return jp, nil
}

// decideSelf is decide() over the in-jail policy.
//
// Simpler than the outer version, and necessarily so: inside the jail the
// layers have already been resolved into four flat lists of absolute paths, and
// the mechanism that produced each is a fact rather than a derivation. The
// longest match wins, because a mask sits under a writable parent.
func decideSelf(path, op string, jp jailPolicy) verdict {
	p := abs(path, jp.Home)
	v := verdict{Query: p, Op: op}

	kind, matched := "", ""
	take := func(k string, entries []string) {
		for _, e := range entries {
			if under(p, e) && len(e) >= len(matched) {
				kind, matched = k, e
			}
		}
	}
	// Application order again, and then longest-match: /home/you/.config is
	// writable and /home/you/.config/gh inside it is not.
	take("rw", jp.Writable)
	take("ro", jp.ReadOnly)
	take("persist", jp.Persisted)
	take("mask", jp.Masked)
	if jp.Project != "" && under(p, jp.Project) && len(jp.Project) >= len(matched) {
		kind, matched = "project", jp.Project
	}

	yes, no := true, false
	switch kind {
	case "":
		v.Decision, v.Mechanism, v.Rule = "absent", "not mounted", "default deny"
		v.Detail = "this path is not in the jail at all. It may well exist on the host — that is not something you can reach from here, and creating it will not help"
	case "project":
		v.Decision, v.Mechanism, v.Rule, v.Survives = "allowed", "bound read-write", "the project directory", &yes
		v.Detail = "the one place writes really persist"
	case "mask":
		v.Decision, v.Mechanism, v.Rule = "denied", "blanked out", matched
		v.Detail = "a credential store, deliberately empty in here. Nothing you do will populate it"
	case "ro":
		v.Decision = allowIf(op == "read")
		v.Mechanism, v.Rule = "bound read-only", matched
		if op == "write" {
			v.Detail = "read-only. This is the sandbox, not Unix permissions — chmod will not change it and sudo is inert here"
		}
	case "persist":
		v.Decision, v.Mechanism, v.Rule, v.Survives = "allowed", "bound read-write", matched, &yes
		v.Detail = "writes here outlive the jail"
	case "rw":
		v.Decision, v.Mechanism, v.Rule = "allowed", "bound read-write", matched
		if jp.Overlay {
			v.Survives = &no
			v.Mechanism = "bound read-write, on a throwaway overlay"
			v.Detail = "writes succeed and are discarded when the jail exits. That is intended; do not try to work around it"
		} else {
			v.Survives = &yes
		}
	}
	return v
}
