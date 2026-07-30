package main

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestParseUserBinds(t *testing.T) {
	c := parseUserBinds(`
# comment
ro .gitconfig
rw .local/share/foo
  ro   /etc/ssl/certs
env ANTHROPIC_API_KEY
mask .config/mytool/token
bogus line ignored
`)
	eq := func(name string, got, want []string) {
		t.Helper()
		if !slices.Equal(got, want) {
			t.Fatalf("%s = %v, want %v", name, got, want)
		}
	}
	eq("ro", c.ro, []string{".gitconfig", "/etc/ssl/certs"})
	eq("rw", c.rw, []string{".local/share/foo"})
	eq("env", c.env, []string{"ANTHROPIC_API_KEY"})
	eq("mask", c.mask, []string{".config/mytool/token"})
}

// The jail binds ~/.config rw, so it can write ~/.config/azkaban/config. A `rw /`
// (or `rw $HOME`) line there would re-expose everything the home tmpfs hides on
// the NEXT run — bindSafe is what stops that from being a full escape.
func TestBindSafe(t *testing.T) {
	const home = "/home/u"
	for _, c := range []struct {
		path string
		want bool
	}{
		{"/home/u/.cache", true},
		{"/srv/data", true},
		{"/", false},
		{"/home/u", false},
		{"/home/u/", false}, // Clean() strips the slash; must not slip past
		{"/home", false},    // ancestor of $HOME
	} {
		if got := bindSafe(home, c.path); got != c.want {
			t.Errorf("bindSafe(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

func TestFilterReasonContainer(t *testing.T) {
	root := t.TempDir()
	root = realPath(root) // t.TempDir may sit under a symlink (e.g. /tmp -> /private/tmp)
	inside := filepath.Join(root, "sub")

	cases := []struct {
		name    string
		body    string
		wantBad bool
	}{
		{"no hostconfig", `{"Image":"alpine"}`, false},
		{"bind inside cwd", `{"HostConfig":{"Binds":["` + inside + `:/app"]}}`, false},
		{"bind root", `{"HostConfig":{"Binds":["/:/host"]}}`, true},
		{"bind etc", `{"HostConfig":{"Binds":["/etc:/etc:ro"]}}`, true},
		{"named volume", `{"HostConfig":{"Binds":["myvol:/data"]}}`, false},
		{"anonymous volume", `{"HostConfig":{"Binds":["/data"]}}`, false},
		{"mount bind outside", `{"HostConfig":{"Mounts":[{"Type":"bind","Source":"/root"}]}}`, true},
		{"mount bind inside", `{"HostConfig":{"Mounts":[{"Type":"bind","Source":"` + inside + `"}]}}`, false},
		{"mount volume type", `{"HostConfig":{"Mounts":[{"Type":"volume","Source":"vol"}]}}`, false},
		// Bind-in-disguise: a local-driver volume mounted inline at container
		// create, with a device opt pointing outside cwd. Must be denied even
		// though its Type is "volume", not "bind" (regression for the filter gap).
		{"mount volume device outside", `{"HostConfig":{"Mounts":[{"Type":"volume","VolumeOptions":{"DriverConfig":{"Name":"local","Options":{"type":"none","o":"bind","device":"/etc"}}}}]}}`, true},
		{"mount volume device inside", `{"HostConfig":{"Mounts":[{"Type":"volume","VolumeOptions":{"DriverConfig":{"Name":"local","Options":{"type":"none","o":"bind","device":"` + inside + `"}}}}]}}`, false},
		{"mount volume no device", `{"HostConfig":{"Mounts":[{"Type":"volume","VolumeOptions":{"DriverConfig":{"Name":"local","Options":{"foo":"bar"}}}}]}}`, false},
		{"privileged", `{"HostConfig":{"Privileged":true}}`, true},
		{"device", `{"HostConfig":{"Devices":[{"PathOnHost":"/dev/sda"}]}}`, true},
		{"cap sys_admin", `{"HostConfig":{"CapAdd":["SYS_ADMIN"]}}`, true},
		{"cap prefixed", `{"HostConfig":{"CapAdd":["CAP_DAC_READ_SEARCH"]}}`, true},
		{"cap benign", `{"HostConfig":{"CapAdd":["NET_ADMIN"]}}`, false},
		{"pid host", `{"HostConfig":{"PidMode":"host"}}`, true},
		{"userns host", `{"HostConfig":{"UsernsMode":"host"}}`, true},
		// --net=host defeats --no-net and turns the allowed NET_ADMIN cap into a
		// host firewall/sniffing primitive.
		{"net host", `{"HostConfig":{"NetworkMode":"host"}}`, true},
		{"net bridge", `{"HostConfig":{"NetworkMode":"bridge"}}`, false},
		// Joining another container's namespace is transitive: that container may
		// itself be on the host stack.
		{"net container join", `{"HostConfig":{"NetworkMode":"container:abc"}}`, true},
		{"pid container join", `{"HostConfig":{"PidMode":"container:abc"}}`, true},
		{"seccomp unconfined", `{"HostConfig":{"SecurityOpt":["seccomp=unconfined"]}}`, true},
		{"apparmor unconfined", `{"HostConfig":{"SecurityOpt":["apparmor:unconfined"]}}`, true},
		{"selinux label disable", `{"HostConfig":{"SecurityOpt":["label=disable"]}}`, true},
		{"no-new-privileges ok", `{"HostConfig":{"SecurityOpt":["no-new-privileges"]}}`, false},
		{"bad json", `{not json`, true},
	}
	for _, c := range cases {
		got := filterReason("/v1.45/containers/create", []byte(c.body), root)
		if (got != "") != c.wantBad {
			t.Errorf("%s: reason=%q, wantBad=%v", c.name, got, c.wantBad)
		}
	}
}

// Matching on the first path SEGMENT (not a suffix) is what makes the endpoint
// allowlist total, so the version-prefix stripping has to be exact. Which roots
// are allowed is asserted end-to-end against the handler in
// dockerproxy_destructive_test.go; this covers only the parse.
func TestAPIRoot(t *testing.T) {
	for _, c := range []struct{ path, want string }{
		{"/v1.45/containers/create", "containers"},
		{"/containers/create", "containers"},
		{"/_ping", "_ping"},
		{"/v1.45/services/create", "services"},
		{"/v4.0.0/libpod/containers/create", "libpod"},
		// "volumes" is not a version prefix; it must not be stripped as one.
		{"/volumes/create", "volumes"},
	} {
		if got := apiRoot(c.path); got != c.want {
			t.Errorf("apiRoot(%q) = %q, want %q", c.path, got, c.want)
		}
	}
}

func TestFilterReasonVolumeAndSymlink(t *testing.T) {
	root := realPath(t.TempDir())

	if r := filterReason("/volumes/create",
		[]byte(`{"DriverOpts":{"type":"none","o":"bind","device":"/home"}}`), root); r == "" {
		t.Error("volume device outside cwd should be denied")
	}
	if r := filterReason("/volumes/create", []byte(`{"Name":"plain"}`), root); r != "" {
		t.Errorf("plain named volume should be allowed, got %q", r)
	}

	// A symlink inside cwd pointing outside it must NOT pass the bind check.
	link := filepath.Join(root, "escape")
	if err := os.Symlink("/etc", link); err != nil {
		t.Fatal(err)
	}
	if r := filterReason("/containers/create",
		[]byte(`{"HostConfig":{"Binds":["`+link+`:/x"]}}`), root); r == "" {
		t.Error("symlink escaping cwd should be denied")
	}
}
