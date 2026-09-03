// dockerproxy.go — filtering reverse proxy in front of the real docker socket.
//
// WHY THIS EXISTS: binding the raw docker socket into the jail hands the jailed
// process the daemon's ENTIRE API. The bind mount for `docker run -v /:/h` is
// performed by dockerd on the HOST, outside bwrap/landlock, so the sandbox can
// never police it (see the note at the bottom of main.go). The socket IS the
// control surface; the only place to enforce "no host paths outside the project
// dir" is on the API itself. This proxy is that enforcement point.
//
// It runs in the OUTER (host) process; only its socket is bound into the jail.
// Two layers, both deny-by-default:
//
//  1. ENDPOINT ALLOWLIST (allowedRoots) — anything outside the everyday
//     container/image/build surface is refused outright. This is what keeps
//     /swarm + /services (whose ContainerSpec.Mounts take host paths and never
//     reach the body filter) and /plugins (host mounts via plugin privileges)
//     from walking straight past the checks below.
//  2. BODY FILTER — container- and volume-create bodies are parsed and rejected
//     if they would mount a host path outside cwd, grant privilege, add dangerous
//     capabilities, pass through host devices, relax seccomp/apparmor, or share
//     the host net/pid/ipc/userns namespaces.
//
// What this is NOT: an authorization boundary for the rest of the API. Allowed
// endpoints still let the jail start, exec into and delete PRE-EXISTING host
// containers — including any created earlier with `-v /:/host`.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// startDockerFilterProxy - Listens on a fresh unix socket, forwards to
// realSock, and returns the proxy socket path (to be bound into the jail). cwd
// is the only host directory bind mounts are permitted to reach.
func startDockerFilterProxy(realSock, cwd string) (string, error) {
	dir, err := os.MkdirTemp("/tmp", "azkaban-dockerproxy-")
	if err != nil {
		return "", err
	}
	tempTrack(dir)
	sock := filepath.Join(dir, "docker.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		return "", err
	}

	target, _ := url.Parse("http://docker")
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.Transport = &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", realSock)
		},
	}
	proxy.FlushInterval = -1 // stream pulls/build/logs/attach without buffering

	rootReal := realPath(cwd)
	// Timeouts bound how long one jailed request can pin a goroutine and an fd.
	// No WriteTimeout: docker legitimately streams pulls, builds and logs for
	// minutes, and a deadline there would cut them off mid-transfer.
	srv := &http.Server{
		Handler:           dockerFilterHandler(proxy, rootReal),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	go srv.Serve(ln)
	return sock, nil
}

// create bodies are tiny; cap the read so a hostile client cannot make us buffer
// unbounded memory before we forward.
const maxCreateBody = 4 << 20

// allowedRoots is the first path segment (after the /vX.YZ prefix) of every API
// area the jail may reach. Everything else — /swarm, /services, /nodes, /tasks,
// /secrets, /configs, /plugins — is refused: those endpoints accept host mounts
// or host-privileged code through bodies this filter does not model.
var allowedRoots = map[string]bool{
	"containers": true, "images": true, "exec": true, "build": true,
	"volumes": true, "networks": true, "commit": true, "distribution": true,
	"version": true, "info": true, "_ping": true, "events": true,
	"system": true, "auth": true,
	// buildkit's client-driven build channel; carries no host paths.
	"session": true, "grpc": true,
}

// apiRoot - Strips the optional /vX.YZ version prefix and returns the first
// path segment. Matching on the segment (not a suffix) is what makes the
// allowlist total: an unmodelled endpoint cannot slip through by not matching a
// pattern.
func apiRoot(p string) string {
	p = strings.TrimPrefix(p, "/")
	if i := strings.IndexByte(p, '/'); i > 1 && p[0] == 'v' && strings.ContainsAny(p[1:i], "0123456789") {
		p = p[i+1:]
	}
	if i := strings.IndexByte(p, '/'); i >= 0 {
		p = p[:i]
	}
	return p
}

// destructiveReason - Refuses the calls that destroy data which has no other
// copy. The rest of the filter blocks ESCAPE; this blocks LOSS, which under
// azkaban's threat model — an agent doing damage by accident — is the likelier
// harm.
//
// Deliberately narrow. `docker rm` and `docker rmi` stay allowed: containers and
// images are rebuildable, and blocking them would break `--rm` cleanup and every
// ordinary workflow. A named volume is the one thing with no git history and no
// trash behind it, and prune deletes in bulk across resources at once.
func destructiveReason(r *http.Request) string {
	p := r.URL.Path
	if strings.HasSuffix(p, "/prune") {
		return "bulk deletion (" + p + ") is not allowed from inside the jail"
	}
	if r.Method == http.MethodDelete && strings.Contains(p, "/volumes/") {
		return "deleting volumes is not allowed from inside the jail: " +
			"a named volume has no other copy. Remove it from outside if you mean to."
	}
	return ""
}

// dockerFilterHandler - Wraps the reverse proxy with the filter, in the order
// the checks get cheaper to fail: the destructive verbs, then the endpoint
// allowlist, then the create bodies. Every denial is printed to the host's
// stderr, because a silently filtered API call looks like a docker bug.
func dockerFilterHandler(proxy http.Handler, rootReal string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if reason := destructiveReason(r); reason != "" {
			dockerDecision(r, "denied", reason)
			denyJSON(w, reason)
			return
		}
		if root := apiRoot(r.URL.Path); !allowedRoots[root] {
			dockerDecision(r, "denied", "endpoint not in allowlist")
			denyJSON(w, "the /"+root+" API is not reachable from inside the jail")
			return
		}
		if guarded(r) {
			body, err := io.ReadAll(io.LimitReader(r.Body, maxCreateBody))
			r.Body.Close()
			if err != nil {
				denyJSON(w, "could not read request body")
				return
			}
			if reason := filterReason(r.URL.Path, body, rootReal); reason != "" {
				dockerDecision(r, "denied", reason)
				denyJSON(w, reason)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
			r.ContentLength = int64(len(body))
		}
		// Allowed calls are recorded too, and only in the run record. Printing
		// every permitted API call to stderr would drown the denials that
		// matter; not recording them at all leaves "what did this jail actually
		// do with the socket" unanswerable, which is the question the record
		// exists for.
		dockerDecision(r, "allowed", "")
		proxy.ServeHTTP(w, r)
	})
}

// dockerDecision - Records one filter verdict, and prints the denials.
//
// A denial goes to stderr as well because a silently filtered API call looks
// like a docker bug, and the person seeing it is usually mid-command. An
// allowed call goes only to the record.
func dockerDecision(r *http.Request, decision, reason string) {
	if decision == "denied" {
		fmt.Fprintln(os.Stderr, "azkaban: docker filter DENIED "+r.URL.Path+": "+reason)
	}
	auditLog.event("docker", map[string]any{
		"decision": decision,
		"method":   r.Method,
		"path":     r.URL.Path,
		"reason":   reason,
	})
}

// guarded - Reports whether a request creates a container or volume — the only
// two endpoints that can introduce a host bind mount. Paths are
// version-prefixed (e.g. /v1.45/containers/create), so match on the suffix.
func guarded(r *http.Request) bool {
	if r.Method != http.MethodPost {
		return false
	}
	p := r.URL.Path
	return strings.HasSuffix(p, "/containers/create") ||
		strings.HasSuffix(p, "/volumes/create")
}

// denyJSON - Answers 403 in docker's own error shape, so the client inside the
// jail prints the reason instead of an unmarshalling failure.
func denyJSON(w http.ResponseWriter, reason string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "azkaban docker filter: " + reason,
	})
}

// dangerousCaps are refused via --cap-add; each is a container->host escape path.
var dangerousCaps = map[string]bool{
	"SYS_ADMIN": true, "SYS_MODULE": true, "SYS_PTRACE": true,
	"SYS_RAWIO": true, "DAC_READ_SEARCH": true, "DAC_OVERRIDE": true,
	"MKNOD": true, "SYS_BOOT": true, "ALL": true,
}

// filterReason - Returns "" if the create request is allowed, else why it is
// not.
func filterReason(path string, body []byte, rootReal string) string {
	if strings.HasSuffix(path, "/volumes/create") {
		return volumeReason(body, rootReal)
	}
	return containerReason(body, rootReal)
}

// containerCreateBody - The subset of Docker's container-create body the
// filter has to understand. Only the fields that can hand out host access are
// modelled; the rest of the body is ignored, and a body that will not parse is
// refused rather than waved through. Written out as named types so the list of
// what is policed can be read on its own — it is the filter's threat model,
// and a field missing from here is a field nothing checks.
type containerCreateBody struct {
	HostConfig *containerHostConfig `json:"HostConfig"`
}

// containerHostConfig - The HostConfig fields that can escape the jail.
type containerHostConfig struct {
	Binds       []string          `json:"Binds"`
	Mounts      []containerMount  `json:"Mounts"`
	Privileged  bool              `json:"Privileged"`
	Devices     []json.RawMessage `json:"Devices"`
	CapAdd      []string          `json:"CapAdd"`
	SecurityOpt []string          `json:"SecurityOpt"`
	PidMode     string            `json:"PidMode"`
	IpcMode     string            `json:"IpcMode"`
	UsernsMode  string            `json:"UsernsMode"`
	NetworkMode string            `json:"NetworkMode"`
}

// containerMount - One --mount entry. VolumeOptions is modelled because a
// local-driver `device` option is a host bind mount in disguise.
type containerMount struct {
	Type          string               `json:"Type"`
	Source        string               `json:"Source"`
	VolumeOptions *containerVolumeOpts `json:"VolumeOptions"`
}

// containerVolumeOpts - The volume options of one --mount entry.
type containerVolumeOpts struct {
	DriverConfig *volumeDriverConfig `json:"DriverConfig"`
}

// volumeDriverConfig - A volume driver and its options, the pair that turns a
// Type=volume mount into a host bind.
type volumeDriverConfig struct {
	Name    string            `json:"Name"`
	Options map[string]string `json:"Options"`
}

// containerReason -Returns "" if a container-create body is allowed, else why
// it is not. Everything it refuses is a way out of the container and onto the
// host: --privileged, device passthrough, an escape-worthy capability, a
// stripped confinement layer, a shared namespace, or a bind of a host path
// outside the project dir.
//
// An unparsable body is refused, not waved through — a create request the
// filter cannot read is a create request it cannot vouch for.
func containerReason(body []byte, rootReal string) string {
	var b containerCreateBody
	if err := json.Unmarshal(body, &b); err != nil {
		return "unparsable container-create body"
	}
	h := b.HostConfig
	if h == nil {
		return ""
	}
	if reason := hostConfigReason(h); reason != "" {
		return reason
	}
	for _, bind := range h.Binds {
		if reason := bindReason(bind, rootReal); reason != "" {
			return reason
		}
	}
	for _, m := range h.Mounts {
		if strings.EqualFold(m.Type, "bind") && !pathWithin(m.Source, rootReal) {
			return "bind mount of host path outside the project dir: " + m.Source
		}
		// A `local`-driver volume with a `device` option is a host bind mount in
		// disguise (`--mount type=volume,volume-opt=type=none,volume-opt=o=bind,
		// volume-opt=device=/etc`). Docker performs it inline at container create
		// WITHOUT a /volumes/create call, so volumeReason never sees it. Apply the
		// same host-path check here, or a Type=volume mount smuggles /etc, /, ...
		if vo := m.VolumeOptions; vo != nil && vo.DriverConfig != nil {
			if reason := driverDeviceReason(vo.DriverConfig.Options, rootReal); reason != "" {
				return reason
			}
		}
	}
	return ""
}

// hostConfigReason - Returns "" if the HostConfig asks for no privilege that
// strips a confinement layer, else why it does. Split out because these need no
// host path to be an escape: the daemon grants them outright.
func hostConfigReason(h *containerHostConfig) string {
	if h.Privileged {
		return "--privileged is not allowed inside the jail"
	}
	if len(h.Devices) > 0 {
		return "host device passthrough (--device) is not allowed"
	}
	for _, c := range h.CapAdd {
		if dangerousCaps[strings.TrimPrefix(strings.ToUpper(c), "CAP_")] {
			return "--cap-add " + c + " is not allowed"
		}
	}
	// seccomp=unconfined / apparmor=unconfined / systempaths=unconfined /
	// label=disable each strip a layer the container relies on to stay contained.
	for _, so := range h.SecurityOpt {
		if l := strings.ToLower(so); strings.Contains(l, "unconfined") || strings.Contains(l, "disable") {
			return "--security-opt " + so + " is not allowed"
		}
	}
	// Every namespace the container can be made to SHARE with the host or with
	// another container is an escape from the jail's own unshare. Checked as one
	// table so a namespace added to HostConfig cannot be given a check that
	// differs from its four siblings. --net=host is the sharpest of them: it puts
	// the container on the host stack, which defeats --no-net and makes the
	// otherwise-harmless NET_ADMIN cap a host firewall/sniffing primitive.
	for _, ns := range []struct{ flag, mode string }{
		{"pid", h.PidMode},
		{"ipc", h.IpcMode},
		{"userns", h.UsernsMode},
		{"network", h.NetworkMode},
	} {
		if escapesNamespace(ns.mode) {
			return "--" + ns.flag + "=" + ns.mode + " is not allowed"
		}
	}
	return ""
}

// driverDeviceReason - Rejects a local-volume `device` opt that points at a
// host path outside the project dir. Shared by inline container mounts and
// /volumes/create, since both accept the same bind-in-disguise driver options.
func driverDeviceReason(opts map[string]string, rootReal string) string {
	dev := opts["device"]
	if strings.HasPrefix(dev, "/") && !pathWithin(dev, rootReal) {
		return "volume device outside the project dir: " + dev
	}
	return ""
}

// volumeReason - Returns "" if a volume-create body is allowed, else why it is
// not. Only the driver options matter here: a named volume is harmless, and the
// one dangerous shape is the local driver pointed at a host path.
func volumeReason(body []byte, rootReal string) string {
	var v struct {
		DriverOpts map[string]string `json:"DriverOpts"`
	}
	if err := json.Unmarshal(body, &v); err != nil {
		return "unparsable volume-create body"
	}
	// A local volume with a `device` opt is a host bind mount in disguise
	// (`--opt type=none --opt o=bind --opt device=/path`). Allow only within cwd.
	return driverDeviceReason(v.DriverOpts, rootReal)
}

// bindReason - Validates one HostConfig.Binds entry ("src:dst[:opts]"). Named
// volumes and anonymous volumes carry no host path and are allowed; a host path
// (absolute source) must resolve inside the project dir.
func bindReason(bind, rootReal string) string {
	src, _, ok := strings.Cut(bind, ":")
	if !ok {
		return "" // anonymous volume, no host source
	}
	if !strings.HasPrefix(src, "/") {
		return "" // named volume
	}
	if !pathWithin(src, rootReal) {
		return "bind mount of host path outside the project dir: " + src
	}
	return ""
}

// escapesNamespace - Reports namespace modes that leave the container's own
// namespace: "host", and "container:<id>" — which is transitive, since the
// target container may itself be running with host networking or host pid.
func escapesNamespace(mode string) bool {
	l := strings.ToLower(mode)
	return l == "host" || strings.HasPrefix(l, "container:")
}

// pathWithin - Reports whether p (after symlink resolution) is rootReal or
// lives under it. Resolving symlinks is essential: a symlink inside the project
// dir pointing at ~/.ssh must NOT be accepted as "within the project dir".
//
// KNOWN LIMITATION (TOCTOU): this resolves symlinks when the request is filtered,
// but dockerd performs the mount moments later. The jailed process owns cwd, so
// it can pass an in-cwd real path (accepted here) and then swap it for a symlink
// to /etc before dockerd mounts. Closing this fully requires the daemon to
// resolve under the project root (or O_NOFOLLOW-style checks) which the socket
// API does not expose; treat the proxy as raising the bar, not a hard boundary.
func pathWithin(p, rootReal string) bool {
	rp := realPath(p)
	return rp == rootReal || strings.HasPrefix(rp, rootReal+string(os.PathSeparator))
}

// realPath - Resolves symlinks even when the leaf does not exist yet (docker
// may create the bind source): it resolves the longest existing ancestor and
// rejoins the remainder, so a symlinked ancestor cannot smuggle a path out of
// the root.
func realPath(p string) string {
	p = filepath.Clean(p)
	if rp, err := filepath.EvalSymlinks(p); err == nil {
		return rp
	}
	dir := p
	for {
		parent := filepath.Dir(dir)
		if parent == dir {
			return p // reached root without an existing ancestor
		}
		if rp, err := filepath.EvalSymlinks(parent); err == nil {
			return filepath.Join(rp, p[len(parent):])
		}
		dir = parent
	}
}
