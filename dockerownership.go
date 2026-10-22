package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

type dockerOwnership struct {
	mu         sync.Mutex
	containers map[string]string
	execs      map[string]bool
	// inspect asks the daemon which full ID a reference (short ID, generated
	// name) means; nil leaves only exact recorded references resolvable.
	inspect func(ctx context.Context, ref string) string
}

func dockerPath(path string) string {
	path = strings.TrimPrefix(path, "/")
	segment, rest, found := strings.Cut(path, "/")
	if found && strings.HasPrefix(segment, "v") && strings.ContainsAny(segment, "0123456789") {
		return rest
	}
	return path
}

// resolve - The owned full ID a container reference names, or "".
func (ownership *dockerOwnership) resolve(ctx context.Context, ref string) string {
	ownership.mu.Lock()
	id := ownership.containers[ref]
	ownership.mu.Unlock()
	if id != "" || ref == "" || ownership.inspect == nil {
		return id
	}
	full := ownership.inspect(ctx, ref)
	ownership.mu.Lock()
	defer ownership.mu.Unlock()
	if full != "" && ownership.containers[full] == full {
		return full
	}
	return ""
}

func (ownership *dockerOwnership) ownsExec(id string) bool {
	ownership.mu.Lock()
	defer ownership.mu.Unlock()
	return ownership.execs[id]
}

func (ownership *dockerOwnership) authorize(request *http.Request) string {
	path := dockerPath(request.URL.Path)
	parts := strings.Split(path, "/")
	if parts[0] == "containers" {
		creating := len(parts) == 2 && parts[1] == "create" && request.Method == http.MethodPost
		listing := len(parts) == 2 && parts[1] == "json" && request.Method == http.MethodGet
		if creating || listing {
			return ""
		}
		if len(parts) < 2 {
			return "container endpoint requires an owned resource"
		}
		if len(parts) > 3 {
			return "unmodelled container endpoint"
		}
		if len(parts) == 3 {
			allowed := map[string]bool{
				"json": true, "logs": true, "attach": true, "wait": true,
				"start": true, "stop": true, "kill": true, "restart": true,
				"pause": true, "unpause": true, "resize": true, "archive": true,
				"export": true, "top": true, "stats": true, "exec": true,
			}
			if !allowed[parts[2]] {
				return "unmodelled container operation"
			}
		}
		id := ownership.resolve(request.Context(), parts[1])
		if id == "" {
			return "container was not created by this jail"
		}
		prefix := strings.TrimSuffix(request.URL.Path, path)
		parts[1] = id
		request.URL.Path = prefix + strings.Join(parts, "/")
		request.URL.RawPath = ""
	}
	if parts[0] == "exec" {
		if len(parts) != 3 || !ownership.ownsExec(parts[1]) {
			return "exec session was not created by this jail"
		}
		if parts[2] != "start" && parts[2] != "json" && parts[2] != "resize" {
			return "unmodelled exec operation"
		}
	}
	if parts[0] == "commit" {
		id := ownership.resolve(request.Context(), request.URL.Query().Get("container"))
		if id == "" {
			return "commit requires a container created by this jail"
		}
		query := request.URL.Query()
		query.Set("container", id)
		request.URL.RawQuery = query.Encode()
	}
	return ""
}

// daemonInspect - Builds the inspect lookup over the daemon's own client.
func daemonInspect(client *http.Client) func(context.Context, string) string {
	return func(ctx context.Context, ref string) string {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet,
			"http://docker/containers/"+url.PathEscape(ref)+"/json", http.NoBody)
		if err != nil {
			return ""
		}
		resp, err := client.Do(req)
		if err != nil {
			return ""
		}
		defer resp.Body.Close() //nolint:errcheck // read-only lookup; a failed close costs a pooled connection
		var value struct {
			ID string `json:"Id"`
		}
		if resp.StatusCode != http.StatusOK ||
			json.NewDecoder(io.LimitReader(resp.Body, maxCreateBody)).Decode(&value) != nil {
			return ""
		}
		return value.ID
	}
}

// filterList - Streams a container list and keeps only owned entries, so a
// host with thousands of containers is never buffered whole.
func (ownership *dockerOwnership) filterList(body io.Reader) ([]byte, error) {
	decoder := json.NewDecoder(body)
	if _, err := decoder.Token(); err != nil {
		return nil, err
	}
	owned := []json.RawMessage{}
	for decoder.More() {
		var container json.RawMessage
		if err := decoder.Decode(&container); err != nil {
			return nil, err
		}
		var value struct {
			ID string `json:"Id"`
		}
		if err := json.Unmarshal(container, &value); err != nil {
			return nil, err
		}
		ownership.mu.Lock()
		mine := value.ID != "" && ownership.containers[value.ID] == value.ID
		ownership.mu.Unlock()
		if mine {
			owned = append(owned, container)
		}
	}
	return json.Marshal(owned)
}

func (ownership *dockerOwnership) record(response *http.Response) error {
	path := dockerPath(response.Request.URL.Path)
	createContainer := path == "containers/create" && response.Request.Method == http.MethodPost
	createExec := strings.HasPrefix(path, "containers/") && strings.HasSuffix(path, "/exec") &&
		response.Request.Method == http.MethodPost
	list := path == "containers/json" && response.Request.Method == http.MethodGet
	if response.StatusCode < 200 || response.StatusCode >= 300 || (!createContainer && !createExec && !list) {
		return nil
	}
	var body []byte
	var err error
	if list {
		body, err = ownership.filterList(response.Body)
	} else {
		body, err = io.ReadAll(io.LimitReader(response.Body, maxCreateBody+1))
	}
	closeErr := response.Body.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if len(body) > maxCreateBody {
		return fmt.Errorf("docker resource response exceeds limit")
	}
	if !list {
		var value struct {
			ID string `json:"Id"`
		}
		if err := json.Unmarshal(body, &value); err != nil {
			return err
		}
		if value.ID == "" {
			return fmt.Errorf("docker create returned no resource ID")
		}
		ownership.mu.Lock()
		if createContainer {
			ownership.containers[value.ID] = value.ID
			if name := response.Request.URL.Query().Get("name"); name != "" {
				ownership.containers[name] = value.ID
			}
		} else {
			ownership.execs[value.ID] = true
		}
		ownership.mu.Unlock()
	}
	response.Body = io.NopCloser(bytes.NewReader(body))
	response.ContentLength = int64(len(body))
	response.Header.Set("Content-Length", fmt.Sprint(len(body)))
	return nil
}
