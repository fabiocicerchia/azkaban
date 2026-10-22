package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
)

type dockerOwnership struct {
	mu         sync.Mutex
	containers map[string]string
	execs      map[string]bool
}

func dockerPath(path string) string {
	path = strings.TrimPrefix(path, "/")
	if segment, rest, found := strings.Cut(path, "/"); found && strings.HasPrefix(segment, "v") && strings.ContainsAny(segment, "0123456789") {
		return rest
	}
	return path
}

func (ownership *dockerOwnership) authorize(request *http.Request) string {
	ownership.mu.Lock()
	defer ownership.mu.Unlock()
	path := dockerPath(request.URL.Path)
	parts := strings.Split(path, "/")
	if parts[0] == "containers" {
		if len(parts) == 2 && ((parts[1] == "create" && request.Method == "POST") || (parts[1] == "json" && request.Method == "GET")) {
			return ""
		}
		if len(parts) < 2 {
			return "container endpoint requires an owned resource"
		}
		id := ownership.containers[parts[1]]
		if id == "" {
			return "container was not created by this jail"
		}
		if len(parts) > 3 {
			return "unmodelled container endpoint"
		}
		if len(parts) == 3 {
			allowed := map[string]bool{"json": true, "logs": true, "attach": true, "wait": true, "start": true, "stop": true, "kill": true, "restart": true, "pause": true, "unpause": true, "resize": true, "archive": true, "export": true, "top": true, "stats": true, "exec": true}
			if !allowed[parts[2]] {
				return "unmodelled container operation"
			}
		}
		prefix := strings.TrimSuffix(request.URL.Path, path)
		parts[1] = id
		request.URL.Path = prefix + strings.Join(parts, "/")
		request.URL.RawPath = ""
	}
	if parts[0] == "exec" && (len(parts) != 3 || !ownership.execs[parts[1]] || (parts[2] != "start" && parts[2] != "json" && parts[2] != "resize")) {
		return "exec session was not created by this jail"
	}
	if parts[0] == "commit" {
		id := ownership.containers[request.URL.Query().Get("container")]
		if id == "" {
			return "commit requires a container created by this jail"
		}
		query := request.URL.Query()
		query.Set("container", id)
		request.URL.RawQuery = query.Encode()
	}
	return ""
}

func (ownership *dockerOwnership) record(response *http.Response) error {
	path := dockerPath(response.Request.URL.Path)
	createContainer := path == "containers/create" && response.Request.Method == "POST"
	createExec := strings.HasPrefix(path, "containers/") && strings.HasSuffix(path, "/exec") && response.Request.Method == "POST"
	list := path == "containers/json" && response.Request.Method == "GET"
	if response.StatusCode < 200 || response.StatusCode >= 300 || (!createContainer && !createExec && !list) {
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxCreateBody+1))
	response.Body.Close()
	if err != nil {
		return err
	}
	if len(body) > maxCreateBody {
		return fmt.Errorf("docker resource response exceeds limit")
	}
	ownership.mu.Lock()
	defer ownership.mu.Unlock()
	if list {
		var containers []json.RawMessage
		if err := json.Unmarshal(body, &containers); err != nil {
			return err
		}
		owned := []json.RawMessage{}
		for _, container := range containers {
			var value struct {
				ID string `json:"Id"`
			}
			if err := json.Unmarshal(container, &value); err != nil {
				return err
			}
			if ownership.containers[value.ID] == value.ID && value.ID != "" {
				owned = append(owned, container)
			}
		}
		body, err = json.Marshal(owned)
		if err != nil {
			return err
		}
	} else {
		var value struct {
			ID string `json:"Id"`
		}
		if err := json.Unmarshal(body, &value); err != nil {
			return err
		}
		if value.ID == "" {
			return fmt.Errorf("docker create returned no resource ID")
		}
		if createContainer {
			ownership.containers[value.ID] = value.ID
			if name := response.Request.URL.Query().Get("name"); name != "" {
				ownership.containers[name] = value.ID
			}
		} else {
			ownership.execs[value.ID] = true
		}
	}
	response.Body = io.NopCloser(bytes.NewReader(body))
	response.ContentLength = int64(len(body))
	response.Header.Set("Content-Length", fmt.Sprint(len(body)))
	return nil
}
