package main

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestDockerOwnershipListIsFiltered(t *testing.T) {
	ownership := &dockerOwnership{containers: map[string]string{"owned": "owned"}, execs: map[string]bool{}}
	request, err := http.NewRequest("GET", "http://docker/v1.45/containers/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	response := &http.Response{StatusCode: 200, Request: request, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`[{"Id":"owned"},{"Id":"external"}]`))}
	if err := ownership.record(response); err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != `[{"Id":"owned"}]` {
		t.Fatalf("unexpected list: %s", body)
	}
}
