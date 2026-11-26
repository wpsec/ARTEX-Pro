package server

import (
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWorkspaceSymlinkCannotAccessOutsideRoot(t *testing.T) {
	base := t.TempDir()
	workspace := filepath.Join(base, "workspace")
	outside := filepath.Join(base, "outside")
	if err := os.MkdirAll(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	marker := "workspace symlink boundary fixture"
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte(marker), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(workspace, "external")); err != nil {
		t.Fatal(err)
	}
	s := &Server{m: &Manager{dir: workspace}}

	read := httptest.NewRecorder()
	s.wsRead(read, httptest.NewRequest("GET", "/api/workspace/read?path="+url.QueryEscape("external/secret.txt"), nil))
	if read.Code == 200 || strings.Contains(read.Body.String(), marker) {
		t.Fatalf("workspace read crossed symlink boundary: status=%d body=%s", read.Code, read.Body.String())
	}

	write := httptest.NewRecorder()
	s.wsWrite(write, httptest.NewRequest("POST", "/api/workspace/write", strings.NewReader(`{"path":"external/created.txt","content":"outside write"}`)))
	if _, err := os.Stat(filepath.Join(outside, "created.txt")); !os.IsNotExist(err) {
		t.Fatalf("workspace write created a file outside the root: err=%v", err)
	}
}
