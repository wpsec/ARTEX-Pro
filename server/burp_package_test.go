package server

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/wpsec/ARTEX-local/db"
)

func TestBurpReplayRequestReframesCapturedPacketAndKeepsHeaders(t *testing.T) {
	body := []byte("payload")
	snapshot := db.TrafficEvidenceSnapshot{
		URL:     "https://app.example.test/submit",
		ReqHead: "POST /submit HTTP/2.0\nAuthorization: Bearer session-secret\nCookie: sid=cookie-secret\nTransfer-Encoding: chunked\nContent-Type: application/octet-stream",
	}
	packet, hostAdded, err := burpReplayRequest(snapshot, body)
	if err != nil {
		t.Fatal(err)
	}
	text := string(packet)
	for _, want := range []string{
		"POST /submit HTTP/1.1\r\n",
		"Host: app.example.test\r\n",
		"Authorization: Bearer session-secret\r\n",
		"Cookie: sid=cookie-secret\r\n",
		"Content-Length: 7\r\n",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("packet is missing %q: %q", want, text)
		}
	}
	if !hostAdded || strings.Contains(text, "Transfer-Encoding:") || !bytes.HasSuffix(packet, body) {
		t.Fatalf("request was not framed as a replayable HTTP/1.1 packet: hostAdded=%t packet=%q", hostAdded, text)
	}
}

func TestBurpPackageArchiveKeepsCapturedCredentialsAndBodies(t *testing.T) {
	requestBody := []byte(`{"token":"session-secret"}`)
	responseBody := []byte{0, 0x7f, 'o', 'k'}
	snapshot := db.TrafficEvidenceSnapshot{
		SourceTrafficID: "source-1",
		URL:             "https://app.example.test/private",
		Method:          "POST",
		Status:          200,
		ReqHead:         "POST /private HTTP/1.1\nHost: app.example.test\nAuthorization: Bearer session-secret\nCookie: sid=cookie-secret\nContent-Type: application/json\nContent-Length: 1",
		RespHead:        "HTTP 200\nSet-Cookie: sid=response-secret\nContent-Length: 1",
	}
	exchanges := []burpPackageExchange{{
		Binding: db.FindingTrafficBinding{
			ID:        42,
			FindingID: 9,
			Role:      "proof",
			Snapshot:  snapshot,
		},
		RequestBody:  requestBody,
		ResponseBody: responseBody,
	}}
	archiveBytes, err := buildBurpReproductionArchive(3, exchanges)
	if err != nil {
		t.Fatal(err)
	}
	archive, err := zip.NewReader(bytes.NewReader(archiveBytes), int64(len(archiveBytes)))
	if err != nil {
		t.Fatal(err)
	}
	files := make(map[string][]byte, len(archive.File))
	for _, file := range archive.File {
		reader, err := file.Open()
		if err != nil {
			t.Fatal(err)
		}
		contents, readErr := io.ReadAll(reader)
		closeErr := reader.Close()
		if readErr != nil || closeErr != nil {
			t.Fatalf("read %s: %v", file.Name, errors.Join(readErr, closeErr))
		}
		files[file.Name] = contents
	}
	request := files["requests/001-binding-42-request.http"]
	if !bytes.Contains(request, []byte("Authorization: Bearer session-secret")) ||
		!bytes.Contains(request, []byte("Cookie: sid=cookie-secret")) ||
		!bytes.Contains(request, requestBody) || bytes.Contains(request, []byte("[REDACTED]")) {
		t.Fatalf("Burp request did not preserve captured values: %q", request)
	}
	response := files["responses/001-binding-42-response.http"]
	if !bytes.Contains(response, []byte("Set-Cookie: sid=response-secret")) || !bytes.HasSuffix(response, responseBody) {
		t.Fatalf("response evidence did not preserve captured values and bytes: %q", response)
	}
	var manifest burpPackageManifest
	if err := json.Unmarshal(files["manifest.json"], &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.EvidenceVersion != 3 || len(manifest.Entries) != 1 || manifest.Entries[0].BindingID != 42 ||
		manifest.Entries[0].RequestBodySHA256 != burpBodySHA256(requestBody) {
		t.Fatalf("package manifest does not describe the exported evidence: %+v", manifest)
	}
	if !bytes.Contains(files["README.txt"], []byte("不做脱敏")) || !bytes.Contains(files["README.txt"], []byte("Burp Suite Repeater")) {
		t.Fatalf("package usage and retention notes are missing: %q", files["README.txt"])
	}
}
