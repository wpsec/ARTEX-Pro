package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wpsec/ARTEX-local/db"
)

type cyberspaceRoundTripFunc func(*http.Request) (*http.Response, error)

func (f cyberspaceRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestCyberspaceAccountProbe(t *testing.T) {
	const fixtureKey = "synthetic-fixture"
	cases := []struct {
		id, path, header, query, body, account string
	}{
		{id: "fofa", path: "/api/v1/info/my", query: "key", body: `{"error":false,"fofa_point":0}`},
		{id: "shodan", path: "/api-info", query: "key", body: `{"plan":"example","query_credits":0}`},
		{id: "zoomeye", path: "/v2/userinfo", header: "API-KEY", body: `{"code":60000,"data":{"subscription":{}}}`},
		{id: "quake_360", path: "/api/v3/user/info", header: "X-QuakeToken", body: `{"code":0,"data":{"id":"fixture"}}`},
		{id: "virustotal", path: "/api/v3/users/synthetic-user", header: "x-apikey", account: "synthetic-user", body: `{"data":{"type":"user","id":"synthetic-user"}}`},
		{id: "securitytrails", path: "/v1/ping", header: "APIKEY", body: `{"success":true}`},
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			provider, ok := cyberspaceProviderByID(tc.id)
			if !ok {
				t.Fatal("provider missing")
			}
			client := newCyberspaceProbeClient()
			client.Transport = cyberspaceRoundTripFunc(func(req *http.Request) (*http.Response, error) {
				if req.URL.Scheme != "https" || req.URL.Path != tc.path || req.Body != nil {
					t.Fatal("expected a provider account request")
				}
				if tc.id == "zoomeye" && req.Method != http.MethodPost || tc.id != "zoomeye" && req.Method != http.MethodGet {
					t.Fatal("unexpected request method")
				}
				if tc.header != "" && (req.Header.Get(tc.header) != fixtureKey || req.URL.RawQuery != "") {
					t.Fatal("expected credential only in the documented header")
				}
				if tc.query != "" && (req.URL.Query().Get(tc.query) != fixtureKey || len(req.URL.Query()) != 1) {
					t.Fatal("expected a query containing only the credential")
				}
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(tc.body))}, nil
			})
			if status, reason := probeCyberspaceProvider(t.Context(), client, provider, fixtureKey, tc.account); status != "passed" || reason != "" {
				t.Fatalf("status=%s reason=%s", status, reason)
			}
		})
	}
}

func TestCyberspaceProbeRejectsUnsafeOrInvalidResponses(t *testing.T) {
	provider, _ := cyberspaceProviderByID("fofa")
	for _, tc := range []struct {
		code   int
		body   string
		reason string
	}{
		{http.StatusFound, "", "request_rejected"},
		{http.StatusUnauthorized, "", "invalid_credential"},
		{http.StatusForbidden, "", "access_denied"},
		{http.StatusTooManyRequests, "", "rate_limited"},
		{http.StatusServiceUnavailable, "", "provider_unavailable"},
		{http.StatusOK, `{"error":true,"errmsg":"synthetic error with fixture secret"}`, "request_rejected"},
		{http.StatusOK, `{"error":false}`, "invalid_response"},
		{http.StatusOK, strings.Repeat(" ", cyberspaceProbeLimit+1), "invalid_response"},
	} {
		t.Run(tc.reason, func(t *testing.T) {
			client := newCyberspaceProbeClient()
			count := 0
			client.Transport = cyberspaceRoundTripFunc(func(req *http.Request) (*http.Response, error) {
				count++
				return &http.Response{
					StatusCode: tc.code,
					Header:     http.Header{"Location": []string{"https://example.invalid"}},
					Body:       io.NopCloser(strings.NewReader(tc.body)),
				}, nil
			})
			status, reason := probeCyberspaceProvider(t.Context(), client, provider, "synthetic-fixture", "")
			if status != "failed" || reason != tc.reason || count != 1 {
				t.Fatalf("status=%s reason=%s requests=%d", status, reason, count)
			}
		})
	}
	client := newCyberspaceProbeClient()
	client.Transport = cyberspaceRoundTripFunc(func(_ *http.Request) (*http.Response, error) {
		return nil, context.DeadlineExceeded
	})
	if _, reason := probeCyberspaceProvider(t.Context(), client, provider, "synthetic-fixture", ""); reason != "timeout" {
		t.Fatalf("reason=%s", reason)
	}
	for _, id := range []string{"hunter_qax", "hunter_how", "chaos", "virustotal"} {
		p, _ := cyberspaceProviderByID(id)
		client.Transport = cyberspaceRoundTripFunc(func(_ *http.Request) (*http.Response, error) {
			t.Fatal("unverified provider attempted a request")
			return nil, errors.New("unexpected request")
		})
		if status, _ := probeCyberspaceProvider(t.Context(), client, p, "synthetic-fixture", ""); status != "unverified" {
			t.Fatalf("%s status=%s", id, status)
		}
	}
}

func TestCyberspaceConfigKeepsSecretsWriteOnly(t *testing.T) {
	c := newCyberspaceSearch(nil, t.TempDir())
	p, _ := cyberspaceProviderByID("virustotal")
	initial := cyberspaceConfig{Enabled: true}
	saved, err := c.updatedConfig(p.id, initial, cyberspaceConfigUpdate{
		Enabled: true, APIKey: "synthetic-fixture", AccountID: "synthetic-user",
	})
	if err != nil || saved.Revision != 1 || saved.Key == "" || saved.Account == "" {
		t.Fatal("credentials were not saved")
	}
	if info, err := os.Stat(c.keyPath); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatal("wrapping key permissions are not private")
	}
	stored, err := json.Marshal(saved)
	if err != nil || strings.Contains(string(stored), "synthetic-") {
		t.Fatal("plaintext credential was serialized")
	}
	published, err := json.Marshal(p.dto(saved))
	if err != nil || strings.Contains(string(published), saved.Key) || strings.Contains(string(published), saved.Account) ||
		strings.Contains(string(published), "synthetic-") || !strings.Contains(string(published), `"configured":true`) {
		t.Fatal("credential data leaked into the response or configuration status was lost")
	}
	reopened := newCyberspaceSearch(nil, filepath.Dir(c.keyPath))
	key, account, err := reopened.openCredentials(p.id, saved)
	if err != nil || key != "synthetic-fixture" || account != "synthetic-user" {
		t.Fatal("persisted credentials could not be reopened")
	}
	if _, _, err := reopened.openCredentials("shodan", saved); err == nil {
		t.Fatal("ciphertext was accepted for a different provider")
	}
	saved.Test = &cyberspaceTest{Status: "passed"}
	edited, err := c.updatedConfig(p.id, saved, cyberspaceConfigUpdate{Enabled: false})
	if err != nil || edited.Test != nil || edited.Key != saved.Key || edited.Revision != 2 {
		t.Fatal("disabling must preserve the credential and invalidate the test")
	}
	cleared, err := c.updatedConfig(p.id, edited, cyberspaceConfigUpdate{Clear: true})
	if err != nil || cleared.Key != "" || cleared.Account != "" || cleared.Revision != 3 {
		t.Fatal("clear did not remove the stored credentials")
	}
}

func TestCyberspaceRoutesRequireAuthentication(t *testing.T) {
	handler := (&Server{m: &Manager{}}).Handler()
	for _, route := range []struct{ method, path string }{
		{"GET", "/api/cyberspace-search/providers"},
		{"PUT", "/api/cyberspace-search/providers/fofa"},
		{"POST", "/api/cyberspace-search/test"},
	} {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(route.method, route.path, nil))
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("%s %s returned %d", route.method, route.path, w.Code)
		}
	}
}

func TestCyberspacePostgresBatchAndRotation(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skip("test PostgreSQL not configured")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Skip("test PostgreSQL unavailable")
	}
	defer pg.Close()
	ids := []string{"shodan", "zoomeye", "hunter_how"}
	for _, provider := range cyberspaceProviders {
		_, exists, err := pg.GetSetting("cyberspace_search." + provider.id)
		if err != nil {
			t.Fatal(err)
		}
		if exists {
			t.Skip("test requires an isolated PostgreSQL without provider settings")
		}
	}
	defer func() {
		for _, id := range ids {
			if _, err := pg.Exec(`DELETE FROM settings WHERE key=$1`, "cyberspace_search."+id); err != nil {
				t.Error(err)
			}
		}
	}()
	ctx, cancel := context.WithCancel(t.Context())
	s := &Server{ctx: ctx, cancel: cancel, cyberspace: newCyberspaceSearch(pg, t.TempDir())}
	defer s.Close()
	oldProbeStarted := make(chan struct{}, 1)
	releaseOldProbe := make(chan struct{})
	s.cyberspace.client.Transport = cyberspaceRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch req.URL.Host {
		case "api.shodan.io":
			oldProbeStarted <- struct{}{}
			select {
			case <-releaseOldProbe:
			case <-req.Context().Done():
				return nil, req.Context().Err()
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{"plan":"fixture"}`)),
			}, nil
		case "api.zoomeye.ai":
			return &http.Response{StatusCode: http.StatusForbidden, Body: http.NoBody}, nil
		default:
			t.Error("unexpected outbound request")
			return nil, errors.New("unexpected request")
		}
	})

	save := func(id, body string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(http.MethodPut, "/", strings.NewReader(body))
		r.SetPathValue("provider", id)
		w := httptest.NewRecorder()
		s.saveCyberspaceSearch(w, r)
		return w
	}
	for _, id := range ids {
		w := save(id, `{"revision":0,"enabled":true,"api_key":"synthetic-old"}`)
		if w.Code != http.StatusOK || strings.Contains(w.Body.String(), "synthetic-old") {
			t.Fatalf("%s save status=%d", id, w.Code)
		}
	}
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		w := httptest.NewRecorder()
		s.testCyberspaceSearch(w, httptest.NewRequest(http.MethodPost, "/", nil))
		done <- w
	}()
	select {
	case <-oldProbeStarted:
	case <-time.After(3 * time.Second):
		t.Fatal("account check did not reach the mocked transport")
	}
	if w := save("shodan", `{"revision":1,"enabled":true,"api_key":"synthetic-new"}`); w.Code != http.StatusOK {
		t.Fatalf("rotation status=%d", w.Code)
	}
	if w := save("shodan", `{"revision":1,"enabled":false}`); w.Code != http.StatusConflict {
		t.Fatalf("stale config update status=%d", w.Code)
	}
	close(releaseOldProbe)

	select {
	case w := <-done:
		var result struct {
			Providers []cyberspaceProviderDTO `json:"providers"`
		}
		if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &result) != nil || len(result.Providers) != 9 {
			t.Fatalf("unexpected batch result status=%d", w.Code)
		}
		for _, p := range result.Providers {
			switch p.ID {
			case "shodan":
				if p.Test != nil || !p.Configured || p.Revision != 2 {
					t.Fatal("a stale result overrode the rotated credential")
				}
			case "zoomeye":
				if p.Test == nil || p.Test.Status != "failed" || p.Test.Reason != "access_denied" {
					t.Fatal("provider permission failure was not recorded")
				}
			case "hunter_how":
				if p.Test == nil || p.Test.Status != "unverified" {
					t.Fatal("provider without independent authentication was marked verified")
				}
			}
		}
	case <-time.After(3 * time.Second):
		t.Fatal("batch did not return")
	}
	restarted := newCyberspaceSearch(pg, filepath.Dir(s.cyberspace.keyPath))
	config, stored, err := restarted.read("shodan")
	if err != nil || strings.Contains(stored, "synthetic-new") {
		t.Fatal("config failed to load or plaintext credential was stored")
	}
	key, _, err := restarted.openCredentials("shodan", config)
	if err != nil || key != "synthetic-new" {
		t.Fatal("rotated credential did not survive reopening the storage")
	}
	if w := save("shodan", `{"revision":2,"enabled":true,"clear":true}`); w.Code != http.StatusOK {
		t.Fatalf("clear status=%d", w.Code)
	}
	config, _, err = restarted.read("shodan")
	if err != nil || config.Key != "" {
		t.Fatal("cleared credential was still stored")
	}
}
