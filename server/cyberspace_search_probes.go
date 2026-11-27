package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

const cyberspaceProbeLimit = 128 << 10

type cyberspaceProvider struct {
	id, name, credential string
	endpoint, method     string
	header, queryKey     string
	accountID            bool
}

var cyberspaceProviders = []cyberspaceProvider{
	{id: "fofa", name: "FOFA", credential: "API Key", endpoint: "https://fofa.info/api/v1/info/my", queryKey: "key"},
	{id: "hunter_qax", name: "奇安信鹰图", credential: "API Key"},
	{id: "hunter_how", name: "hunter.how", credential: "API Key"},
	{id: "shodan", name: "Shodan", credential: "API Key", endpoint: "https://api.shodan.io/api-info", queryKey: "key"},
	{id: "zoomeye", name: "ZoomEye", credential: "API Key", endpoint: "https://api.zoomeye.ai/v2/userinfo", method: http.MethodPost, header: "API-KEY"},
	{id: "quake_360", name: "360 Quake", credential: "API Token", endpoint: "https://quake.360.net/api/v3/user/info", header: "X-QuakeToken"},
	{id: "virustotal", name: "VirusTotal", credential: "API Key", endpoint: "https://www.virustotal.com/api/v3/users/", header: "x-apikey", accountID: true},
	{id: "chaos", name: "ProjectDiscovery Chaos", credential: "API Key"},
	{id: "securitytrails", name: "SecurityTrails", credential: "API Key", endpoint: "https://api.securitytrails.com/v1/ping", header: "APIKEY"},
}

func cyberspaceProviderByID(id string) (cyberspaceProvider, bool) {
	for _, provider := range cyberspaceProviders {
		if provider.id == id {
			return provider, true
		}
	}
	return cyberspaceProvider{}, false
}

func newCyberspaceProbeClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	// Requests can carry credentials in their URL. Use the fixed provider host directly.
	transport.Proxy = nil
	return &http.Client{
		Transport: transport,
		Timeout:   5 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func probeCyberspaceProvider(ctx context.Context, client *http.Client, provider cyberspaceProvider, key, account string) (status, reason string) {
	if provider.endpoint == "" {
		return "unverified", "probe_unavailable"
	}
	if provider.accountID && account == "" {
		return "unverified", "account_required"
	}
	endpoint := provider.endpoint
	if provider.accountID {
		endpoint += url.PathEscape(account)
	}
	req, err := http.NewRequestWithContext(ctx, provider.method, endpoint, nil)
	if err != nil {
		return "failed", "probe_error"
	}
	req.Header.Set("Accept", "application/json")
	if provider.queryKey != "" {
		query := req.URL.Query()
		query.Set(provider.queryKey, key)
		req.URL.RawQuery = query.Encode()
	}
	if provider.header != "" {
		req.Header.Set(provider.header, key)
	}

	res, err := client.Do(req)
	if err != nil {
		var timeout net.Error
		if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &timeout) && timeout.Timeout()) {
			return "failed", "timeout"
		}
		return "failed", "network_error"
	}
	defer res.Body.Close()
	switch {
	case res.StatusCode == http.StatusUnauthorized:
		return "failed", "invalid_credential"
	case res.StatusCode == http.StatusForbidden || res.StatusCode == http.StatusPaymentRequired:
		return "failed", "access_denied"
	case res.StatusCode == http.StatusTooManyRequests:
		return "failed", "rate_limited"
	case res.StatusCode == http.StatusNotFound && provider.accountID:
		return "failed", "account_not_found"
	case res.StatusCode >= 500:
		return "failed", "provider_unavailable"
	case res.StatusCode != http.StatusOK:
		return "failed", "request_rejected"
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, cyberspaceProbeLimit+1))
	if err != nil {
		var timeout net.Error
		if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &timeout) && timeout.Timeout()) {
			return "failed", "timeout"
		}
		return "failed", "network_error"
	}
	var payload map[string]json.RawMessage
	if len(body) > cyberspaceProbeLimit || json.Unmarshal(body, &payload) != nil {
		return "failed", "invalid_response"
	}
	return cyberspaceProbeResult(provider.id, payload)
}

func cyberspaceProbeResult(id string, payload map[string]json.RawMessage) (status, reason string) {
	switch id {
	case "fofa":
		var rejected *bool
		if json.Unmarshal(payload["error"], &rejected) == nil && rejected != nil {
			if *rejected {
				return "failed", "request_rejected"
			}
			if len(payload["isvip"]) > 0 || len(payload["fofa_point"]) > 0 || len(payload["remain_api_query"]) > 0 {
				return "passed", ""
			}
		}
	case "zoomeye", "quake_360":
		var code *int
		if json.Unmarshal(payload["code"], &code) == nil && code != nil {
			if (id == "zoomeye" && *code != 60000) || (id == "quake_360" && *code != 0) {
				return "failed", "request_rejected"
			}
			var data map[string]json.RawMessage
			if json.Unmarshal(payload["data"], &data) == nil && len(data) > 0 {
				return "passed", ""
			}
		}
	case "shodan":
		var plan string
		if json.Unmarshal(payload["plan"], &plan) == nil && plan != "" && len(payload["error"]) == 0 {
			return "passed", ""
		}
	case "virustotal":
		var data struct {
			ID   string `json:"id"`
			Type string `json:"type"`
		}
		if json.Unmarshal(payload["data"], &data) == nil && data.Type == "user" && data.ID != "" {
			return "passed", ""
		}
	case "securitytrails":
		var success bool
		if json.Unmarshal(payload["success"], &success) == nil && success {
			return "passed", ""
		}
	}
	return "failed", "invalid_response"
}
