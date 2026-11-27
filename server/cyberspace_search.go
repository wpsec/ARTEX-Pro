package server

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/wpsec/ARTEX-local/db"
)

type cyberspaceSearch struct {
	db      *db.DB
	keyPath string
	client  *http.Client
	mu      sync.Mutex
	batch   *cyberspaceBatch
}

type cyberspaceBatch struct {
	done   chan struct{}
	failed bool
}

type cyberspaceTest struct {
	Status   string    `json:"status"`
	Reason   string    `json:"reason,omitempty"`
	TestedAt time.Time `json:"tested_at"`
}

type cyberspaceConfig struct {
	Enabled  bool            `json:"enabled"`
	Revision uint64          `json:"revision"`
	Key      string          `json:"encrypted_key,omitempty"`
	Account  string          `json:"encrypted_account,omitempty"`
	Test     *cyberspaceTest `json:"test,omitempty"`
}

type cyberspaceProviderDTO struct {
	ID             string          `json:"id"`
	Name           string          `json:"name"`
	Credential     string          `json:"credential"`
	NeedsAccountID bool            `json:"needs_account_id"`
	Configured     bool            `json:"configured"`
	AccountIDSet   bool            `json:"account_id_set"`
	Enabled        bool            `json:"enabled"`
	Revision       uint64          `json:"revision"`
	Test           *cyberspaceTest `json:"test,omitempty"`
}

type cyberspaceConfigUpdate struct {
	Revision  *uint64 `json:"revision"`
	Enabled   bool    `json:"enabled"`
	APIKey    string  `json:"api_key"`
	AccountID string  `json:"account_id"`
	Clear     bool    `json:"clear"`
}

var cyberspaceAccountID = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._@-]{0,127}$`)

func newCyberspaceSearch(pg *db.DB, dataDir string) *cyberspaceSearch {
	return &cyberspaceSearch{
		db: pg, keyPath: filepath.Join(dataDir, "cyberspace-search.key"), client: newCyberspaceProbeClient(),
	}
}

func (p cyberspaceProvider) dto(config cyberspaceConfig) cyberspaceProviderDTO {
	return cyberspaceProviderDTO{
		ID: p.id, Name: p.name, Credential: p.credential, NeedsAccountID: p.accountID,
		Configured: config.Key != "", AccountIDSet: config.Account != "", Enabled: config.Enabled,
		Revision: config.Revision, Test: config.Test,
	}
}

func (c *cyberspaceSearch) read(id string) (config cyberspaceConfig, raw string, err error) {
	raw, exists, err := c.db.GetSetting("cyberspace_search." + id)
	if err != nil {
		return config, "", err
	}
	config.Enabled = true
	if exists {
		if raw == "" || json.Unmarshal([]byte(raw), &config) != nil || config.Revision == 0 {
			return config, "", fmt.Errorf("invalid cyberspace search configuration")
		}
	}
	return config, raw, nil
}

func (c *cyberspaceSearch) write(id, previous string, config cyberspaceConfig) (bool, error) {
	next, err := json.Marshal(config)
	if err != nil {
		return false, err
	}
	key := "cyberspace_search." + id
	if previous == "" {
		return c.db.InsertSettingIfAbsent(key, string(next))
	}
	return c.db.ReplaceSettingIfUnchanged(key, previous, string(next))
}

func (s *Server) listCyberspaceSearch(w http.ResponseWriter, _ *http.Request) {
	if s.cyberspace == nil || s.cyberspace.db == nil {
		writeErr(w, http.StatusServiceUnavailable, "搜索引擎配置库不可用")
		return
	}
	s.cyberspace.writeList(w)
}

func (c *cyberspaceSearch) writeList(w http.ResponseWriter) {
	providers := make([]cyberspaceProviderDTO, 0, len(cyberspaceProviders))
	for _, p := range cyberspaceProviders {
		config, _, err := c.read(p.id)
		if err != nil {
			writeErr(w, http.StatusServiceUnavailable, "读取搜索引擎配置失败")
			return
		}
		providers = append(providers, p.dto(config))
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"providers": providers})
}

func (s *Server) saveCyberspaceSearch(w http.ResponseWriter, r *http.Request) {
	c := s.cyberspace
	if c == nil || c.db == nil {
		writeErr(w, http.StatusServiceUnavailable, "搜索引擎配置库不可用")
		return
	}
	p, ok := cyberspaceProviderByID(r.PathValue("provider"))
	if !ok {
		writeErr(w, http.StatusNotFound, "搜索引擎不存在")
		return
	}
	var req cyberspaceConfigUpdate
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&req) != nil || decoder.Decode(new(any)) != io.EOF || req.Revision == nil {
		writeErr(w, http.StatusBadRequest, "配置请求无效")
		return
	}
	req.APIKey = strings.TrimSpace(req.APIKey)
	req.AccountID = strings.TrimSpace(req.AccountID)
	if len(req.APIKey) > 2048 || strings.ContainsFunc(req.APIKey, func(r rune) bool { return r < '!' || r > '~' }) {
		writeErr(w, http.StatusBadRequest, "凭据格式无效")
		return
	}
	if req.AccountID != "" && (!p.accountID || !cyberspaceAccountID.MatchString(req.AccountID) || req.AccountID == req.APIKey) {
		writeErr(w, http.StatusBadRequest, "用户 ID 格式无效，请填写账户标识")
		return
	}
	if req.Clear && (req.APIKey != "" || req.AccountID != "") {
		writeErr(w, http.StatusBadRequest, "请分别执行清除或替换操作")
		return
	}

	for range 4 {
		config, raw, err := c.read(p.id)
		if err != nil {
			writeErr(w, http.StatusServiceUnavailable, "读取搜索引擎配置失败")
			return
		}
		if config.Revision != *req.Revision {
			break
		}
		config, err = c.updatedConfig(p.id, config, req)
		if err != nil {
			writeErr(w, http.StatusServiceUnavailable, "加密凭据失败，请检查服务端密钥目录")
			return
		}
		if config.Revision == *req.Revision {
			writeJSON(w, http.StatusOK, p.dto(config))
			return
		}
		written, err := c.write(p.id, raw, config)
		if err != nil {
			writeErr(w, http.StatusServiceUnavailable, "保存搜索引擎配置失败")
			return
		}
		if written {
			log.Printf("[cyberspace-search] configuration updated provider=%s revision=%d enabled=%t clear=%t", p.id, config.Revision, config.Enabled, req.Clear)
			w.Header().Set("Cache-Control", "no-store")
			writeJSON(w, http.StatusOK, p.dto(config))
			return
		}
	}
	writeErr(w, http.StatusConflict, "配置已变化，请刷新后重试")
}

func (c *cyberspaceSearch) updatedConfig(id string, config cyberspaceConfig, req cyberspaceConfigUpdate) (cyberspaceConfig, error) {
	if config.Enabled == req.Enabled && !req.Clear && req.APIKey == "" && req.AccountID == "" {
		return config, nil
	}
	if req.Clear {
		config.Key, config.Account = "", ""
	}
	if req.APIKey != "" || req.AccountID != "" {
		aead, err := loadCyberspaceCipher(c.keyPath, config.Key == "" && config.Account == "")
		if err != nil {
			return config, err
		}
		if req.APIKey != "" {
			config.Key = sealCyberspaceValue(aead, id+"/key", req.APIKey)
		}
		if req.AccountID != "" {
			config.Account = sealCyberspaceValue(aead, id+"/account", req.AccountID)
		}
	}
	config.Enabled = req.Enabled
	config.Revision++
	config.Test = nil
	return config, nil
}

func (s *Server) testCyberspaceSearch(w http.ResponseWriter, r *http.Request) {
	c := s.cyberspace
	if c == nil || c.db == nil {
		writeErr(w, http.StatusServiceUnavailable, "搜索引擎配置库不可用")
		return
	}
	c.mu.Lock()
	batch := c.batch
	if batch == nil {
		batch = &cyberspaceBatch{done: make(chan struct{})}
		c.batch = batch
		if !s.goBackground(func() {
			batch.failed = s.runCyberspaceTests(c)
			c.mu.Lock()
			c.batch = nil
			close(batch.done)
			c.mu.Unlock()
		}) {
			c.batch = nil
			c.mu.Unlock()
			writeErr(w, http.StatusServiceUnavailable, "服务正在关闭")
			return
		}
	}
	c.mu.Unlock()

	select {
	case <-r.Context().Done():
		return
	case <-batch.done:
		if batch.failed {
			writeErr(w, http.StatusServiceUnavailable, "有连接测试结果未能保存，请刷新查看")
			return
		}
		c.writeList(w)
	}
}

func (s *Server) runCyberspaceTests(c *cyberspaceSearch) (failed bool) {
	jobs := make(chan cyberspaceProvider, len(cyberspaceProviders))
	errors := make(chan struct{}, len(cyberspaceProviders))
	for _, provider := range cyberspaceProviders {
		jobs <- provider
	}
	close(jobs)
	var workers sync.WaitGroup
	for range 3 {
		workers.Go(func() {
			for provider := range jobs {
				if s.ctx.Err() != nil {
					return
				}
				if err := s.testAndRecordCyberspaceProvider(c, provider); err != nil {
					log.Printf("[cyberspace-search] test result unavailable provider=%s", provider.id)
					errors <- struct{}{}
				}
			}
		})
	}
	workers.Wait()
	return len(errors) > 0 || s.ctx.Err() != nil
}

func (s *Server) testAndRecordCyberspaceProvider(c *cyberspaceSearch, p cyberspaceProvider) error {
	config, raw, err := c.read(p.id)
	if err != nil || !config.Enabled || config.Key == "" {
		return err
	}
	at := time.Now().UTC()
	status, reason := "unverified", "probe_unavailable"
	if p.endpoint != "" {
		key, account, err := c.openCredentials(p.id, config)
		if err != nil {
			status, reason = "failed", "credential_storage_error"
		} else {
			status, reason = probeCyberspaceProvider(s.ctx, c.client, p, key, account)
		}
	}
	config.Test = &cyberspaceTest{Status: status, Reason: reason, TestedAt: at}
	written, err := c.write(p.id, raw, config)
	if written {
		log.Printf("[cyberspace-search] tested provider=%s status=%s reason=%s", p.id, status, reason)
	}
	return err
}
