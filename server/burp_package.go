package server

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/wpsec/ARTEX-local/db"
	"github.com/wpsec/ARTEX-local/evidence"
)

type burpPackageExchange struct {
	Binding      db.FindingTrafficBinding
	RequestBody  []byte
	ResponseBody []byte
}

type burpPackageManifest struct {
	Version         int                       `json:"version"`
	EvidenceVersion int64                     `json:"evidence_version"`
	GeneratedAt     time.Time                 `json:"generated_at"`
	Entries         []burpPackageManifestItem `json:"entries"`
}

type burpPackageManifestItem struct {
	BindingID          int64  `json:"binding_id"`
	Role               string `json:"role"`
	SourceTrafficID    string `json:"source_traffic_id"`
	CapturedAt         string `json:"captured_at,omitempty"`
	URL                string `json:"url"`
	Method             string `json:"method"`
	Status             int    `json:"status"`
	RequestFile        string `json:"request_file"`
	ResponseFile       string `json:"response_file"`
	RequestHostAdded   bool   `json:"request_host_added_from_captured_url"`
	RequestBodySHA256  string `json:"request_body_sha256"`
	ResponseBodySHA256 string `json:"response_body_sha256"`
}

func (s *Server) downloadFindingBurpPackage(w http.ResponseWriter, r *http.Request) {
	access, ok := s.deliveryReportAccess(w, r)
	if !ok {
		return
	}
	traffic, err := s.m.pg.GetFindingTraffic(r.Context(), access.findingID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "读取漏洞流量证据失败")
		return
	}
	if traffic == nil || len(traffic.Bindings) == 0 {
		writeErr(w, http.StatusNotFound, "该漏洞没有绑定可下载的 HTTP 请求证据")
		return
	}
	if err := validateDeliveryTrafficEvidenceSize(traffic.Bindings); err != nil {
		writeErr(w, http.StatusRequestEntityTooLarge, "绑定流量超过 Burp 复测包的大小上限")
		return
	}
	exchanges, err := loadBurpPackageExchanges(r.Context(), s.evidenceStore(), traffic.Bindings)
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, "读取已绑定的原始流量失败")
		return
	}
	archive, err := buildBurpReproductionArchive(traffic.Version, exchanges)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "生成 Burp 复测包失败")
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="artex-finding-%d-burp.zip"`, access.findingID))
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Length", strconv.Itoa(len(archive)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(archive)
}

func loadBurpPackageExchanges(ctx context.Context, store *evidence.Store, bindings []db.FindingTrafficBinding) ([]burpPackageExchange, error) {
	out := make([]burpPackageExchange, 0, len(bindings))
	for _, binding := range bindings {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		requestBody, err := readBurpEvidenceBody(store, binding.Snapshot, "request")
		if err != nil {
			return nil, err
		}
		responseBody, err := readBurpEvidenceBody(store, binding.Snapshot, "response")
		if err != nil {
			return nil, err
		}
		out = append(out, burpPackageExchange{Binding: binding, RequestBody: requestBody, ResponseBody: responseBody})
	}
	return out, nil
}

func readBurpEvidenceBody(store *evidence.Store, snapshot db.TrafficEvidenceSnapshot, side string) ([]byte, error) {
	file, expected, err := store.OpenBody(snapshot, side)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	body, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}
	if int64(len(body)) != expected {
		return nil, fmt.Errorf("HTTP %s 正文不完整：证据记录 %d 字节，实际读取 %d 字节", side, expected, len(body))
	}
	return body, nil
}

func buildBurpReproductionArchive(evidenceVersion int64, exchanges []burpPackageExchange) ([]byte, error) {
	if len(exchanges) == 0 {
		return nil, errors.New("没有绑定的 HTTP 请求证据")
	}
	var buffer bytes.Buffer
	archive := zip.NewWriter(&buffer)
	manifest := burpPackageManifest{
		Version:         1,
		EvidenceVersion: evidenceVersion,
		GeneratedAt:     time.Now().UTC(),
		Entries:         make([]burpPackageManifestItem, 0, len(exchanges)),
	}
	for index, exchange := range exchanges {
		request, hostAdded, err := burpReplayRequest(exchange.Binding.Snapshot, exchange.RequestBody)
		if err != nil {
			return nil, errors.Join(err, archive.Close())
		}
		response, err := burpResponseEvidence(exchange.Binding.Snapshot, exchange.ResponseBody)
		if err != nil {
			return nil, errors.Join(err, archive.Close())
		}
		requestFile := fmt.Sprintf("requests/%03d-binding-%d-request.http", index+1, exchange.Binding.ID)
		responseFile := fmt.Sprintf("responses/%03d-binding-%d-response.http", index+1, exchange.Binding.ID)
		if err := writeBurpArchiveFile(archive, requestFile, request); err != nil {
			return nil, errors.Join(err, archive.Close())
		}
		if err := writeBurpArchiveFile(archive, responseFile, response); err != nil {
			return nil, errors.Join(err, archive.Close())
		}
		item := burpPackageManifestItem{
			BindingID:          exchange.Binding.ID,
			Role:               deliveryBindingRoleLabel(exchange.Binding.Role),
			SourceTrafficID:    exchange.Binding.Snapshot.SourceTrafficID,
			URL:                exchange.Binding.Snapshot.URL,
			Method:             exchange.Binding.Snapshot.Method,
			Status:             exchange.Binding.Snapshot.Status,
			RequestFile:        requestFile,
			ResponseFile:       responseFile,
			RequestHostAdded:   hostAdded,
			RequestBodySHA256:  burpBodySHA256(exchange.RequestBody),
			ResponseBodySHA256: burpBodySHA256(exchange.ResponseBody),
		}
		if exchange.Binding.Snapshot.CapturedAt > 0 {
			item.CapturedAt = time.Unix(exchange.Binding.Snapshot.CapturedAt, 0).UTC().Format(time.RFC3339)
		}
		manifest.Entries = append(manifest.Entries, item)
	}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, errors.Join(err, archive.Close())
	}
	if err := writeBurpArchiveFile(archive, "manifest.json", manifestBytes); err != nil {
		return nil, errors.Join(err, archive.Close())
	}
	readme := []byte("ARTEX Burp 复测包\n\n" +
		"requests/ 下的文件包含完整 HTTP 请求，可逐个复制到 Burp Suite Repeater 后复测。\n" +
		"请求头与请求正文来自漏洞绑定的 ARTEX 流量证据；请求正文按采集字节保留，Authorization、Cookie、业务参数等值不做脱敏。\n" +
		"为便于 Burp 重放，包内请求统一使用 CRLF，并按采集正文长度整理 Content-Length；缺失 Host 时从同一条采集 URL 补入。\n" +
		"responses/ 下是同次采集的响应证据，响应状态行与消息长度按保存的状态码和正文长度整理，供核对使用。\n" +
		"这些文件不是 Burp 项目文件，也不是 TLS/TCP 层逐字节抓包；包内没有发送或执行任何请求。\n" +
		"导入前应确认当前 Burp 会话和目标环境与授权测试范围一致。\n")
	if err := writeBurpArchiveFile(archive, "README.txt", readme); err != nil {
		return nil, errors.Join(err, archive.Close())
	}
	if err := archive.Close(); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func writeBurpArchiveFile(archive *zip.Writer, name string, contents []byte) error {
	writer, err := archive.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Deflate})
	if err != nil {
		return err
	}
	_, err = writer.Write(contents)
	return err
}

func burpReplayRequest(snapshot db.TrafficEvidenceSnapshot, body []byte) ([]byte, bool, error) {
	head := strings.TrimRight(strings.ReplaceAll(snapshot.ReqHead, "\r\n", "\n"), "\n")
	lines := strings.Split(head, "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) == "" {
		return nil, false, errors.New("采集请求缺少请求行")
	}
	requestLine := strings.Fields(lines[0])
	if len(requestLine) != 3 || !strings.HasPrefix(strings.ToUpper(requestLine[2]), "HTTP/") {
		return nil, false, errors.New("采集请求行不完整")
	}
	if !strings.HasPrefix(strings.ToUpper(requestLine[2]), "HTTP/1.") {
		requestLine[2] = "HTTP/1.1"
	}
	cleanedHeaders := make([]string, 0, len(lines)+2)
	hostPresent := false
	framingPresent := false
	for _, line := range lines[1:] {
		line = strings.TrimSuffix(line, "\r")
		if line == "" {
			continue
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			return nil, false, errors.New("采集请求头格式无效")
		}
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "host":
			hostPresent = strings.TrimSpace(value) != ""
			if hostPresent {
				cleanedHeaders = append(cleanedHeaders, line)
			}
		case "content-length":
			framingPresent = true
		case "transfer-encoding":
			framingPresent = true
		default:
			cleanedHeaders = append(cleanedHeaders, line)
		}
	}
	hostAdded := false
	if !hostPresent {
		u, err := url.Parse(snapshot.URL)
		if err != nil || strings.TrimSpace(u.Host) == "" {
			return nil, false, errors.New("采集请求缺少 Host 且无法从 URL 补全")
		}
		cleanedHeaders = append(cleanedHeaders, "Host: "+u.Host)
		hostAdded = true
	}
	if len(body) > 0 || framingPresent {
		cleanedHeaders = append(cleanedHeaders, "Content-Length: "+strconv.Itoa(len(body)))
	}
	var packet bytes.Buffer
	packet.WriteString(strings.Join(requestLine, " "))
	packet.WriteString("\r\n")
	for _, line := range cleanedHeaders {
		packet.WriteString(line)
		packet.WriteString("\r\n")
	}
	packet.WriteString("\r\n")
	packet.Write(body)
	return packet.Bytes(), hostAdded, nil
}

func burpResponseEvidence(snapshot db.TrafficEvidenceSnapshot, body []byte) ([]byte, error) {
	if snapshot.Status < 100 || snapshot.Status > 599 {
		return nil, errors.New("采集响应状态码无效")
	}
	head := strings.TrimRight(strings.ReplaceAll(snapshot.RespHead, "\r\n", "\n"), "\n")
	lines := strings.Split(head, "\n")
	if len(lines) > 0 && strings.TrimSpace(lines[0]) != "" {
		lines = lines[1:]
	}
	statusLine := "HTTP/1.1 " + strconv.Itoa(snapshot.Status)
	if statusText := http.StatusText(snapshot.Status); statusText != "" {
		statusLine += " " + statusText
	}
	cleanedHeaders := make([]string, 0, len(lines)+1)
	framingPresent := false
	for _, line := range lines {
		line = strings.TrimSuffix(line, "\r")
		if line == "" {
			continue
		}
		name, _, ok := strings.Cut(line, ":")
		if !ok {
			return nil, errors.New("采集响应头格式无效")
		}
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "content-length", "transfer-encoding":
			framingPresent = true
		default:
			cleanedHeaders = append(cleanedHeaders, line)
		}
	}
	if len(body) > 0 || framingPresent {
		cleanedHeaders = append(cleanedHeaders, "Content-Length: "+strconv.Itoa(len(body)))
	}
	var packet bytes.Buffer
	packet.WriteString(statusLine)
	packet.WriteString("\r\n")
	for _, line := range cleanedHeaders {
		packet.WriteString(line)
		packet.WriteString("\r\n")
	}
	packet.WriteString("\r\n")
	packet.Write(body)
	return packet.Bytes(), nil
}

func burpBodySHA256(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}
