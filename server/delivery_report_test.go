package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wpsec/ARTEX-local/db"
	"github.com/wpsec/ARTEX-local/evidence"
)

func TestNormalizeCVSS4BaseVector(t *testing.T) {
	valid := []string{
		"CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
		"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N",
	}
	for _, vector := range valid {
		got, ok := normalizeCVSS4BaseVector(vector)
		if !ok || got != vector {
			t.Errorf("normalizeCVSS4BaseVector(%q) = (%q, %v), want unchanged valid vector", vector, got, ok)
		}
	}
	invalid := []string{
		"AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
		"CVSS:4.0/AC:L/AV:N/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
		"CVSS:4.0/AV:F/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
		"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N/E:A",
	}
	for _, vector := range invalid {
		if got, ok := normalizeCVSS4BaseVector(vector); ok {
			t.Errorf("normalizeCVSS4BaseVector(%q) = (%q, true), want rejection", vector, got)
		}
	}
}

func TestDeliveryReportRequestOccurrenceIndex(t *testing.T) {
	requestPacket := strings.Join([]string{
		"证据绑定 1（漏洞验证）",
		"POST /api/registrations HTTP/1.1",
		"Host: example.invalid",
		"",
		"{}",
		"",
		"证据绑定 2（漏洞验证）",
		"POST /api/registrations HTTP/1.1",
		"Host: example.invalid",
		"",
		"{}",
	}, "\n")
	responsePacket := strings.Join([]string{
		"证据绑定 1（漏洞验证）",
		"HTTP/1.1 201 Created",
		"Content-Type: application/json",
		"",
		`{"id":"reg-1"}`,
		"",
		"证据绑定 2（漏洞验证）",
		"HTTP/1.1 201 Created",
		"Content-Type: application/json",
		"",
		`{"id":"reg-2"}`,
	}, "\n")
	got, err := deliveryReportRequestOccurrenceIndex(requestPacket, responsePacket)
	if err != nil {
		t.Fatalf("deliveryReportRequestOccurrenceIndex: %v", err)
	}
	var occurrences []struct {
		Purpose      string `json:"purpose"`
		RequestLine  string `json:"request_line"`
		ResponseLine string `json:"response_line"`
	}
	if err := json.Unmarshal([]byte(got), &occurrences); err != nil {
		t.Fatalf("decode occurrence index: %v", err)
	}
	if len(occurrences) != 2 {
		t.Fatalf("occurrence count = %d, want 2: %s", len(occurrences), got)
	}
	for index, occurrence := range occurrences {
		if occurrence.RequestLine != "POST /api/registrations" || occurrence.ResponseLine != "HTTP/1.1 201 Created" || !strings.Contains(occurrence.Purpose, "漏洞验证") {
			t.Errorf("occurrence %d lost its request, purpose, or paired result: %+v", index, occurrence)
		}
	}
}

func TestDeliveryReportWithoutBoundTrafficDoesNotInventPackets(t *testing.T) {
	request, response, err := (&Server{}).deliveryTrafficPackets(nil)
	if err != nil {
		t.Fatal(err)
	}
	if request != missingTrafficPacket || response != missingTrafficPacket {
		t.Fatalf("missing traffic placeholders = (%q, %q)", request, response)
	}
}

func TestDeliveryReportRequestLineIndexPreservesEncodedPathsAndCounts(t *testing.T) {
	packet := "" +
		"证据绑定 1\n" +
		"GET /api/items?id=a%2Fb HTTP/1.1\r\nHost: example.test\r\n\r\n\n" +
		"证据绑定 2\n" +
		"POST /api/items HTTP/1.1\r\nHost: example.test\r\n\r\n{}\n" +
		"证据绑定 3\n" +
		"GET /api/items?id=a%2Fb HTTP/1.1\r\nHost: example.test\r\n\r\n"

	want := "1. GET /api/items?id=a%2Fb\n2. POST /api/items\n3. GET /api/items?id=a%2Fb"
	if got := deliveryReportRequestLineIndex(packet); got != want {
		t.Fatalf("request line index = %q, want %q", got, want)
	}
	if got := deliveryReportRequestLineIndex("没有留存 HTTP 请求行"); got != "" {
		t.Fatalf("request line index without HTTP evidence = %q, want empty", got)
	}
}

func TestDeliveryReportUsesAllBoundPacketsWithoutRedactingCredentials(t *testing.T) {
	dataDir := t.TempDir()
	managerDir := filepath.Join(dataDir, "manager")
	storeDir := filepath.Join(managerDir, "evidence")
	writeBody := func(body string) (string, int64) {
		t.Helper()
		raw := []byte(body)
		sum := sha256.Sum256(raw)
		hash := hex.EncodeToString(sum[:])
		path := filepath.Join(storeDir, "blobs", hash[:2], hash+".bin")
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		return hash, int64(len(raw))
	}
	baselineRequestHash, baselineRequestLen := writeBody(`{"value":"baseline request"}`)
	baselineResponseHash, baselineResponseLen := writeBody(`{"value":"baseline response"}`)
	proofRequestHash, proofRequestLen := writeBody(`{"password":"body-secret","value":"proof request"}`)
	proofResponseHash, proofResponseLen := writeBody(`{"token":"response-secret","value":"proof response"}`)
	baseline := db.TrafficEvidenceSnapshot{
		ReqHead: "POST /baseline HTTP/1.1\r\nHost: baseline.test", RespHead: "HTTP/1.1 200 OK",
		ReqHash: baselineRequestHash, ReqLen: baselineRequestLen, RespHash: baselineResponseHash, RespLen: baselineResponseLen,
	}
	proof := db.TrafficEvidenceSnapshot{
		ReqHead:  "POST /proof?access_token=query-secret HTTP/1.1\r\nHost: proof.test\r\nAuthorization: Bearer header-secret\r\nCookie: session=cookie-secret",
		RespHead: "HTTP/1.1 200 OK\r\nSet-Cookie: session=response-cookie",
		ReqHash:  proofRequestHash, ReqLen: proofRequestLen, RespHash: proofResponseHash, RespLen: proofResponseLen,
	}
	s := &Server{m: &Manager{dir: managerDir}}
	request, response, err := s.deliveryTrafficPackets([]db.FindingTrafficBinding{
		{Role: "baseline", Snapshot: baseline},
		{Role: "proof", Snapshot: proof},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, check := range []struct{ packet, want string }{
		{request, "POST /proof"},
		{request, "baseline request"},
		{request, "proof request"},
		{response, "baseline response"},
		{response, "proof response"},
	} {
		if !strings.Contains(check.packet, check.want) {
			t.Fatalf("packet did not use the bound proof evidence: %s", check.packet)
		}
	}
	for _, evidence := range []struct{ packet, want string }{
		{request, "access_token=query-secret"},
		{request, "Authorization: Bearer header-secret"},
		{request, "Cookie: session=cookie-secret"},
		{request, `"password":"body-secret"`},
		{response, "Set-Cookie: session=response-cookie"},
		{response, `"token":"response-secret"`},
	} {
		if !strings.Contains(evidence.packet, evidence.want) {
			t.Fatalf("delivery packet omitted original evidence %q: %s\n%s", evidence.want, request, response)
		}
	}
}

func TestDeliveryTrafficEvidencePairsSeparatePacketsWithinEvidenceSection(t *testing.T) {
	store := evidence.New(nil, nil, t.TempDir())
	baseline := deliveryPacketFixture(t, store, "GET /before HTTP/1.1\r\nHost: report.test", "", "HTTP 200\nContent-Type: application/json", `{"count":2}`)
	baseline.SourceTrafficID = "baseline-source"
	baseline.URL = "https://report.test/before"
	baseline.CapturedAt = 1700000000
	proof := deliveryPacketFixture(t, store, "POST /write HTTP/1.1\r\nHost: report.test", `{"value":"proof"}`, "HTTP/1.1 200 OK", `{"id":3}`)
	proof.SourceTrafficID = "proof-source"
	proof.URL = "https://report.test/write"
	proof.CapturedAt = 1700000001
	appendix, err := renderDeliveryTrafficEvidence(store, []db.FindingTrafficBinding{
		{ID: 11, Role: "baseline", Note: "写入前读取记录数", Snapshot: baseline},
		{ID: 12, Role: "proof", Note: "验证写入结果\n## 不能变成章节", Snapshot: proof},
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(appendix, "\n## ") || strings.Count(appendix, "```http\n") != 4 {
		t.Fatalf("evidence changed the report's section structure or combined packets: %s", appendix)
	}
	for _, want := range []string{"2023-11-15T06:13:20+08:00", "baseline-source", "proof-source", "写入前读取记录数", "头部由平台采集时整理", "HTTP 200\nContent-Type: application/json"} {
		if !strings.Contains(appendix, want) {
			t.Errorf("evidence omitted provenance or stored bytes %q", want)
		}
	}
	last := -1
	for _, want := range []string{"#### 证据绑定 11", "GET /before HTTP/1.1", `{"count":2}`, "#### 证据绑定 12", "POST /write HTTP/1.1", `{"id":3}`} {
		index := strings.Index(appendix, want)
		if index <= last {
			t.Fatalf("request and response did not remain paired at %q: %s", want, appendix)
		}
		last = index
	}
	for _, chunk := range strings.Split(appendix, "```http\n")[1:] {
		packet, _, found := strings.Cut(chunk, "\n```")
		if !found || strings.Contains(packet, "证据绑定") || strings.Contains(packet, "源流量编号") {
			t.Fatalf("an HTTP block includes report labels: %s", packet)
		}
	}
	vector := "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"
	report := deliveryReportFixture("测试结论", vector) + "\n\n" + deliveryEvidenceAppendixMarker + "\n" + appendix
	if err := validateDeliveryReportTemplate(report, vector); err != nil {
		t.Fatalf("evidence appendix broke the five-section template: %v", err)
	}
	if got := stripDeliveryTrafficEvidence(report); got != deliveryReportFixture("测试结论", vector) {
		t.Fatalf("automatic evidence was not removable before regeneration: %s", got)
	}
}

func TestDeliveryTrafficEvidenceMarksMissingAndBinaryMaterial(t *testing.T) {
	store := evidence.New(nil, nil, t.TempDir())
	snapshot := deliveryPacketFixture(t, store, "", string([]byte{0, 255, 1}), "HTTP 200", "ok")
	appendix, err := renderDeliveryTrafficEvidence(store, []db.FindingTrafficBinding{{ID: 7, Role: "proof", Snapshot: snapshot}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"采集时间：未留存", "源流量编号：未留存", "报文头未留存", "Base64", "AP8B", "不能直接粘贴重放", "HTTP 200"} {
		if !strings.Contains(appendix, want) {
			t.Errorf("evidence omitted the limitation %q: %s", want, appendix)
		}
	}
	if strings.Contains(appendix, "HTTP/1.1 200") {
		t.Fatal("renderer invented a response protocol version")
	}
	missing, err := renderDeliveryTrafficEvidence(nil, nil)
	if err != nil || !strings.Contains(missing, "未绑定 ARTEX HTTP 流量") || strings.Contains(missing, "\n## ") {
		t.Fatalf("missing traffic was not reported inside the existing section: %q, %v", missing, err)
	}
}

func TestDeliveryTrafficEvidenceRejectsOversizeOrDamagedBodies(t *testing.T) {
	if appendix, err := renderDeliveryTrafficEvidence(nil, []db.FindingTrafficBinding{{Snapshot: db.TrafficEvidenceSnapshot{ReqLen: deliveryReportEvidenceMaxBytes + 1}}}); err == nil || appendix != "" {
		t.Fatalf("oversize evidence was rendered: %q, %v", appendix, err)
	}
	store := evidence.New(nil, nil, t.TempDir())
	snapshot := deliveryPacketFixture(t, store, "GET / HTTP/1.1\r\nHost: report.test", "request", "HTTP 200", "response")
	path := filepath.Join(store.Dir, "blobs", snapshot.RespHash[:2], snapshot.RespHash+".bin")
	if err := os.WriteFile(path, []byte("damaged"), 0o600); err != nil {
		t.Fatal(err)
	}
	if appendix, err := renderDeliveryTrafficEvidence(store, []db.FindingTrafficBinding{{Snapshot: snapshot}}); err == nil || appendix != "" {
		t.Fatalf("damaged evidence was rendered: %q, %v", appendix, err)
	}
}

func TestDeliveryPacketFencePreservesMarkdownInHTTPBody(t *testing.T) {
	packet := "HTTP/1.1 200 OK\r\n\r\n```\n## 证据说明\n```"
	block := markdownPacketBlock(packet)
	if !strings.HasPrefix(block, "````http\n") || !strings.HasSuffix(block, "\n````") || !strings.Contains(block, packet) {
		t.Fatalf("HTTP body escaped its evidence code block: %s", block)
	}
}

func TestStripDeliveryTrafficEvidenceIgnoresMarkerInsideHTTPPacket(t *testing.T) {
	vector := "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"
	packet := "HTTP/1.1 200 OK\r\n\r\n" + deliveryEvidenceAppendixMarker + "\n## 响应正文中的标题\n```"
	report := deliveryReportFixture("测试结论", vector) + "\n\n### 本机留存报文\n\n" + markdownPacketBlock(packet)
	if got := stripDeliveryTrafficEvidence(report); got != report {
		t.Fatalf("marker inside the stored HTTP body truncated the report: %s", got)
	}
	withAppendix := report + "\n\n" + deliveryEvidenceAppendixMarker + "\n### 旧平台附录\n\n旧内容"
	if got := stripDeliveryTrafficEvidence(withAppendix); got != report {
		t.Fatalf("automatic appendix was not removed independently of packet markers: %s", got)
	}
	inlineMarker := "正文引用 " + deliveryEvidenceAppendixMarker + " 作为证据。"
	if got := stripDeliveryTrafficEvidence(inlineMarker); got != inlineMarker {
		t.Fatalf("inline marker truncated narrative: %s", got)
	}
}

func TestFindingDeliveryReportIsolationAndEvidenceVersion(t *testing.T) {
	s, finding, request := trafficEvidenceServer(t)
	findingRecord, err := s.m.pg.GetFinding(finding.FindingID)
	if err != nil {
		t.Fatal(err)
	}
	if findingRecord == nil || findingRecord.TaskID == nil {
		t.Fatal("fixture finding has no owning task")
	}
	ownerID := *findingRecord.TaskID
	child, err := s.m.CreateTaskWithOptions("delivery child", "independent report", db.TaskCreateOptions{SourceTaskIDs: []int64{ownerID}})
	if err != nil {
		t.Fatal(err)
	}
	childID := mustTaskID(t, child.ID)
	t.Cleanup(func() { _ = s.m.pg.DeleteTask(childID) })
	outsider, err := s.m.CreateTask("delivery outsider", "no inherited finding", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	outsiderID := mustTaskID(t, outsider.ID)
	t.Cleanup(func() { _ = s.m.pg.DeleteTask(outsiderID) })

	vector := "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"
	ownerContent := deliveryReportFixture("owner report", vector)
	childContent := deliveryReportFixture("child report", vector)
	put := func(taskID int64, content, cvss string, version int64) int {
		t.Helper()
		body, err := json.Marshal(map[string]any{
			"content": content, "cvss_vector": cvss, "evidence_version": version,
		})
		if err != nil {
			t.Fatal(err)
		}
		path := fmt.Sprintf("/api/tasks/%d/findings/%d/delivery-report", taskID, finding.FindingID)
		return request(http.MethodPut, path, string(body)).Code
	}
	get := func(taskID int64) FindingDeliveryReport {
		t.Helper()
		path := fmt.Sprintf("/api/tasks/%d/findings/%d/delivery-report", taskID, finding.FindingID)
		w := request(http.MethodGet, path, "")
		if w.Code != http.StatusOK {
			t.Fatalf("get delivery report: status=%d body=%s", w.Code, w.Body.String())
		}
		var report FindingDeliveryReport
		if err := json.Unmarshal(w.Body.Bytes(), &report); err != nil {
			t.Fatal(err)
		}
		return report
	}

	if code := put(ownerID, ownerContent, vector, 0); code != http.StatusOK {
		t.Fatalf("save owner report: status=%d", code)
	}
	if code := put(childID, childContent, vector, 0); code != http.StatusOK {
		t.Fatalf("save inherited report: status=%d", code)
	}
	ownerSaved := get(ownerID)
	if ownerSaved.HasDetailedReport {
		t.Fatal("saving a delivery report alone must not mark the detailed report saved")
	}
	if owner := ownerSaved; stripDeliveryTrafficEvidence(owner.Content) != ownerContent || !owner.Exists {
		t.Fatalf("owner report was not persisted independently: %+v", owner)
	}
	if inherited := get(childID); stripDeliveryTrafficEvidence(inherited.Content) != childContent || !inherited.Exists {
		t.Fatalf("inherited report was not persisted independently: %+v", inherited)
	}
	if w := request(http.MethodGet, fmt.Sprintf("/api/tasks/%d/findings/%d/delivery-report", outsiderID, finding.FindingID), ""); w.Code != http.StatusNotFound {
		t.Fatalf("unrelated task accessed finding report: status=%d body=%s", w.Code, w.Body.String())
	}

	if code := put(ownerID, ownerContent, "CVSS:4.0/AV:N", 0); code != http.StatusBadRequest {
		t.Fatalf("invalid vector save status=%d", code)
	}
	if got := get(ownerID); got.Content != ownerSaved.Content {
		t.Fatalf("invalid vector overwrote saved report: %+v", got)
	}
	if code := put(ownerID, strings.Replace(ownerContent, "## 攻击链路", "## 其他章节", 1), vector, 0); code != http.StatusBadRequest {
		t.Fatalf("invalid report structure save status=%d", code)
	}
	if got := get(ownerID); got.Content != ownerSaved.Content {
		t.Fatalf("invalid template overwrote saved report: %+v", got)
	}

	seedTraffic := func(id, path, requestHead, requestBody, responseBody string) {
		t.Helper()
		responseHead := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nSet-Cookie: sid=response-cookie"
		_, err := s.m.traffic.DB().Exec(`INSERT INTO exchanges(id,ts,host,method,url_template,url,status,content_type,req_len,resp_len,path)
VALUES(?,1,'delivery.local','POST',?,?,200,'application/json',?,?,'')`,
			id, path, "http://delivery.local"+path, len(requestBody), len(responseBody))
		if err != nil {
			t.Fatal(err)
		}
		_, err = s.m.traffic.DB().Exec(`INSERT INTO exchange_bodies(id,req_head,resp_head,req_body,resp_body)
VALUES(?,?,?,?,?)`, id, requestHead, responseHead, []byte(requestBody), []byte(responseBody))
		if err != nil {
			t.Fatal(err)
		}
	}
	seedTraffic("delivery-report-baseline", "/baseline", "POST /baseline HTTP/1.1\r\nHost: delivery.local", `{"value":"baseline"}`, `{"value":"baseline response"}`)
	seedTraffic("delivery-report-proof", "/proof?access_token=query-secret", "POST /proof?access_token=query-secret HTTP/1.1\r\nHost: delivery.local\r\nAuthorization: Bearer header-secret\r\nCookie: sid=request-cookie", `{"password":"body-secret","value":"proof request"}`, `{"token":"response-secret","value":"proof response"}`)
	if _, err := s.evidenceStore().Bind(context.Background(), finding.FindingID, []db.TrafficRef{
		{TrafficID: "delivery-report-baseline", Role: "baseline"},
		{TrafficID: "delivery-report-proof", Role: "proof"},
	}); err != nil {
		t.Fatal(err)
	}
	traffic, err := s.m.pg.GetFindingTraffic(context.Background(), finding.FindingID)
	if err != nil {
		t.Fatal(err)
	}
	requestPacket, responsePacket, err := s.deliveryTrafficPackets(traffic.Bindings)
	if err != nil {
		t.Fatal(err)
	}
	for _, check := range []struct{ packet, want string }{
		{requestPacket, "POST /proof"},
		{requestPacket, "POST /baseline"},
		{responsePacket, "proof response"},
		{responsePacket, "baseline response"},
	} {
		if !strings.Contains(check.packet, check.want) {
			t.Fatalf("delivery packet omitted bound traffic %q: %s", check.want, check.packet)
		}
	}
	for _, secret := range []string{"query-secret", "header-secret", "request-cookie", "body-secret", "response-cookie", "response-secret"} {
		if !strings.Contains(requestPacket+responsePacket, secret) {
			t.Fatalf("delivery packet changed synthetic original evidence %q", secret)
		}
	}
	if code := put(ownerID, deliveryReportFixture("stale overwrite", vector), vector, 0); code != http.StatusConflict {
		t.Fatalf("stale report save status=%d", code)
	}
	stale := get(ownerID)
	if stale.Content != ownerSaved.Content || stale.EvidenceVersion != 0 || stale.CurrentEvidenceVersion != 1 {
		t.Fatalf("stale evidence changed saved report or version state: %+v", stale)
	}
	if code := put(ownerID, ownerContent, vector, traffic.Version); code != http.StatusOK {
		t.Fatalf("save current evidence: status=%d", code)
	}
	current := get(ownerID)
	if err := validateDeliveryReportTemplate(current.Content, vector); err != nil {
		t.Fatalf("saved evidence broke the report template: %v", err)
	}
	if strings.Count(current.Content, deliveryEvidenceAppendixMarker) != 1 || !strings.Contains(current.Content, "baseline response") || !strings.Contains(current.Content, "proof response") {
		t.Fatalf("saved report did not include all bound evidence once: %s", current.Content)
	}
	if code := put(ownerID, current.Content, vector, traffic.Version); code != http.StatusOK {
		t.Fatalf("resave generated evidence: status=%d", code)
	}
	if resaved := get(ownerID); resaved.Content != current.Content {
		t.Fatalf("resave duplicated or changed the automatic appendix: %s", resaved.Content)
	}
}

func TestGeneratedDeliveryReportStoresReadableNarrative(t *testing.T) {
	s, finding, _ := trafficEvidenceServer(t)
	const vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"
	const ledgerNote = "复核分组记在台账的蓝色标签下。"
	const detailed = "## 详细报告\n\n两次返回逐字节相同（seq 5–11）。\n" + ledgerNote
	const fieldMarker = "<!-- artex:developer-report-fields-v1 -->\n"
	const descriptionTail = "\n已确认影响：其他部门的目录名称可见。\n触发位置：文档中心的预览页，日常操作是打开文档预览。"
	const markedFacts = "<!-- artex:developer-test-facts-v1 -->\n测试角色：普通账号。\n预期行为：列表仅显示当前部门的记录。\n实际结果：显示了其他部门的目录。\n未验证范围：现有记录无法确认响应包含用户列表。"
	const repair = fieldMarker + "修复措施：服务端按当前用户权限限制可见目录。\n修复后验收：无权限时应拒绝访问。"
	withFields := func(phenomenon, note string) string {
		report := deliveryReportFixture(fieldMarker+"漏洞现象："+phenomenon+descriptionTail+note, vector)
		report = strings.Replace(report, "操作、失败尝试和影响边界未记录。", markedFacts+note, 1)
		return strings.Replace(report, "现有材料不足以定位具体实现，需结合源码确认修复位置。", repair+note, 1)
	}
	delivery := withFields("普通账号看到其他部门的目录（seq 5–11）。", "\n"+ledgerNote)
	workflowCall(t, context.Background(), s.toolUpdateFindingReport(), map[string]any{
		"finding_id": finding.NodeID, "report": detailed, "delivery_report": delivery,
		"cvss_vector": vector, "evidence_version": 0,
	}, false)
	record, err := s.m.pg.GetFinding(finding.FindingID)
	if err != nil || record == nil || record.TaskID == nil || record.Report != detailed {
		t.Fatalf("unexpected detailed report state: %v", err)
	}
	saved, err := s.m.pg.GetFindingDeliveryReport(*record.TaskID, finding.FindingID)
	want := withFields("普通账号看到其他部门的目录。", "")
	if err != nil || saved == nil || !saved.Exists || !saved.HasDetailedReport || stripDeliveryTrafficEvidence(saved.Content) != want {
		t.Fatalf("generated report did not save its readable narrative: %v", err)
	}
}

func deliveryReportFixture(description, vector string) string {
	return fmt.Sprintf(`# 测试系统-模块 /test 测试缺陷：测试结果

CVSS 4.0：%s  评分待复核

## 描述

%s

## 攻击链路

~~~text
账号权限和利用前提未验证
└─ 请求结果和业务影响未验证
~~~

## 测试过程

测试时间：未记录

操作、失败尝试和影响边界未记录。

## Burp 复现

以下请求包供渗透测试工程师在授权目标中导入 Burp Repeater 复现或复测；请求包本身不代表已发送或验证。

~~~http
GET /test HTTP/1.1
Host: <需从授权账号重新捕获>
~~~

## 修复建议

现有材料不足以定位具体实现，需结合源码确认修复位置。`, vector, description)
}

func deliveryPacketFixture(t *testing.T, store *evidence.Store, requestHead, requestBody, responseHead, responseBody string) db.TrafficEvidenceSnapshot {
	t.Helper()
	writeBody := func(body string) (string, int64) {
		raw := []byte(body)
		sum := sha256.Sum256(raw)
		hash := hex.EncodeToString(sum[:])
		path := filepath.Join(store.Dir, "blobs", hash[:2], hash+".bin")
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		return hash, int64(len(raw))
	}
	requestHash, requestLen := writeBody(requestBody)
	responseHash, responseLen := writeBody(responseBody)
	return db.TrafficEvidenceSnapshot{ReqHead: requestHead, RespHead: responseHead, ReqHash: requestHash, ReqLen: requestLen, RespHash: responseHash, RespLen: responseLen}
}

type FindingDeliveryReport struct {
	Content                string `json:"content"`
	EvidenceVersion        int64  `json:"evidence_version"`
	CurrentEvidenceVersion int64  `json:"current_evidence_version"`
	HasDetailedReport      bool   `json:"has_detailed_report"`
	Exists                 bool   `json:"exists"`
}
