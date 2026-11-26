package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"iter"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/norma/llm"
	"github.com/wpsec/ARTEX-local/agent"
	"github.com/wpsec/ARTEX-local/db"
	"github.com/wpsec/ARTEX-local/tools/report-eval"
)

func TestDeliveryReportTimeHintsUseBeijingAndKeepMissingExplicit(t *testing.T) {
	if got, want := reportEvalTestTimeHint("2026-11-01T02:00:00Z"), "2026-11-01 10:00:00（北京时间）"; got != want {
		t.Fatalf("UTC evaluation time hint=%q, want %q", got, want)
	}
	if got := reportEvalTestTimeHint("not-a-time"); got != "测试时间未记录" {
		t.Fatalf("invalid evaluation time hint=%q, want missing marker", got)
	}

	bindings := []db.FindingTrafficBinding{{
		ID:   7,
		Role: "proof",
		Note: "关键请求",
		Snapshot: db.TrafficEvidenceSnapshot{
			CapturedAt: time.Date(2026, time.November, 1, 2, 0, 0, 0, time.UTC).Unix(),
		},
	}}
	index := deliveryEvidenceTimeIndex(bindings)
	if !strings.Contains(index, "2026-11-01 10:00:00（北京时间）") || !strings.Contains(index, "关键请求") {
		t.Fatalf("evidence time index omitted timestamp or purpose: %q", index)
	}
	if got, want := deliveryEvidenceTestTimeHint(bindings), "2026-11-01 10:00:00（北京时间，首条证据请求采集时间）"; got != want {
		t.Fatalf("evidence test time hint=%q, want %q", got, want)
	}
	if got := deliveryEvidenceTimeIndex(nil); !strings.Contains(got, "没有绑定流量采集时间") {
		t.Fatalf("empty evidence time index=%q, want explicit missing-time guidance", got)
	}
	if got := deliveryEvidenceTestTimeHint(nil); got != "测试时间未记录" {
		t.Fatalf("empty evidence test time hint=%q, want missing marker", got)
	}
}

type reportEvalProvider struct {
	request llm.CompletionRequest
	calls   int
	result  string
	err     error
}

func (p *reportEvalProvider) Stream(context.Context, llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(func(llm.StreamEvent, error) bool) {}
}

func (p *reportEvalProvider) Complete(_ context.Context, request llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	p.request = request
	p.calls++
	if p.err != nil {
		return llm.Message{}, "", llm.Usage{}, p.err
	}
	return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock(p.result)}}, "end_turn", llm.Usage{InputTokens: 17, OutputTokens: 23}, nil
}

func TestReportEvalRouteIsAuthenticatedOptInAndFixedInputOnly(t *testing.T) {
	t.Setenv("ARTEX_REPORT_EVAL_ENABLED", "false")
	modelResponseJSON := `{"cvss_vector":"CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N","description":"普通用户可修改他人作业，状态随之改变。","remediation":"服务端校验当前账号是否有权修改该作业。","test_process":"使用样本中的普通用户请求修改作业，再以所有者账号读取并检查状态。","burp_reproduction":"请求包供授权复现。","attack_chain":"FENCEtext\n普通用户\n└─ 修改接口\n   └─ 作业状态发生变化\nFENCE"}`
	provider := &reportEvalProvider{result: strings.ReplaceAll(modelResponseJSON, "FENCE", "```")}
	s := &Server{llmProv: provider, llmOn: true, llmCfg: agent.Config{
		Format: llm.FormatOpenAI, Model: "fixed-test-model", APIKey: "must-not-be-exposed",
		ThinkingType: "enabled", ReasoningEffort: "high",
	}, jwtKey: []byte("report-eval-test-signing-key")}
	handler := s.Handler()
	token, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	request := func(method, path, body, bearer string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		return response
	}
	if response := request(http.MethodPost, "/api/report-eval/idor", "", ""); response.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated request status=%d, want 401", response.Code)
	}
	if response := request(http.MethodPost, "/api/report-eval/idor", "", token); response.Code != http.StatusNotFound {
		t.Fatalf("disabled route status=%d, want 404", response.Code)
	}
	t.Setenv("ARTEX_REPORT_EVAL_ENABLED", "true")
	if response := request(http.MethodPost, "/api/report-eval/unknown", "", token); response.Code != http.StatusNotFound {
		t.Fatalf("unknown case status=%d, want 404", response.Code)
	}
	if response := request(http.MethodPost, "/api/report-eval/idor", `{"prompt":"custom"}`, token); response.Code != http.StatusBadRequest {
		t.Fatalf("custom input status=%d, want 400", response.Code)
	}
	if provider.calls != 0 {
		t.Fatalf("rejected requests called the model %d times", provider.calls)
	}
	info := request(http.MethodGet, "/api/report-eval", "", token)
	if info.Code != http.StatusOK || !strings.Contains(info.Body.String(), "fixed-test-model") ||
		!strings.Contains(info.Body.String(), `"thinking_type":"enabled"`) ||
		!strings.Contains(info.Body.String(), `"reasoning_effort":"high"`) ||
		!strings.Contains(info.Body.String(), `"completion_passes":1`) ||
		strings.Contains(info.Body.String(), `"review_system_sha256"`) ||
		strings.Contains(info.Body.String(), "must-not-be-exposed") {
		t.Fatalf("metadata response status=%d body=%s", info.Code, info.Body.String())
	}
	response := request(http.MethodPost, "/api/report-eval/idor", "", token)
	if response.Code != http.StatusOK {
		t.Fatalf("sample request status=%d body=%s", response.Code, response.Body.String())
	}
	if provider.calls != 1 {
		t.Fatalf("model call count=%d, want one report generation call", provider.calls)
	}
	if len(provider.request.Tools) != 0 {
		t.Fatalf("evaluation request exposed %d tools", len(provider.request.Tools))
	}
	if provider.request.Thinking != "disabled" {
		t.Fatalf("evaluation request thinking=%q, want disabled for strict JSON output", provider.request.Thinking)
	}
	if provider.request.MaxTokens != deliveryReportMaxTokens {
		t.Fatalf("evaluation max tokens=%d, want %d", provider.request.MaxTokens, deliveryReportMaxTokens)
	}
	if len(provider.request.System) != 1 || !strings.Contains(provider.request.System[0], "保存前在本次输出中核对结论、限制、修复和链路") {
		t.Fatal("report generation call did not receive the same-Reporter self-check instructions")
	}
	if strings.Count(provider.request.System[0], agent.DeliveryReportDraftRules) != 1 {
		t.Fatal("compatibility draft generation must use the dedicated JSON draft rules once")
	}
	if strings.Contains(provider.request.System[0], "# 系统或模块 功能或接口 缺陷：实际后果") {
		t.Fatal("JSON draft instructions must not also require a full Markdown report")
	}
	for _, staleRule := range []string{"并发漏洞须使用并发工具或脚本验证", "把过滤或拒绝特殊字符列为修复", "文件名、所有者名称和权限位不能单独证明文件内容敏感"} {
		if strings.Contains(provider.request.System[0], staleRule) {
			t.Fatalf("compatibility draft generation retained superseded guidance %q", staleRule)
		}
	}
	for _, rule := range []string{"不要把占位主机、身份、Cookie 或 Token 改成真实测试条件", "每个请求或命令的结果缩进在该节点下", "响应差异只证明差异", "缺项写“未验证”", "漏洞名称和 CVSS 向量也不能代替影响证据"} {
		if !strings.Contains(provider.request.System[0], rule) {
			t.Fatalf("report generation instructions omitted rule %q", rule)
		}
	}
	prompt := provider.request.Messages[0].Text()
	for _, forbidden := range []string{"reference_report", "must_preserve", "must_not_claim", `"id":"E`} {
		if strings.Contains(prompt, forbidden) {
			t.Fatalf("model input exposed internal review material %q", forbidden)
		}
	}
	if !strings.Contains(prompt, "GET /api/jobs/job-a HTTP/1.1") || !strings.Contains(prompt, "user-b") ||
		!strings.Contains(prompt, `"request_line_index":"1. GET /api/jobs/job-a`) ||
		!strings.Contains(prompt, "2. POST /api/jobs/job-a/types") {
		t.Fatal("model input omitted the fixed sample evidence")
	}
	for _, required := range []string{`"synthetic":"true"`, "离线合成报文与记录", "攻击者已登录，知道 job-a 编号", "不带身份提交修改：HTTP 401", "没有取得正式文件正文"} {
		if !strings.Contains(prompt, required) {
			t.Fatalf("model input omitted authoritative sample context %q", required)
		}
	}
	if !strings.Contains(prompt, "不对应真实系统") || !strings.Contains(prompt, "不访问网络") {
		t.Fatal("model input must mark the cases as synthetic and prohibit network activity")
	}
	var result struct {
		Model string              `json:"model"`
		Usage llm.Usage           `json:"usage"`
		Draft deliveryReportDraft `json:"draft"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Model != "fixed-test-model" || result.Usage.InputTokens != 17 || result.Usage.OutputTokens != 23 || result.Draft.RequestPacket == "" {
		t.Fatalf("incomplete evaluation response: %+v", result)
	}
}

func TestReportEvalPromptInputLabelsSyntheticMaterials(t *testing.T) {
	sample, material, err := reporteval.Load("incomplete")
	if err != nil {
		t.Fatal(err)
	}
	input, err := reportEvalPromptInput(sample, material)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(input["task_description"], "不对应真实系统") || !strings.Contains(input["task_goal"], "不访问网络") {
		t.Fatalf("synthetic boundary missing from task context: description=%q goal=%q", input["task_description"], input["task_goal"])
	}
	if input["request_packet"] == "" || input["response_packet"] == "" {
		t.Fatal("incomplete HTTP evidence must preserve both the request and the partial response")
	}
	if input["evidence_transport"] != "http" {
		t.Fatalf("evidence transport=%q, want http", input["evidence_transport"])
	}
	if strings.Contains(input["evidence"], "/api/files/file-a/download") || strings.Contains(input["evidence"], "HTTP/1.1 200 OK") {
		t.Fatal("evidence inventory must not duplicate packets already passed in dedicated fields")
	}
	if !strings.Contains(input["request_packet"], "/api/files/file-a/download") {
		t.Fatal("dedicated request packet omitted the original request")
	}
	if !strings.Contains(input["request_line_index"], "1. GET /api/files/file-a/download") {
		t.Fatalf("request line index omitted the exact path: %q", input["request_line_index"])
	}
	if !strings.Contains(input["request_occurrence_index"], `"purpose":"请求他人文件"`) ||
		!strings.Contains(input["request_occurrence_index"], `"request_line":"GET /api/files/file-a/download"`) ||
		!strings.Contains(input["request_occurrence_index"], `"response_line":"HTTP/1.1 200 OK"`) {
		t.Fatalf("request occurrence index omitted its purpose, path, or result: %q", input["request_occurrence_index"])
	}
	if !strings.Contains(input["request_packet"], "X-Eval-Actor: user-b") {
		t.Fatal("synthetic identity marker must remain available verbatim for the Burp request")
	}
	if input["cvss_vector_hint"] != sample.Facts.CVSSVector {
		t.Fatalf("CVSS hint=%q, want %q", input["cvss_vector_hint"], sample.Facts.CVSSVector)
	}
	if want := "2026-11-01 10:00:00（北京时间）"; input["test_time_hint"] != want {
		t.Fatalf("test time hint=%q, want %q", input["test_time_hint"], want)
	}
	concurrency, concurrencyMaterial, err := reporteval.Load("concurrency")
	if err != nil {
		t.Fatal(err)
	}
	concurrencyInput, err := reportEvalPromptInput(concurrency, concurrencyMaterial)
	if err != nil {
		t.Fatal(err)
	}
	if concurrencyInput["test_tool_hint"] != concurrency.Facts.TestTool {
		t.Fatalf("test tool hint=%q, want %q", concurrencyInput["test_tool_hint"], concurrency.Facts.TestTool)
	}
	if strings.Count(concurrencyInput["request_line_index"], "POST /api/registrations") != 4 {
		t.Fatalf("request line index omitted repeated request count: %q", concurrencyInput["request_line_index"])
	}
	if strings.Count(concurrencyInput["request_occurrence_index"], `"request_line":"POST /api/registrations"`) != 4 ||
		!strings.Contains(concurrencyInput["request_occurrence_index"], `"purpose":"第三次并发提交"`) {
		t.Fatalf("request occurrence index did not preserve each repeated request: %q", concurrencyInput["request_occurrence_index"])
	}
	nonHTTP, nonHTTPMaterial, err := reporteval.Load("non-http")
	if err != nil {
		t.Fatal(err)
	}
	nonHTTPInput, err := reportEvalPromptInput(nonHTTP, nonHTTPMaterial)
	if err != nil {
		t.Fatal(err)
	}
	if nonHTTPInput["evidence_transport"] != "non_http" {
		t.Fatalf("non-HTTP evidence transport=%q", nonHTTPInput["evidence_transport"])
	}
	for _, command := range []string{
		"id",
		"stat -c '%a %U %G %n' /tmp/report-eval/backups/customer-notes.txt",
		"cat /tmp/report-eval/backups/customer-notes.txt",
		"cat /tmp/report-eval/backups/private-notes.txt",
	} {
		if !strings.Contains(nonHTTPInput["command_line_index"], `"command":"`+command+`"`) {
			t.Fatalf("command line index omitted the exact recorded command %q: %s", command, nonHTTPInput["command_line_index"])
		}
	}
}

func TestReportEvalReturnsSafeCompletionFailureCategory(t *testing.T) {
	t.Setenv("ARTEX_REPORT_EVAL_ENABLED", "true")
	tests := []struct {
		name        string
		result      string
		providerErr error
		wantMessage string
		wantRaw     string
		mustHide    string
	}{
		{name: "provider error", providerErr: errors.New("upstream token=secret-value"), wantMessage: "报告模型调用失败", mustHide: "secret-value"},
		{name: "invalid JSON", result: "not JSON", wantMessage: "模型未返回可解析的报告字段", wantRaw: "not JSON"},
		{name: "missing fields", result: `{}`, wantMessage: "模型报告字段不完整", wantRaw: `{}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := &reportEvalProvider{result: tt.result, err: tt.providerErr}
			s := &Server{llmProv: provider, llmOn: true, llmCfg: agent.Config{Model: "fixed-test-model"}, jwtKey: []byte("report-eval-test-signing-key")}
			token, err := signJWT(s.jwtKey)
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(http.MethodPost, "/api/report-eval/idor", nil)
			req.Header.Set("Authorization", "Bearer "+token)
			response := httptest.NewRecorder()
			s.Handler().ServeHTTP(response, req)
			if response.Code != http.StatusBadGateway {
				t.Fatalf("status=%d body=%s, want 502", response.Code, response.Body.String())
			}
			if !strings.Contains(response.Body.String(), tt.wantMessage) {
				t.Fatalf("body=%s, want safe category %q", response.Body.String(), tt.wantMessage)
			}
			if tt.wantRaw != "" && !strings.Contains(response.Body.String(), tt.wantRaw) {
				t.Fatalf("body=%s, want fixed-sample model output %q", response.Body.String(), tt.wantRaw)
			}
			if tt.name == "invalid JSON" {
				for _, want := range []string{`"stop_reason":"end_turn"`, `"content_block_types":["text"]`, `"output_tokens":23`} {
					if !strings.Contains(response.Body.String(), want) {
						t.Fatalf("body=%s, missing safe model diagnostic %q", response.Body.String(), want)
					}
				}
			}
			if tt.mustHide != "" && strings.Contains(response.Body.String(), tt.mustHide) {
				t.Fatalf("response leaked provider error detail: %s", response.Body.String())
			}
		})
	}
}

func TestDeliveryReportCompletionSystemIncludesEvidenceGuardrails(t *testing.T) {
	prompt := deliveryReportCompletionSystem()
	for _, required := range []string{
		"本次只生成交付报告草稿，不调用工具",
		"平台生成标题、含完整向量、分数和等级的 CVSS 4.0 评分行、五节标题和原始报文附件",
		"只返回这个 JSON 对象",
		`{"cvss_vector":"","description":"","attack_chain":"","test_process":"","burp_reproduction":"","remediation":""}`,
		"description 用短句写问题、成立条件、观察结果和评分依据",
		"test_process 第一行必须为“测试时间：<test_time_hint>”",
		"burp_reproduction 对 HTTP 场景附最小必要请求包",
		"不得声称已通过 Burp 发送或验证",
		"attack_chain 不超过 230 字",
		"attack_chain 只写一棵短树。单一流程的根节点使用实际页面或功能入口",
		"HTTP 节点原样复制 METHOD/path",
		"平台会添加 text 代码围栏",
		"首条证据请求采集时间",
		"不改变详细报告的章节和台账",
		"动笔前先从原始请求/响应、命令输出和执行记录整理事实",
		"根因（只有源码、配置或日志能证明时才填写，否则记为未知）",
		"不得称为真实用户资料、敏感数据或实际泄露",
		"禁止声称发生任何真实数据泄露或机密性影响",
		"输入标记 synthetic=true 或证据来源标为离线合成时，描述第一句必须写",
		"不得把样本内容本身称为“合成样本泄露”",
		"不得把 VC:L 描述成已确认、已证实、已观察到或局部发生的机密性影响",
		"VC:L 为待复核的潜在影响假设，真实数据影响未验证",
		"SQL 参数改变查询逻辑时只写“使用参数化查询”",
		"不得把预编译语句等同义实现并列为选项",
		"不得把删除服务端会话记录列为另一种措施",
		"缺陷行为未确认时只列补证步骤",
		"只有本地命令或终端证据、没有 HTTP 请求记录时",
		"修复建议只写一项与已确认行为相符的主要措施",
		"第二种措施与不同权限值均不得出现",
		"缺陷行为未确认时只列补证步骤，不给条件式代码修复建议",
		"业务约定一个编号只能登记一次而观察到重复记录时，描述为违反业务约定",
		"业务约定一个编号只能登记一次时，只建议阻止相同编号重复登记",
		"同一路径重复出现时，每一次都必须在攻击链独立成节点",
		"布尔注入的真、假条件各自成并列分支",
		"非 HTTP 攻击链以“本地终端记录”为根",
		"合成样本不能直接发往真实目标，也不能要求把样本值替换成真实凭据",
		"所有 HTTP 报告都必须有独立的 Burp 复现章节和至少一段足以复现核心结论的 HTTP 请求包",
		"材料没有 METHOD/path 时，代码块仍给出带占位符的请求行",
		"任何真实 Authorization、Cookie、Token、会话标识或个人数据都改成用途明确的占位符",
		"结果用自然语言说明业务状态，不得只写状态码/响应长度缩写或变量名",
		"避免测试脚本内部说法和难懂缩写",
		"正文以 800 字为参考预算",
		"无身份、真假条件等独立对照放在独立分支，不接在主流程之后造成因果暗示",
		"除第一行根节点外，攻击链代码块中每个非空行都必须以“├─”或“└─”开始",
		"不另加定级子标题",
		"不加子标题",
	} {
		if !strings.Contains(prompt, required) {
			t.Fatalf("report completion prompt is missing %q", required)
		}
	}
	if strings.Count(prompt, agent.DeliveryReportDraftRules) != 1 || strings.Contains(prompt, agent.DeliveryReportWritingRules) {
		t.Fatal("compatibility draft generation must use only its dedicated draft rules")
	}
}

func TestNormalizeDeliveryAttackChainGroupBranches(t *testing.T) {
	input := strings.Join([]string{
		"验证请求组",
		"   └─ 主流程",
		"      └─ GET /api/jobs/job-a",
		"         └─ 读取到作业状态",
		"                  └─ 独立对照",
		"                     └─ POST /api/jobs/job-a/types",
		"                        └─ 请求被拒绝",
	}, "\n")

	got := normalizeDeliveryAttackChainGroupBranches(input)
	want := strings.Join([]string{
		"验证请求组",
		"   ├─ 主流程",
		"      └─ GET /api/jobs/job-a",
		"         └─ 读取到作业状态",
		"   └─ 独立对照",
		"      └─ POST /api/jobs/job-a/types",
		"         └─ 请求被拒绝",
	}, "\n")
	if got != want {
		t.Fatalf("normalized attack-chain groups=%q, want %q", got, want)
	}
}

func TestDeliveryAttackChainGroupIndentationAccountsForTreeGuides(t *testing.T) {
	input := strings.Join([]string{
		"验证请求组",
		"├─ 主流程",
		"│  ├─ GET /api/jobs/job-a (基线)",
		"│  │  └─ 结果：类型为空",
		"│  ├─ POST /api/jobs/job-a/types (操作)",
		"│  │  └─ 结果：修改成功",
		"│  └─ GET /api/jobs/job-a (回读)",
		"│     └─ 结果：类型已修改",
		"└─ 独立对照",
		"   └─ POST /api/jobs/job-a/types (无身份)",
		"      └─ 结果：请求被拒绝",
	}, "\n")
	want := "```text\n" + strings.Join([]string{
		"验证请求组",
		"   ├─ 主流程",
		"      ├─ GET /api/jobs/job-a (基线)",
		"         └─ 结果：类型为空",
		"      ├─ POST /api/jobs/job-a/types (操作)",
		"         └─ 结果：修改成功",
		"      └─ GET /api/jobs/job-a (回读)",
		"         └─ 结果：类型已修改",
		"   └─ 独立对照",
		"      └─ POST /api/jobs/job-a/types (无身份)",
		"         └─ 结果：请求被拒绝",
	}, "\n") + "\n```"
	if got := ensureDeliveryAttackChainTextFence(input); got != want {
		t.Fatalf("normalized group indentation=%q, want %q", got, want)
	}
}

func TestDeliveryReportDraftKeepsRatingRationaleInDescriptionAndSanitizesSyntheticClaims(t *testing.T) {
	message, err := json.Marshal(deliveryReportDraft{
		CVSSVector:       "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
		Description:      "离线合成场景，未测试真实目标。读取敏感数据的影响尚未验证。VC:L 为待复核的潜在影响假设。",
		Remediation:      "阻止非授权用户访问敏感数据。",
		TestProcess:      "### 发现过程与攻击思路\n读取到合成内容。\n### 失败尝试与未验证项\n真实影响未验证。",
		BurpReproduction: "请求包供授权复现。\n```http\nGET /api/me HTTP/1.1\nHost: report-eval.invalid\n```",
		AttackChain:      "验证请求组\n└─ GET /api/me\n   └─ 返回用户信息",
	})
	if err != nil {
		t.Fatal(err)
	}
	draft, err := parseDeliveryReportDraft(
		llm.Message{Content: []llm.ContentBlock{llm.TextBlock(string(message))}},
		"end_turn",
		llm.Usage{},
		map[string]string{"synthetic": "true", "evidence_transport": "http"},
		0,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(draft.Description, "VC:L 为待复核的潜在影响假设。") || strings.Contains(draft.Description, "### 定级依据") {
		t.Fatalf("rating rationale did not remain in the description without an extra heading: %s", draft.Description)
	}
	for name, content := range map[string]string{
		"description": draft.Description,
		"remediation": draft.Remediation,
	} {
		if strings.Contains(content, "敏感数据") {
			t.Fatalf("synthetic %s retained a sensitive-data claim: %s", name, content)
		}
	}
	cleaned := normalizeDeliverySyntheticText("VC:L 基于能读取合成样本内容；真实机密性影响未验证，评分前提待复核。收紧文件权限至仅允许属主或授权组读取（如600或640）。")
	assetDescription := normalizeDeliverySyntheticText("本地低权限即可访问敏感备份，但仅观察到合成样本，真实数据影响未验证。修改了 所有者为 user-a 的作业脱敏设置。回读显示 所选类型、作业状态 及 正式文件可用状态 字段发生非预期变更。")
	for _, expected := range []string{"样本显示低权限用户可读取备份文件", "修改了 user-a 名下的作业", "回读显示所选类型、作业状态及正式文件可用状态字段"} {
		if !strings.Contains(assetDescription, expected) {
			t.Fatalf("synthetic report did not normalize awkward or overclaimed wording %q: %s", expected, assetDescription)
		}
	}
	if strings.Contains(assetDescription, "敏感备份") {
		t.Fatalf("synthetic report retained a sensitive-asset claim: %s", assetDescription)
	}
	for _, expected := range []string{
		"VC:L 为待复核的潜在影响假设",
		"真实数据影响未验证",
		"仅允许属主读取",
	} {
		if !strings.Contains(cleaned, expected) {
			t.Fatalf("synthetic wording was not normalized for %q: %s", expected, cleaned)
		}
	}
	if strings.Contains(cleaned, "或") {
		t.Fatalf("synthetic remediation still contains alternate permissions: %s", cleaned)
	}
	plainLanguage := normalizeDeliverySyntheticText("owner 为 eval-admin；total=0；id=reg-1；ok:true；items=[reg-1, reg-2, reg-3]；作业所有者或具备显式管理权限。")
	for _, expected := range []string{
		"所有者为 eval-admin",
		"记录数为 0",
		"新记录编号为 reg-1",
		"操作成功",
		"查询结果包含 3 条记录（编号 reg-1、reg-2、reg-3）",
		"作业所有者。",
	} {
		if !strings.Contains(plainLanguage, expected) {
			t.Fatalf("synthetic report did not replace shorthand %q: %s", expected, plainLanguage)
		}
	}
	reportTerms := normalizeDeliverySyntheticText("total为0；total:3；ID reg-1；items含reg-1/2/3；返回 ok:true；selectedTypes含name；selectedTypes 由空变为 name；selectedTypes 设为 [\"name\"]；确认 selectedTypes 已变；state为WAITING；state由WAITING变为SUCCESS；state 和 formalAvailable 状态变更；资源所有者或授权协作者")
	for _, expected := range []string{"记录数为 0", "记录数为 3", "新记录编号为 reg-1", "查询结果包含 3 条记录", "操作成功", "所选类型为 name", "所选类型由空变为 name", "所选类型设为 name", "确认 所选类型已变", "作业状态为等待中", "作业状态由等待中变为已完成", "作业状态与正式文件可用状态变更", "资源所有者"} {
		if !strings.Contains(reportTerms, expected) {
			t.Fatalf("report wording was not normalized for %q: %s", expected, reportTerms)
		}
	}
	if strings.Contains(reportTerms, "授权协作者") || strings.Contains(reportTerms, "selectedTypes") || strings.Contains(reportTerms, "formalAvailable") || strings.Contains(reportTerms, "state") || strings.Contains(reportTerms, "返回 操作成功") {
		t.Fatalf("synthetic remediation retained unsupported authorization alternatives: %s", reportTerms)
	}
	requestWithBody := "将 selectedTypes 设为 [\"name\"]\n```http\nPOST /api/jobs/job-a/types HTTP/1.1\nContent-Length: 26\n\n{\"selectedTypes\":[\"name\"]}\n```"
	normalizedRequest := normalizeDeliverySyntheticText(requestWithBody)
	if !strings.Contains(normalizedRequest, "将 所选类型设为 name") || !strings.Contains(normalizedRequest, `{"selectedTypes":["name"]}`) {
		t.Fatalf("synthetic prose changed or lost the exact HTTP request body: %s", normalizedRequest)
	}
}

func TestDeliveryReportDraftRestoresBurpSectionAndRedactsEvidencePacket(t *testing.T) {
	vector := "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N"
	message, err := json.Marshal(deliveryReportDraft{
		CVSSVector:  vector,
		Description: "普通用户可修改作业。\n### 定级依据\n观察到完整性变化。",
		Remediation: "在修改接口校验作业归属。",
		TestProcess: strings.Join([]string{
			"### 发现过程与攻击思路",
			"按步骤重放请求。",
			"### 失败尝试与未验证项",
			"其他资源未验证。",
		}, "\n"),
		AttackChain:      "验证请求组\n├─ 主流程\n│  └─ POST /api/jobs/job-a/types\n│     └─ 配置发生变化",
		BurpReproduction: "请求内容在报告字段中提供。",
	})
	if err != nil {
		t.Fatal(err)
	}
	draft, err := parseDeliveryReportDraft(llm.Message{Content: []llm.ContentBlock{llm.TextBlock(string(message))}}, "end_turn", llm.Usage{}, map[string]string{
		"evidence_transport": "http",
		"request_packet":     "证据绑定 1（漏洞验证）\nPOST /api/jobs/job-a/types HTTP/1.1\r\nHost: report-eval.invalid\r\nAuthorization: Bearer session-secret\r\nCookie: sid=cookie-secret\r\nContent-Type: application/json\r\nContent-Length: 18\r\n\r\n{\"token\":\"secret\"}",
	}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(draft.TestProcess, "### ") || !strings.HasPrefix(draft.TestProcess, "测试时间：未记录") {
		t.Fatalf("test process retained nested headings or lacks a time line: %s", draft.TestProcess)
	}
	burpSection := draft.BurpReproduction
	if !strings.Contains(burpSection, "请求包供渗透测试工程师") || !strings.Contains(burpSection, "不代表已通过 Burp 发送或验证") || !strings.Contains(burpSection, "POST /api/jobs/job-a/types HTTP/1.1") {
		t.Fatalf("Burp guidance or the request packet is missing: %s", burpSection)
	}
	if strings.Contains(burpSection, "Burp 不适用") {
		t.Fatalf("HTTP report was incorrectly marked not applicable: %s", burpSection)
	}
	if strings.Contains(burpSection, "session-secret") || strings.Contains(burpSection, "cookie-secret") || strings.Contains(burpSection, `"secret"`) {
		t.Fatalf("sensitive values leaked into the Burp request packet: %s", burpSection)
	}
}

func TestDeliveryReportDraftLabelsSyntheticMaterialAndNormalizesBurpSection(t *testing.T) {
	vector := "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N"
	message, err := json.Marshal(deliveryReportDraft{
		CVSSVector:       vector,
		Description:      "普通用户可修改其他用户设置。\n### 定级依据\n观察到配置变化。",
		Remediation:      "拒绝非所有者的修改请求。",
		TestProcess:      "### 发现过程与攻击思路\n重放修改请求。\n### 失败尝试与未验证项\n未检查其他资源。",
		BurpReproduction: "离线合成请求样例，不能直接发送到真实目标。\n```http\nPOST /api/jobs/job-a/types HTTP/1.1\nHost: report-eval.invalid\n```",
		AttackChain:      "验证请求组\n└─ POST /api/jobs/job-a/types\n   └─ 修改成功",
	})
	if err != nil {
		t.Fatal(err)
	}
	draft, err := parseDeliveryReportDraft(llm.Message{Content: []llm.ContentBlock{llm.TextBlock(string(message))}}, "end_turn", llm.Usage{}, map[string]string{
		"synthetic":          "true",
		"evidence_transport": "http",
		"request_packet":     "证据绑定 1（漏洞验证）\nPOST /api/jobs/job-a/types HTTP/1.1\r\nHost: report-eval.invalid\r\nX-Eval-Actor: user-b\r\nContent-Type: application/json\r\nContent-Length: 26\r\n\r\n{\"selectedTypes\":[\"name\"]}",
	}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(draft.Description, "离线合成场景，未测试真实目标。") {
		t.Fatalf("synthetic scope was not made explicit: %s", draft.Description)
	}
	if strings.Count(draft.Description, "未测试真实目标") != 1 {
		t.Fatalf("synthetic scope was duplicated: %s", draft.Description)
	}
	burpSection := draft.BurpReproduction
	for _, expected := range []string{
		"离线合成请求样例，不能直接发送到真实目标",
		"不代表已通过 Burp 发送或验证",
		"POST /api/jobs/job-a/types HTTP/1.1",
		"X-Eval-Actor: user-b",
		`{"selectedTypes":["name"]}`,
	} {
		if !strings.Contains(burpSection, expected) {
			t.Fatalf("synthetic Burp section is missing %q: %s", expected, burpSection)
		}
	}
	if strings.Count(burpSection, "建议复测请求") != 0 {
		t.Fatalf("duplicate model prose was retained in the Burp section: %s", burpSection)
	}
}

func TestDeliveryReportDraftAddsEvidenceRequestWhenModelOmitsPacket(t *testing.T) {
	vector := "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N"
	message, err := json.Marshal(deliveryReportDraft{
		CVSSVector:  vector,
		Description: "问题已观察。\n### 定级依据\n证据说明完整性影响。",
		Remediation: "校验资源归属。",
		TestProcess: "### 发现过程与攻击思路\n按步骤核对请求。\n### 失败尝试与未验证项\n没有其他失败记录。",
		AttackChain: "验证请求\n└─ POST /api/jobs/job-a/types\n   └─ 修改成功",
	})
	if err != nil {
		t.Fatal(err)
	}
	evidenceRequest := "证据绑定 1（测试基线）\nGET /api/jobs/job-a HTTP/1.1\r\nHost: report-eval.invalid\r\nContent-Length: 0\r\n\r\n\n\n证据绑定 2（漏洞验证）\nPOST /api/jobs/job-a/types?access_token=query-secret HTTP/1.1\r\nHost: report-eval.invalid\r\nAuthorization: Bearer session-secret\r\nCookie: sid=cookie-secret\r\nContent-Type: application/json\r\nContent-Length: 18\r\n\r\n{\"token\":\"secret\"}"
	draft, err := parseDeliveryReportDraft(llm.Message{Content: []llm.ContentBlock{llm.TextBlock(string(message))}}, "end_turn", llm.Usage{}, map[string]string{
		"evidence_transport": "http",
		"request_packet":     evidenceRequest,
	}, 0)
	if err != nil {
		t.Fatal(err)
	}
	burpSection := draft.BurpReproduction
	for _, expected := range []string{
		"请求包供渗透测试工程师在授权目标中导入 Burp Repeater",
		"不代表已通过 Burp 发送或验证",
		"POST /api/jobs/job-a/types?access_token=%5BREDACTED%5D HTTP/1.1",
		"Authorization: [REDACTED]",
		"Cookie: [REDACTED]",
		`"token":"[REDACTED]"`,
		"Content-Length: 22",
	} {
		if !strings.Contains(burpSection, expected) {
			t.Fatalf("Burp subsection is missing %q: %s", expected, burpSection)
		}
	}
	for _, secret := range []string{"query-secret", "session-secret", "cookie-secret", `"secret"`} {
		if strings.Contains(burpSection, secret) {
			t.Fatalf("Burp packet leaked %q: %s", secret, burpSection)
		}
	}
}

func TestDeliveryBurpEvidenceRequestKeepsEvalPacketsSeparate(t *testing.T) {
	packet := strings.Join([]string{
		"### 修改前查询 · 请求",
		"GET /api/jobs/job-a HTTP/1.1",
		"Host: report-eval.invalid",
		"",
		"",
		"### 其他用户提交修改 · 请求",
		"POST /api/jobs/job-a/types HTTP/1.1",
		"Host: report-eval.invalid",
		"Content-Type: application/json",
		"Content-Length: 18",
		"",
		`{"token":"secret"}`,
		"",
		"",
		"### 修改后查询 · 请求",
		"GET /api/jobs/job-a HTTP/1.1",
		"Host: report-eval.invalid",
		"",
		"",
		"### 不带身份提交修改 · 请求",
		"POST /api/jobs/job-a/types HTTP/1.1",
		"Host: report-eval.invalid",
		"Content-Type: application/json",
		"Content-Length: 26",
		"",
		`{"selectedTypes":["name"]}`,
	}, "\n")

	got := deliveryBurpEvidenceRequest(packet)
	if !strings.HasPrefix(got, "POST /api/jobs/job-a/types HTTP/1.1\r\n") {
		t.Fatalf("expected the proof request, got %q", got)
	}
	if strings.Contains(got, "GET /api/jobs/job-a HTTP/1.1") || strings.Contains(got, "### 修改后查询") {
		t.Fatalf("extracted request contains neighboring evidence: %q", got)
	}
	if strings.Contains(got, `"secret"`) || !strings.Contains(got, `"token":"[REDACTED]"`) {
		t.Fatalf("extracted request was not redacted: %q", got)
	}
}

func TestDeliveryBurpEvidenceRequestSelectsCoreConcurrentWrite(t *testing.T) {
	packet := strings.Join([]string{
		"### 提交前查询 · 请求",
		"GET /api/registrations?reference=EVAL-RACE HTTP/1.1",
		"Host: report-eval.invalid",
		"Content-Length: 0",
		"",
		"",
		"### 第一次并发提交 · 请求",
		"POST /api/registrations HTTP/1.1",
		"Host: report-eval.invalid",
		"Content-Type: application/json",
		"Content-Length: 25",
		"",
		`{"reference":"EVAL-RACE"}`,
		"",
		"",
		"### 提交后查询 · 请求",
		"GET /api/registrations?reference=EVAL-RACE HTTP/1.1",
		"Host: report-eval.invalid",
	}, "\n")
	got := deliveryBurpEvidenceRequest(packet)
	if !strings.HasPrefix(got, "POST /api/registrations HTTP/1.1\r\n") || !strings.Contains(got, `{"reference":"EVAL-RACE"}`) {
		t.Fatalf("Burp packet should select a repeated write request, got %q", got)
	}
}

func TestDeliveryAttackChainMovesIndependentControlToRootGroup(t *testing.T) {
	input := strings.Join([]string{
		"验证请求组",
		"├─ 主流程",
		"│  ├─ GET /api/registrations?reference=EVAL-RACE (基线)",
		"│  │  └─ 结果：记录数为 0",
		"│  ├─ 并发提交 2 次相同请求",
		"│  │  ├─ POST /api/registrations",
		"│  │  │  └─ 结果：HTTP 201，新记录编号为 reg-1",
		"│  │  └─ POST /api/registrations",
		"│  │     └─ 结果：HTTP 201，新记录编号为 reg-2",
		"│  └─ GET /api/registrations?reference=EVAL-RACE (回读)",
		"│     └─ 结果：记录数为 2",
		"│        └─ 独立对照",
		"│           └─ POST /api/registrations (缺少编号)",
		"│              └─ 结果：HTTP 400",
	}, "\n")
	requests := "POST /api/registrations HTTP/1.1\r\nContent-Length: 0\r\n\r\nPOST /api/registrations HTTP/1.1\r\nContent-Length: 0\r\n\r\n"
	got := ensureDeliveryAttackChainTextFenceWithEvidence(input, requests, true)
	for _, expected := range []string{"   ├─ 主流程", "   └─ 独立对照", "      └─ POST /api/registrations (缺少编号)"} {
		if !strings.Contains(got, expected) {
			t.Fatalf("attack-chain group was not kept at the root: missing %q in\n%s", expected, got)
		}
	}
	if strings.Contains(got, "                  └─ 独立对照") {
		t.Fatalf("independent control remains connected to the main flow:\n%s", got)
	}
}

func TestDeliveryAttackChainSeparatesUnlabeledControlRequest(t *testing.T) {
	input := strings.Join([]string{
		"验证请求组",
		"   └─ GET /api/registrations?reference=EVAL-RACE (回读)",
		"      └─ 结果：记录数为 3",
		"         └─ POST /api/registrations (缺少业务编号的提交)",
		"            └─ 结果：HTTP 400 Bad Request",
	}, "\n")
	want := strings.Join([]string{
		"验证请求组",
		"   ├─ GET /api/registrations?reference=EVAL-RACE (回读)",
		"      └─ 结果：记录数为 3",
		"   └─ 独立对照",
		"      └─ POST /api/registrations (缺少业务编号的提交)",
		"         └─ 结果：HTTP 400 Bad Request",
	}, "\n")
	got := ensureDeliveryAttackChainTextFenceWithEvidence(input, "", false)
	if got != "```text\n"+want+"\n```" {
		t.Fatalf("unlabeled control request remained attached to the main path:\n%s", got)
	}
}

func TestDeliveryAttackChainIndentsRootChildren(t *testing.T) {
	input := "本地终端记录\n├─ id (当前用户)\n   └─ 结果：eval-user\n├─ cat /tmp/report-eval/backups/customer-notes.txt\n   └─ 结果：读取到合成记录"
	want := "```text\n本地终端记录\n   ├─ id (当前用户)\n      └─ 结果：eval-user\n   └─ cat /tmp/report-eval/backups/customer-notes.txt\n      └─ 结果：读取到合成记录\n```"
	if got := ensureDeliveryAttackChainTextFence(input); got != want {
		t.Fatalf("root children indentation=%q, want %q", got, want)
	}
}

func TestDeliveryNonHTTPBurpSectionRemovesFabricatedRequest(t *testing.T) {
	content := strings.Join([]string{
		"### 发现过程与攻击思路",
		"使用本地命令读取样本。",
		"### Burp 复现",
		"Burp 不适用。",
		"```http",
		"GET /fabricated HTTP/1.1",
		"Host: example.invalid",
		"```",
	}, "\n")

	got := ensureDeliveryBurpSection(content, "", "non_http", false)
	if !strings.Contains(got, "Burp 不适用：本次证据为本地命令或终端输出。") {
		t.Fatalf("non-HTTP report is missing the required boundary: %s", got)
	}
	if strings.Contains(got, "```http") || strings.Contains(got, "/fabricated") {
		t.Fatalf("non-HTTP Burp section retained a fabricated HTTP request: %s", got)
	}
}

func TestDeliveryHTTPBurpSectionUsesOnlyRecordedRequests(t *testing.T) {
	recorded := "证据绑定 1（漏洞验证）\nGET /records/42 HTTP/1.1\r\nHost: app.example\r\n\r\n"
	got := ensureDeliveryBurpSection("Burp 不适用。", recorded, "http", false)
	if !strings.Contains(got, "GET /records/42 HTTP/1.1") || strings.Contains(got, "Burp 不适用") {
		t.Fatalf("HTTP evidence was not used for the Burp reproduction packet: %s", got)
	}

	fabricated := "```http\nGET /invented HTTP/1.1\nHost: app.example\n```"
	got = ensureDeliveryBurpSection(fabricated, "", "http", false)
	if strings.Contains(got, "/invented") || !strings.Contains(got, "<METHOD> <PATH> HTTP/1.1") {
		t.Fatalf("model-authored request was accepted without source evidence: %s", got)
	}

	got = ensureDeliveryBurpSection("", "GET /records/43 HTTP/1.1\r\n\r\n", "http", false)
	if !strings.Contains(got, "Host: <需从授权账号重新捕获>") || !strings.Contains(got, "原始请求未记录 Host") {
		t.Fatalf("request without Host was not marked incomplete: %s", got)
	}
}

func TestDeliveryReportMarkdownFallbackParsesRequiredSections(t *testing.T) {
	vector := "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N"
	markdown := `# 测试系统 越权修改：普通用户可修改他人配置
CVSS 4.0：` + vector + ` 评分 6.1（中）

## 描述
普通用户可修改其他用户的配置。

## 攻击链路
普通用户
└─ POST /api/jobs/job-a/types
   └─ 配置发生变化

## 测试过程
测试时间：未记录

普通用户重放更新请求并回读配置。未测试其他作业状态。

## Burp 复现
离线合成请求样例，不能直接发送到真实目标。以下请求包供渗透测试工程师在授权目标中导入 Burp Repeater 复现或复测；请求包本身不代表已通过 Burp 发送或验证。
~~~http
POST /api/jobs/job-a/types HTTP/1.1
Host: report-eval.invalid
X-Eval-Actor: user-b
~~~

## 修复建议
服务端校验作业归属后再更新配置。`
	input := map[string]string{"cvss_vector_hint": vector}
	draft, usage, err := completeDeliveryReportWith(context.Background(), input, 4, func(_ context.Context, request llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
		if len(request.Tools) != 0 {
			t.Fatalf("fallback request exposed %d tools", len(request.Tools))
		}
		return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock(markdown)}}, "end_turn", llm.Usage{OutputTokens: 80}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if usage.OutputTokens != 80 || draft.CVSSVector != vector || draft.EvidenceVersion != 4 {
		t.Fatalf("metadata lost during Markdown fallback: usage=%+v draft=%+v", usage, draft)
	}
	for _, value := range []string{draft.Description, draft.Remediation, draft.TestProcess, draft.BurpReproduction} {
		if strings.TrimSpace(value) == "" {
			t.Fatal("Markdown fallback returned an empty report field")
		}
	}
	if !strings.HasPrefix(draft.AttackChain, "```text\n") || !strings.Contains(draft.AttackChain, "POST /api/jobs/job-a/types") {
		t.Fatalf("Markdown fallback did not preserve and fence the attack chain: %s", draft.AttackChain)
	}
	if !strings.Contains(draft.BurpReproduction, "不代表已通过 Burp 发送或验证") {
		t.Fatalf("Markdown fallback lost the Burp request usage boundary: %s", draft.BurpReproduction)
	}
}

func TestDeliveryReportDraftRemovesLegacySubheadings(t *testing.T) {
	vector := "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N"
	raw, err := json.Marshal(deliveryReportDraft{
		CVSSVector:  vector,
		Description: "普通用户可修改作业。定级依据：现有材料显示配置已变化。",
		Remediation: "服务端校验作业归属。",
		TestProcess: "测试时间：2026-11-01 10:00:00（北京时间）\n步骤。### 发现过程与攻击思路：重放修改请求。### 失败尝试与未验证项：没有记录失败尝试。",
		AttackChain: "普通用户\n└─ POST /api/jobs/job-a/types\n   └─ 配置改变",
	})
	if err != nil {
		t.Fatal(err)
	}
	draft, err := parseDeliveryReportDraft(llm.Message{Content: []llm.ContentBlock{llm.TextBlock(string(raw))}}, "end_turn", llm.Usage{}, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{draft.Description, draft.TestProcess, draft.BurpReproduction} {
		if strings.Contains(value, "### ") || strings.Contains(value, "。### ") {
			t.Fatalf("legacy subheading remained in a report field: %q", value)
		}
	}
	if !strings.Contains(draft.Description, "现有材料显示配置已变化。") {
		t.Fatalf("rating rationale was not retained in the description: %q", draft.Description)
	}
	joinedHeading := normalizeDeliveryDraftSubheadings("结果。### 定级依据影响已观察。", "定级依据")
	if !strings.Contains(joinedHeading, "\n### 定级依据\n影响已观察。") {
		t.Fatalf("heading joined directly to prose was not normalized: %q", joinedHeading)
	}
	compactBurpHeading := normalizeDeliveryDraftSubheadings("请求未实际发送。Burp复现：建议在授权环境重放。", "Burp 复现")
	if !strings.Contains(compactBurpHeading, "\n### Burp 复现\n建议在授权环境重放。") {
		t.Fatalf("compact Burp label was not normalized to the fixed heading: %q", compactBurpHeading)
	}
	if strings.Contains(draft.TestProcess, "发现过程与攻击思路") || strings.Contains(draft.TestProcess, "失败尝试与未验证项") {
		t.Fatalf("legacy test-process headings were not removed: %q", draft.TestProcess)
	}
	report := strings.Join([]string{
		"# 测试系统 作业越权",
		"CVSS 4.0：" + vector + " 评分待复核",
		"## 描述\n\n" + draft.Description,
		"## 攻击链路\n\n" + draft.AttackChain,
		"## 测试过程\n\n" + draft.TestProcess,
		"## Burp 复现\n\n" + draft.BurpReproduction,
		"## 修复建议\n\n" + draft.Remediation,
	}, "\n\n")
	if err := validateDeliveryReportTemplate(report, vector); err != nil {
		t.Fatalf("normalized draft does not meet the report template: %v", err)
	}
}

func TestDeliveryReportCompletionUsesProvidedCVSSVectorHint(t *testing.T) {
	sample, material, err := reporteval.Load("incomplete")
	if err != nil {
		t.Fatal(err)
	}
	input, err := reportEvalPromptInput(sample, material)
	if err != nil {
		t.Fatal(err)
	}
	modelDraft := `{"cvss_vector":"not-a-cvss-vector","description":"线索待核实。\n当前证据不足。","remediation":"先补齐响应正文。","test_process":"测试时间：未记录\n复核现有请求。文件内容未取得。","burp_reproduction":"请求包供授权复现。\n\u0060\u0060\u0060http\nGET /api/files/file-a/download HTTP/1.1\nHost: report-eval.invalid\n\u0060\u0060\u0060","attack_chain":"用户 B 请求文件\n└─ 仅留存 HTTP 200 响应头"}`
	draft, _, err := completeDeliveryReportWith(context.Background(), input, 0, func(context.Context, llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
		return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock(modelDraft)}}, "end_turn", llm.Usage{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if draft.CVSSVector != sample.Facts.CVSSVector {
		t.Fatalf("CVSS vector=%q, want trusted hint %q", draft.CVSSVector, sample.Facts.CVSSVector)
	}
}

func TestStripDeliveryDraftSectionHeading(t *testing.T) {
	for _, tc := range []struct {
		name    string
		content string
		section string
		want    string
	}{
		{"leading duplicate", "## 描述\n\n正文。", "描述", "正文。"},
		{"remediation section heading", "## 修复建议\n\n服务端校验归属。", "修复建议", "服务端校验归属。"},
		{"repeated leading duplicate", "## 描述\n## 描述\n正文。", "描述", "正文。"},
		{"preserve different heading", "### 定级依据\n正文。", "描述", "### 定级依据\n正文。"},
		{"preserve inline occurrence", "正文中引用 ## 描述。", "描述", "正文中引用 ## 描述。"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := stripDeliveryDraftSectionHeading(tc.content, tc.section); got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}

func TestEnsureDeliveryAttackChainTextFence(t *testing.T) {
	plain := "普通用户登录\n└─ GET /api/me\n   └─ 返回用户信息"
	formatted := "```text\n普通用户登录\n   └─ GET /api/me\n      └─ 返回用户信息\n```"
	if got, want := ensureDeliveryAttackChainTextFence(plain), formatted; got != want {
		t.Fatalf("plain chain=%q, want %q", got, want)
	}
	if got, want := ensureDeliveryAttackChainTextFence("text\n"+plain), formatted; got != want {
		t.Fatalf("chain with duplicated language label=%q, want %q", got, want)
	}
	arrowChain := "入口：普通用户登录 -> POST /api/jobs/job-a/types -> 作业状态发生变化"
	if got, want := ensureDeliveryAttackChainTextFence(arrowChain), "```text\n普通用户登录\n   └─ POST /api/jobs/job-a/types\n      └─ 作业状态发生变化\n```"; got != want {
		t.Fatalf("arrow chain=%q, want %q", got, want)
	}
	if got, want := ensureDeliveryAttackChainTextFence("用户持有会话\n    └─ ↓\n    └─ > GET /api/me"), "```text\n用户持有会话\n   └─ GET /api/me\n```"; got != want {
		t.Fatalf("decorated tree=%q, want %q", got, want)
	}
	arrowInText := "用户提交参数含 ↓ 字符\n   ├─ 请求 A 返回 200\n   └─ 请求 B 返回 403"
	if got := ensureDeliveryAttackChainTextFence(arrowInText); got != "```text\n"+arrowInText+"\n```" {
		t.Fatalf("down arrow in prose changed the tree: %q", got)
	}
	misaligned := "登记请求\n└─ 并发提交相同编号\n   ├─ 请求 A 返回 201\n│  └─ 回读查询得到三条记录"
	if got, want := ensureDeliveryAttackChainTextFence(misaligned), "```text\n登记请求\n   └─ 并发提交相同编号\n      ├─ 请求 A 返回 201\n      └─ 回读查询得到三条记录\n```"; got != want {
		t.Fatalf("misaligned tree=%q, want %q", got, want)
	}
	decorated := "```text\n用户已登录且知晓目标作业编号\n   └─ ↓\n   └─ POST /api/jobs/job-a/types\n   └─ ↓\n   └─ 服务端未校验所有权，直接接受修改\n```"
	want := "```text\n用户已登录且知晓目标作业编号\n   └─ POST /api/jobs/job-a/types\n      └─ 服务端未校验所有权，直接接受修改\n```"
	if got := ensureDeliveryAttackChainTextFence(decorated); got != want {
		t.Fatalf("decorated model tree=%q, want %q", got, want)
	}
	flatConcurrent := "GET /api/items?key=x\n   ├─ HTTP 200 total=0\n   ├─ 并发提交 POST /api/items\n   ├─ POST /api/items\n   ├─ HTTP 201 id=1\n   ├─ POST /api/items\n   ├─ HTTP 201 id=2\n   ├─ GET /api/items?key=x\n   └─ HTTP 200 total=2"
	concurrentRequests := "POST /api/items HTTP/1.1\nContent-Length: 0\n\nPOST /api/items HTTP/1.1\nContent-Length: 0\n\n"
	concurrentWant := "```text\nGET /api/items?key=x\n   └─ HTTP 200 total=0\n      ├─ 并发提交 2 次相同请求\n      │  ├─ POST /api/items\n      │  │  └─ HTTP 201 id=1\n      │  └─ POST /api/items\n      │     └─ HTTP 201 id=2\n      └─ GET /api/items?key=x\n         └─ HTTP 200 total=2\n```"
	if got := ensureDeliveryAttackChainTextFenceWithEvidence(flatConcurrent, concurrentRequests, true); got != concurrentWant {
		t.Fatalf("flat concurrent chain=%q, want %q", got, concurrentWant)
	}
	nestedConcurrent := "GET /api/items?key=x\n   └─ HTTP 200 total=0\n      ├─ 并发提交 POST /api/items\n      │  ├─ HTTP 201 id=1\n      │  └─ HTTP 201 id=2\n      └─ GET /api/items?key=x\n         └─ HTTP 200 total=2"
	if got := ensureDeliveryAttackChainTextFenceWithEvidence(nestedConcurrent, concurrentRequests, true); got != concurrentWant {
		t.Fatalf("nested concurrent chain=%q, want %q", got, concurrentWant)
	}
	concurrentThree := "GET /api/registrations?reference=EVAL-RACE\n   └─ HTTP 200 total=0\n      └─ 并发父节点：\n         └─ POST /api/registrations\n            └─ HTTP 201 id=reg-1\n               └─ POST /api/registrations\n                  └─ HTTP 201 id=reg-2\n                     └─ POST /api/registrations\n                        └─ HTTP 201 id=reg-3\n                           └─ GET /api/registrations?reference=EVAL-RACE\n                              └─ HTTP 200 total=3"
	requestPacket := strings.Join([]string{
		"### 提交前查询 · 请求\nGET /api/registrations?reference=EVAL-RACE HTTP/1.1\r\nContent-Length: 0\r\n\r\n",
		"### 第一次并发提交 · 请求\nPOST /api/registrations HTTP/1.1\r\nContent-Length: 25\r\n\r\n{\"reference\":\"EVAL-RACE\"}",
		"### 第二次并发提交 · 请求\nPOST /api/registrations HTTP/1.1\r\nContent-Length: 25\r\n\r\n{\"reference\":\"EVAL-RACE\"}",
		"### 第三次并发提交 · 请求\nPOST /api/registrations HTTP/1.1\r\nContent-Length: 25\r\n\r\n{\"reference\":\"EVAL-RACE\"}",
		"### 提交后查询 · 请求\nGET /api/registrations?reference=EVAL-RACE HTTP/1.1\r\nContent-Length: 0\r\n\r\n",
		"### 缺少业务编号的提交 · 请求\nPOST /api/registrations HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}",
	}, "\n\n")
	if method, path, count := repeatedDeliveryRequest(requestPacket, "并发父节点"); method != http.MethodPost || path != "/api/registrations" || count != 3 {
		t.Fatalf("actual packet repetition=%s %s x%d", method, path, count)
	}
	concurrentThreeWant := "```text\nGET /api/registrations?reference=EVAL-RACE\n   └─ HTTP 200 total=0\n      ├─ 并发提交 3 次相同请求\n      │  ├─ POST /api/registrations\n      │  │  └─ HTTP 201 id=reg-1\n      │  ├─ POST /api/registrations\n      │  │  └─ HTTP 201 id=reg-2\n      │  └─ POST /api/registrations\n      │     └─ HTTP 201 id=reg-3\n      └─ GET /api/registrations?reference=EVAL-RACE\n         └─ HTTP 200 total=3\n```"
	if got := ensureDeliveryAttackChainTextFenceWithEvidence(concurrentThree, requestPacket, true); got != concurrentThreeWant {
		t.Fatalf("concurrent evidence with unrelated same-path request was normalized incorrectly:\n%s\nwant:\n%s", got, concurrentThreeWant)
	}
	omittedFirstConcurrentRequest := "验证请求组\n├─ 主流程\n│  ├─ GET /api/registrations?reference=EVAL-RACE (基线)\n│  │  └─ 结果：HTTP 200 OK，total 为 0\n│  ├─ 并发提交 3 次相同请求\n│  │  ├─ 结果：HTTP 201 Created，id 为 reg-1\n│  │  ├─ POST /api/registrations (第二次并发提交)\n│  │  │  └─ 结果：HTTP 201 Created，id 为 reg-2\n│  │  └─ POST /api/registrations (第三次并发提交)\n│  │     └─ 结果：HTTP 201 Created，id 为 reg-3\n│  └─ GET /api/registrations?reference=EVAL-RACE (回读)\n│     └─ 结果：HTTP 200 OK，total 为 3"
	repairedConcurrentChain := ensureDeliveryAttackChainTextFenceWithEvidence(omittedFirstConcurrentRequest, requestPacket, true)
	if got := strings.Count(repairedConcurrentChain, "POST /api/registrations"); got != 3 {
		t.Fatalf("normalizer left an omitted concurrent request node: got %d POST nodes in\n%s", got, repairedConcurrentChain)
	}
	firstConcurrentPost := strings.Index(repairedConcurrentChain, "POST /api/registrations")
	firstConcurrentResult := strings.Index(repairedConcurrentChain, "id 为 reg-1")
	secondConcurrentPost := strings.Index(repairedConcurrentChain[firstConcurrentPost+1:], "POST /api/registrations")
	if firstConcurrentPost < 0 || firstConcurrentResult < firstConcurrentPost || secondConcurrentPost < 0 ||
		firstConcurrentPost+1+secondConcurrentPost < firstConcurrentResult {
		t.Fatalf("orphaned first response was not attached to its reconstructed request:\n%s", repairedConcurrentChain)
	}
	unrelatedConcurrentRequest := "验证请求组\n├─ 主流程\n│  ├─ GET /api/registrations?reference=EVAL-RACE (基线)\n│  ├─ 并发提交 3 次相同请求\n│  │  ├─ 结果：HTTP 201 Created，id 为 reg-1\n│  │  ├─ POST /api/registrations\n│  │  │  └─ 结果：HTTP 201 Created，id 为 reg-2\n│  │  └─ POST /api/audit\n│  │     └─ 结果：HTTP 202 Accepted\n│  └─ GET /api/registrations?reference=EVAL-RACE (回读)"
	preservedUnrelatedChain := ensureDeliveryAttackChainTextFenceWithEvidence(unrelatedConcurrentRequest, requestPacket, true)
	if !strings.Contains(preservedUnrelatedChain, "POST /api/audit") || !strings.Contains(preservedUnrelatedChain, "HTTP 202 Accepted") {
		t.Fatalf("normalizer discarded an unrelated request or its result from the concurrent group:\n%s", preservedUnrelatedChain)
	}
	ambiguous := "普通用户\n   ├─ 请求 A 返回 200\n   └─ 请求 B 返回 403"
	if got := ensureDeliveryAttackChainTextFence(ambiguous); got != "```text\n"+ambiguous+"\n```" {
		t.Fatalf("ambiguous branches were converted to a sequence: %q", got)
	}
	fenced := formatted
	if got := ensureDeliveryAttackChainTextFence(fenced); got != fenced {
		t.Fatalf("already fenced chain changed: %q", got)
	}
}

func TestEnsureDeliveryAttackChainUsesFirstEvidenceNodeWhenRootMissing(t *testing.T) {
	input := "├─ GET /api/items\n   └─ 200 OK\n└─ POST /api/items\n   └─ 201 Created"
	want := "```text\nGET /api/items\n   └─ 200 OK\n└─ POST /api/items\n   └─ 201 Created\n```"
	if got := ensureDeliveryAttackChainTextFence(input); got != want {
		t.Fatalf("rootless attack chain did not use its first request as the root: %q", got)
	}
	if got, want := ensureDeliveryAttackChainTextFence("Root\n└─ GET /api/items"), "```text\nGET /api/items\n```"; got != want {
		t.Fatalf("placeholder root did not fall back to the first request: got %q want %q", got, want)
	}
}

func TestRepeatedDeliveryRequestRequiresUnambiguousMatch(t *testing.T) {
	packet := "POST /api/a HTTP/1.1\n\nPOST /api/a HTTP/1.1\n\nPOST /api/b HTTP/1.1\n\nPOST /api/b HTTP/1.1\n\nPOST /api/b HTTP/1.1"
	if method, path, count := repeatedDeliveryRequest(packet, "并发提交相同请求"); method != "" || path != "" || count != 0 {
		t.Fatalf("ambiguous repeated requests selected %s %s x%d", method, path, count)
	}
	if method, path, count := repeatedDeliveryRequest(packet, "并发提交 POST /api/a"); method != http.MethodPost || path != "/api/a" || count != 2 {
		t.Fatalf("matched repeated request=%s %s x%d", method, path, count)
	}
	packetWithDifferentBody := strings.Join([]string{
		"### 第一次并发提交 · 请求",
		"POST /api/registrations HTTP/1.1\r\nContent-Length: 25\r\n\r\n{\"reference\":\"EVAL-RACE\"}",
		"### 第二次并发提交 · 请求",
		"POST /api/registrations HTTP/1.1\r\nContent-Length: 25\r\n\r\n{\"reference\":\"EVAL-RACE\"}",
		"### 第三次并发提交 · 请求",
		"POST /api/registrations HTTP/1.1\r\nContent-Length: 25\r\n\r\n{\"reference\":\"EVAL-RACE\"}",
		"### 缺少业务编号的提交 · 请求",
		"POST /api/registrations HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}",
	}, "\n\n")
	if method, path, count := repeatedDeliveryRequest(packetWithDifferentBody, "并发提交 POST /api/registrations"); method != http.MethodPost || path != "/api/registrations" || count != 3 {
		t.Fatalf("request bodies were not distinguished: %s %s x%d", method, path, count)
	}
}

func TestDeliveryReportConcurrencyEvidenceHint(t *testing.T) {
	if !hasExplicitDeliveryConcurrencyEvidence(map[string]string{"summary": "同一账号并发提交3次相同请求"}) {
		t.Fatal("explicitly tested concurrency was not recognized")
	}
	if hasExplicitDeliveryConcurrencyEvidence(map[string]string{"summary": "并发未测试"}) {
		t.Fatal("unverified concurrency was accepted as evidence")
	}
}

func TestDeliveryReportDraftDisablesConfiguredResponsesReasoning(t *testing.T) {
	modelDraft := `{"cvss_vector":"CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:H/VA:L/SC:N/SI:L/SA:N","description":"问题描述。\n有可复核证据。","remediation":"在服务端校验资源归属。","test_process":"测试时间：未记录\n用授权账号核对请求和响应。批量编号未验证。","burp_reproduction":"请求包供渗透测试工程师导入 Repeater。","attack_chain":"普通用户\n└─ 修改请求\n   └─ 其他用户数据发生变化"}`
	receivedCh := make(chan map[string]json.RawMessage, 1)
	providerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/responses" {
			t.Errorf("request path=%q, want /v1/responses", r.URL.Path)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read request body: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		var received map[string]json.RawMessage
		if err := json.Unmarshal(body, &received); err != nil {
			t.Errorf("decode request body: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		receivedCh <- received
		w.Header().Set("Content-Type", "application/json")
		response := map[string]any{
			"status": "completed",
			"output": []map[string]any{{
				"type": "message", "role": "assistant",
				"content": []map[string]any{{"type": "output_text", "text": modelDraft}},
			}},
			"usage": map[string]int{"input_tokens": 1200, "output_tokens": 420},
		}
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Errorf("write model response: %v", err)
		}
	}))
	defer providerServer.Close()

	provider, err := (agent.Config{
		Format: llm.FormatOpenAIResponses, BaseURL: providerServer.URL + "/v1",
		Model: "qwen3.8-flash", APIKey: "test-provider-key", ReasoningEffort: "xhigh",
	}).NewProvider()
	if err != nil {
		t.Fatal(err)
	}
	draft, usage, err := completeDeliveryReportWith(context.Background(), map[string]string{
		"task_description": "合成评测任务", "request_packet": "GET /item/1 HTTP/1.1",
	}, 7, provider.Complete)
	if err != nil {
		t.Fatal(err)
	}
	received := <-receivedCh
	var request struct {
		Instructions string `json:"instructions"`
		Reasoning    struct {
			Effort string `json:"effort"`
		} `json:"reasoning"`
	}
	receivedJSON, err := json.Marshal(received)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(receivedJSON, &request); err != nil {
		t.Fatal(err)
	}
	if request.Reasoning.Effort != "none" {
		t.Fatalf("Responses API reasoning effort=%q, want none for strict JSON output", request.Reasoning.Effort)
	}
	if !strings.Contains(request.Instructions, "保存前在本次输出中核对结论、限制、修复和链路") {
		t.Fatal("report request did not include the same-Reporter self-check rules")
	}
	if draft.Description == "" || usage.OutputTokens != 420 {
		t.Fatalf("draft=%+v usage=%+v", draft, usage)
	}
}
