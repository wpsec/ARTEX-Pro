package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Autumn-27/norma/llm"
	"github.com/wpsec/ARTEX-local/agent"
	"github.com/wpsec/ARTEX-local/db"
	"github.com/wpsec/ARTEX-local/evidence"
)

const (
	deliveryReportMaxBytes         = 8 << 20
	deliveryReportEvidenceMaxBytes = 4 << 20
	deliveryEvidenceAppendixMarker = "<!-- artex:bound-traffic-evidence -->"
)

var (
	errDeliveryReportInvalidJSON = errors.New("模型没有返回有效的报告 JSON")
	errDeliveryReportMissingBody = errors.New("报告缺少必需内容")
)

const deliveryReportMaxTokens = 4096

type deliveryReportOutputError struct {
	cause            error
	raw              string
	stopReason       string
	contentBlockType []string
	outputTokens     int
}

func (e *deliveryReportOutputError) Error() string { return e.cause.Error() }

func (e *deliveryReportOutputError) Unwrap() error { return e.cause }

type deliveryReportAccess struct {
	task      *Task
	taskID    int64
	finding   *db.DBFinding
	findingID int64
}

type deliveryReportDraft struct {
	CVSSVector       string `json:"cvss_vector"`
	Description      string `json:"description"`
	AttackChain      string `json:"attack_chain"`
	TestProcess      string `json:"test_process"`
	BurpReproduction string `json:"burp_reproduction"`
	Remediation      string `json:"remediation"`
	RequestPacket    string `json:"request_packet"`
	ResponsePacket   string `json:"response_packet"`
	EvidenceVersion  int64  `json:"evidence_version"`
}

func (s *Server) deliveryReportAccess(w http.ResponseWriter, r *http.Request) (deliveryReportAccess, bool) {
	taskID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || taskID <= 0 {
		writeErr(w, http.StatusBadRequest, "任务编号无效")
		return deliveryReportAccess{}, false
	}
	task, ok := s.m.Task(strconv.FormatInt(taskID, 10))
	if !ok || task == nil {
		writeErr(w, http.StatusNotFound, "任务不存在")
		return deliveryReportAccess{}, false
	}
	findingID, err := strconv.ParseInt(r.PathValue("finding_id"), 10, 64)
	if err != nil || findingID <= 0 {
		writeErr(w, http.StatusBadRequest, "漏洞编号无效")
		return deliveryReportAccess{}, false
	}
	finding, err := s.m.pg.GetFinding(findingID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return deliveryReportAccess{}, false
	}
	if finding == nil {
		writeErr(w, http.StatusNotFound, "漏洞不存在")
		return deliveryReportAccess{}, false
	}
	if _, _, allowed := findingProvenanceInTask(task, finding.TaskID); !allowed {
		writeErr(w, http.StatusNotFound, "漏洞不属于当前任务或其继承范围")
		return deliveryReportAccess{}, false
	}
	return deliveryReportAccess{task: task, taskID: taskID, finding: finding, findingID: findingID}, true
}

func (s *Server) getFindingDeliveryReport(w http.ResponseWriter, r *http.Request) {
	access, ok := s.deliveryReportAccess(w, r)
	if !ok {
		return
	}
	report, err := s.m.pg.GetFindingDeliveryReport(access.taskID, access.findingID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if report == nil {
		writeErr(w, http.StatusNotFound, "漏洞不存在")
		return
	}
	writeJSON(w, http.StatusOK, report)
}

func (s *Server) saveFindingDeliveryReport(w http.ResponseWriter, r *http.Request) {
	access, ok := s.deliveryReportAccess(w, r)
	if !ok {
		return
	}
	var input struct {
		Content         string `json:"content"`
		CVSSVector      string `json:"cvss_vector"`
		EvidenceVersion *int64 `json:"evidence_version"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, deliveryReportMaxBytes)).Decode(&input); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("请求内容无效或超过 %d MiB", deliveryReportMaxBytes>>20))
		return
	}
	if strings.TrimSpace(input.Content) == "" || input.EvidenceVersion == nil {
		writeErr(w, http.StatusBadRequest, "报告正文和证据版本必填")
		return
	}
	vector, ok := normalizeCVSS4BaseVector(input.CVSSVector)
	if !ok {
		writeErr(w, http.StatusBadRequest, "CVSS 4.0 Base 向量无效")
		return
	}
	if err := validateDeliveryReportTemplate(input.Content, vector); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	content, err := s.appendDeliveryTrafficEvidence(r.Context(), access.findingID, *input.EvidenceVersion, input.Content)
	if errors.Is(err, db.ErrEvidenceConflict) {
		writeErr(w, http.StatusConflict, "漏洞证据已变化，请刷新后重新保存")
		return
	}
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, "附加完整 HTTP 流量证据失败："+err.Error())
		return
	}
	err = s.m.pg.SaveFindingDeliveryReport(r.Context(), access.taskID, access.findingID, *input.EvidenceVersion, content, vector)
	if errors.Is(err, db.ErrEvidenceConflict) || errors.Is(err, db.ErrTaskArchiveState) {
		writeErr(w, http.StatusConflict, "证据已变化或任务正在归档，请刷新后重新保存")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	report, err := s.m.pg.GetFindingDeliveryReport(access.taskID, access.findingID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, report)
}

func (s *Server) generateFindingDeliveryReport(w http.ResponseWriter, r *http.Request) {
	access, ok := s.deliveryReportAccess(w, r)
	if !ok {
		return
	}
	traffic, err := s.m.pg.GetFindingTraffic(r.Context(), access.findingID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "读取已绑定流量失败："+err.Error())
		return
	}
	if traffic.Version != access.finding.EvidenceVersion {
		writeErr(w, http.StatusConflict, "漏洞证据刚刚发生变化，请重新生成")
		return
	}
	requestPacket, responsePacket, err := s.deliveryTrafficPackets(traffic.Bindings)
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, "读取已绑定的真实流量失败："+err.Error())
		return
	}
	draft, err := s.completeDeliveryReport(r.Context(), access,
		requestPacket,
		responsePacket,
		traffic.Version,
		len(traffic.Bindings) > 0,
		deliveryEvidenceTimeIndex(traffic.Bindings),
		deliveryEvidenceTestTimeHint(traffic.Bindings),
	)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "生成交付报告草稿失败："+err.Error())
		return
	}
	latestTraffic, err := s.m.pg.GetFindingTraffic(r.Context(), access.findingID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "复核漏洞证据版本失败")
		return
	}
	if latestTraffic.Version != traffic.Version {
		writeErr(w, http.StatusConflict, "生成期间漏洞证据发生变化，请重新生成")
		return
	}
	draft.RequestPacket = requestPacket
	draft.ResponsePacket = responsePacket
	draft.EvidenceVersion = traffic.Version
	draft.CVSSVector, ok = normalizeCVSS4BaseVector(draft.CVSSVector)
	if !ok {
		writeErr(w, http.StatusBadGateway, "模型返回的 CVSS 4.0 Base 向量无效，请重试")
		return
	}
	writeJSON(w, http.StatusOK, draft)
}

func (s *Server) completeDeliveryReport(ctx context.Context, access deliveryReportAccess, requestPacket, responsePacket string, evidenceVersion int64, hasHTTPBindings bool, evidenceTimeIndex, testTimeHint string) (deliveryReportDraft, error) {
	evidenceTransport := "unknown"
	if hasHTTPBindings {
		evidenceTransport = "http"
	}
	requestOccurrenceIndex, err := deliveryReportRequestOccurrenceIndex(requestPacket, responsePacket)
	if err != nil {
		return deliveryReportDraft{}, err
	}
	input := map[string]string{
		"task_description":                  access.task.Description,
		"task_goal":                         access.task.Goal,
		"finding_name":                      access.finding.Name,
		"vulnerability_class":               access.finding.VulnClass,
		"severity":                          access.finding.Severity,
		"summary":                           access.finding.Summary,
		"evidence":                          access.finding.Evidence,
		"existing_detailed_report":          access.finding.Report,
		"existing_detailed_report_is_stale": strconv.FormatBool(access.finding.Report != "" && access.finding.ReportEvidenceVersion != access.finding.EvidenceVersion),
		"request_packet":                    requestPacket,
		"request_line_index":                deliveryReportRequestLineIndex(requestPacket),
		"request_occurrence_index":          requestOccurrenceIndex,
		"response_packet":                   responsePacket,
		"evidence_transport":                evidenceTransport,
		"evidence_time_index":               evidenceTimeIndex,
		"test_time_hint":                    testTimeHint,
	}
	runtime := &taskLLMRuntime{s: s, taskID: access.task.ID, agentKey: "reporter"}
	draft, _, err := completeDeliveryReportWith(ctx, input, evidenceVersion, runtime.Complete)
	return draft, err
}

func deliveryEvidenceTimeIndex(bindings []db.FindingTrafficBinding) string {
	if len(bindings) == 0 {
		return "没有绑定流量采集时间。"
	}
	location := beijingLocation()
	lines := make([]string, 0, len(bindings))
	for index, binding := range bindings {
		capturedAt := "未记录"
		if binding.Snapshot.CapturedAt > 0 {
			capturedAt = time.Unix(binding.Snapshot.CapturedAt, 0).In(location).Format("2006-01-02 15:04:05") + "（北京时间）"
		}
		purpose := strings.TrimSpace(binding.Note)
		if purpose == "" {
			purpose = deliveryBindingRoleLabel(binding.Role)
		}
		lines = append(lines, fmt.Sprintf("%d. %s：%s", index+1, purpose, capturedAt))
	}
	return "以下为绑定请求各自的采集时间（北京时间），只用于对应请求，不代表漏洞首次发现时间或完整测试时段：\n" + strings.Join(lines, "\n")
}

func deliveryEvidenceTestTimeHint(bindings []db.FindingTrafficBinding) string {
	var firstCapturedAt int64
	for _, binding := range bindings {
		capturedAt := binding.Snapshot.CapturedAt
		if capturedAt > 0 && (firstCapturedAt == 0 || capturedAt < firstCapturedAt) {
			firstCapturedAt = capturedAt
		}
	}
	if firstCapturedAt == 0 {
		return "测试时间未记录"
	}
	return time.Unix(firstCapturedAt, 0).In(beijingLocation()).Format("2006-01-02 15:04:05（北京时间，首条证据请求采集时间）")
}

func beijingLocation() *time.Location {
	return time.FixedZone("北京时间", 8*60*60)
}

func reportEvalTestTimeHint(raw string) string {
	parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(raw))
	if err != nil {
		return "测试时间未记录"
	}
	return parsed.In(beijingLocation()).Format("2006-01-02 15:04:05（北京时间）")
}

func deliveryReportCompletionSystem() string {
	return agent.DeliveryReportDraftRules
}

func deliveryReportRequestLineIndex(packet string) string {
	lines := make([]string, 0)
	for _, line := range strings.Split(packet, "\n") {
		fields := strings.Fields(strings.TrimSuffix(line, "\r"))
		if len(fields) < 3 || !strings.HasPrefix(fields[2], "HTTP/") || !strings.HasPrefix(fields[1], "/") {
			continue
		}
		lines = append(lines, fmt.Sprintf("%d. %s %s", len(lines)+1, fields[0], fields[1]))
	}
	if len(lines) == 0 {
		return ""
	}
	return strings.Join(lines, "\n")
}

func deliveryReportRequestOccurrenceIndex(requestPacket, responsePacket string) (string, error) {
	type occurrence struct {
		Purpose      string `json:"purpose"`
		RequestLine  string `json:"request_line"`
		ResponseLine string `json:"response_line,omitempty"`
	}
	type packetSection struct {
		purpose string
		body    string
	}
	sections := func(packet, kind string) []packetSection {
		lines := strings.Split(packet, "\n")
		var result []packetSection
		for index := 0; index < len(lines); index++ {
			heading := strings.TrimSpace(strings.TrimSuffix(lines[index], "\r"))
			purpose := ""
			if strings.HasPrefix(heading, "证据绑定 ") {
				purpose = heading
			} else if strings.HasPrefix(heading, "### ") && strings.HasSuffix(heading, " · "+kind) {
				purpose = strings.TrimSuffix(strings.TrimPrefix(heading, "### "), " · "+kind)
			}
			if purpose == "" {
				continue
			}
			start := index + 1
			end := start
			for end < len(lines) {
				candidate := strings.TrimSpace(strings.TrimSuffix(lines[end], "\r"))
				if strings.HasPrefix(candidate, "证据绑定 ") ||
					strings.HasPrefix(candidate, "### ") && (strings.HasSuffix(candidate, " · 请求") || strings.HasSuffix(candidate, " · 响应")) {
					break
				}
				end++
			}
			result = append(result, packetSection{purpose: purpose, body: strings.Join(lines[start:end], "\n")})
			index = end - 1
		}
		return result
	}
	responseLines := make(map[string][]string)
	for _, section := range sections(responsePacket, "响应") {
		for _, line := range strings.Split(section.body, "\n") {
			if line = strings.TrimSpace(strings.TrimSuffix(line, "\r")); line != "" {
				responseLines[section.purpose] = append(responseLines[section.purpose], line)
				break
			}
		}
	}
	index := make([]occurrence, 0)
	responseUse := make(map[string]int)
	for _, section := range sections(requestPacket, "请求") {
		requestLine := ""
		for _, line := range strings.Split(section.body, "\n") {
			fields := strings.Fields(strings.TrimSuffix(line, "\r"))
			if len(fields) >= 3 && strings.HasPrefix(fields[2], "HTTP/") {
				requestLine = fields[0] + " " + fields[1]
				break
			}
		}
		if requestLine == "" {
			continue
		}
		item := occurrence{Purpose: section.purpose, RequestLine: requestLine}
		if responses := responseLines[section.purpose]; responseUse[section.purpose] < len(responses) {
			item.ResponseLine = responses[responseUse[section.purpose]]
			responseUse[section.purpose]++
		}
		index = append(index, item)
	}
	if len(index) == 0 {
		return "", nil
	}
	encoded, err := json.Marshal(index)
	if err != nil {
		return "", fmt.Errorf("marshal delivery report request occurrence index: %w", err)
	}
	return string(encoded), nil
}

func stripDeliveryDraftSectionHeading(content, section string) string {
	lines := strings.Split(strings.TrimSpace(content), "\n")
	for len(lines) > 0 {
		if strings.TrimSpace(lines[0]) == "" {
			lines = lines[1:]
			continue
		}
		if strings.TrimSpace(lines[0]) != "## "+section {
			break
		}
		lines = lines[1:]
	}
	return strings.TrimSpace(strings.Join(lines, "\n"))
}

func stripRedundantDeliveryDraftSubheading(content, section string) string {
	lines := strings.Split(content, "\n")
	result := make([]string, 0, len(lines))
	insideFence := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if strings.HasPrefix(trimmed, "```") {
			insideFence = !insideFence
		}
		if !insideFence && trimmed == "### "+section {
			continue
		}
		result = append(result, line)
	}
	return strings.TrimSpace(strings.Join(result, "\n"))
}

func ensureDeliveryBurpSection(content, evidencePacket, evidenceTransport string, synthetic bool) string {
	packet := deliveryBurpEvidenceRequest(evidencePacket)
	isNonHTTP := evidenceTransport == "non-http" || evidenceTransport == "non_http"
	if isNonHTTP || (evidenceTransport != "http" && packet == "" && strings.Contains(content, "Burp 不适用")) {
		return ensureDeliveryNonHTTPBurpSection()
	}

	var section strings.Builder
	if synthetic {
		section.WriteString("离线合成请求样例，不能直接发送到真实目标。\n")
	}
	section.WriteString("以下请求包供渗透测试工程师在授权目标中导入 Burp Repeater 复现或复测，不代表已通过 Burp 发送或验证。\n")
	if packet == "" {
		packet = "<METHOD> <PATH> HTTP/1.1\r\nHost: <需从授权账号重新捕获>"
		section.WriteString("原始请求未完整留存；此模板不能直接发送，缺失字段需从授权账号重新捕获。\n")
	} else {
		var missingHost bool
		packet, missingHost = deliveryBurpEnsureHostHeader(packet)
		if missingHost {
			section.WriteString("原始请求未记录 Host；当前请求含占位符，需从授权账号重新捕获后再发送。\n")
		}
	}
	section.WriteString("```http\n")
	section.WriteString(packet)
	section.WriteString("\n```")
	return strings.TrimSpace(section.String())
}

func deliveryBurpEnsureHostHeader(packet string) (string, bool) {
	lines := strings.Split(packet, "\r\n")
	if len(lines) == 1 {
		lines = strings.Split(packet, "\n")
	}
	for index := 1; index < len(lines); index++ {
		if strings.TrimSpace(lines[index]) == "" {
			break
		}
		name, value, ok := strings.Cut(lines[index], ":")
		if !ok || !strings.EqualFold(strings.TrimSpace(name), "Host") {
			continue
		}
		if strings.TrimSpace(value) != "" && !strings.Contains(value, "需从授权账号重新捕获") {
			return packet, false
		}
		lines[index] = "Host: <需从授权账号重新捕获>"
		return strings.Join(lines, "\r\n"), true
	}
	lines = append(lines[:1], append([]string{"Host: <需从授权账号重新捕获>"}, lines[1:]...)...)
	return strings.Join(lines, "\r\n"), true
}

func ensureDeliveryNonHTTPBurpSection() string {
	return "Burp 不适用：本次证据为本地命令或终端输出。"
}

func ensureDeliverySyntheticBoundary(content string) string {
	content = strings.TrimSpace(content)
	if content == "" {
		return content
	}
	const syntheticBoundary = "离线合成场景，未测试真实目标。"
	if first, rest, _ := strings.Cut(content, "\n"); strings.TrimSpace(first) == agent.DeliveryReportFieldsMarker {
		return agent.DeliveryReportFieldsMarker + "\n测试范围：" + syntheticBoundary + "\n" + rest
	}
	hasSyntheticScope := strings.Contains(content, "离线合成") || strings.Contains(content, "合成样本") || strings.Contains(content, "合成场景")
	hasRealTargetLimit := strings.Contains(content, "未测试真实目标") || strings.Contains(content, "未访问真实目标") || strings.Contains(content, "未测试真实系统")
	if hasSyntheticScope && hasRealTargetLimit {
		return content
	}
	return syntheticBoundary + "\n\n" + content
}

func normalizeDeliverySyntheticText(content string) string {
	lines := strings.Split(content, "\n")
	insideFence := false
	normalizeFenceContent := false
	for index, line := range lines {
		trimmed := strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if strings.HasPrefix(trimmed, "```") {
			if !insideFence {
				language := strings.Fields(strings.TrimPrefix(trimmed, "```"))
				normalizeFenceContent = len(language) > 0 && language[0] == "text"
				insideFence = true
			} else {
				insideFence = false
				normalizeFenceContent = false
			}
			continue
		}
		if insideFence && !normalizeFenceContent {
			continue
		}
		lines[index] = normalizeDeliverySyntheticTextLine(line)
	}
	return strings.Join(lines, "\n")
}

func normalizeDeliverySyntheticTextLine(content string) string {
	replacements := strings.NewReplacer(
		"本地低权限导致样本机密性潜在受损，真实影响未验证", "VC:L 为待复核的潜在影响假设，真实数据影响未验证",
		"样本机密性潜在受损，真实影响未验证", "VC:L 为待复核的潜在影响假设，真实数据影响未验证",
		"VC:L 基于能读取合成样本内容", "VC:L 为待复核的潜在影响假设",
		"真实机密性影响未验证", "真实数据影响未验证",
		"机密性潜在受损", "VC:L 为待复核的潜在影响假设",
		"机密性受损", "真实数据影响未验证",
		"未验证敏感数据泄露", "未验证真实数据影响",
		"敏感数据泄露", "文件内容读取",
		"访问敏感数据", "读取文件内容",
		"读取敏感数据", "读取文件内容",
		"泄露敏感数据", "读取文件内容",
		"敏感数据", "相关内容",
		"本地低权限即可访问敏感备份", "样本显示低权限用户可读取备份文件",
		"敏感备份文件", "备份文件",
		"敏感备份", "备份文件",
		"敏感文件", "文件",
		"owner 为", "所有者为",
		"或具备显式管理权限", "",
		"作业所有者或授权协作者", "作业所有者",
		"资源所有者或授权协作者", "资源所有者",
		"所有者或授权协作者", "所有者",
		"items=[reg-1, reg-2, reg-3]", "查询结果包含 3 条记录（编号 reg-1、reg-2、reg-3）",
		"返回 ok=true", "操作成功",
		"ok=true", "操作成功",
		"ok:true", "操作成功",
		"返回成功标记", "操作成功",
		"返回 操作成功", "操作成功",
		"返回操作成功", "操作成功",
		"selectedTypes为空", "所选类型为空",
		"selectedTypes含name", "所选类型为 name",
		"state为WAITING", "作业状态为等待中",
		"state为SUCCESS", "作业状态变为已完成",
		" (Exit Code 1)", "（退出码 1）",
		"属主或授权组", "属主",
	)
	content = replacements.Replace(content)
	content = regexp.MustCompile(`修改了\s+所有者为\s+([^，。\s]+)\s+的作业`).ReplaceAllString(content, "修改了 $1 名下的作业")
	content = regexp.MustCompile(`显示\s+(所选类型|作业状态|正式文件可用状态)`).ReplaceAllString(content, "显示$1")
	content = regexp.MustCompile(`\s+及\s+`).ReplaceAllString(content, "及")
	content = regexp.MustCompile(`\s+字段`).ReplaceAllString(content, "字段")
	content = regexp.MustCompile(`(?:作业|资源)?所有者\s*或\s*(?:拥有|具备|有)?\s*共享授权`).ReplaceAllString(content, "作业所有者")
	content = regexp.MustCompile(`selectedTypes\s*由\s*空变为\s*name`).ReplaceAllString(content, "所选类型由空变为 name")
	content = regexp.MustCompile(`selectedTypes\s*从\s*空变为\s*name`).ReplaceAllString(content, "所选类型由空变为 name")
	content = regexp.MustCompile(`selectedTypes\s*为空`).ReplaceAllString(content, "所选类型为空")
	content = regexp.MustCompile(`selectedTypes\s*设为\s*\[?"?name"?\]?`).ReplaceAllString(content, "所选类型设为 name")
	content = regexp.MustCompile(`selectedTypes\s*已变`).ReplaceAllString(content, "所选类型已变")
	content = regexp.MustCompile(`selectedTypes\s*(?:含|变为)\s*\[?"?name"?\]?`).ReplaceAllString(content, "所选类型为 name")
	content = regexp.MustCompile(`state\s*(?:由|从)\s*WAITING\s*变为\s*SUCCESS`).ReplaceAllString(content, "作业状态由等待中变为已完成")
	content = regexp.MustCompile(`state\s*为\s*WAITING`).ReplaceAllString(content, "作业状态为等待中")
	content = regexp.MustCompile(`state\s*变为\s*SUCCESS`).ReplaceAllString(content, "作业状态变为已完成")
	content = regexp.MustCompile(`state\s*和\s*formalAvailable\s*状态变更`).ReplaceAllString(content, "作业状态与正式文件可用状态变更")
	content = regexp.MustCompile(`formalAvailable\s*状态变更`).ReplaceAllString(content, "正式文件可用状态变更")
	content = regexp.MustCompile(`formalAvailable\s*变为\s*true`).ReplaceAllString(content, "正式文件已可用")
	content = regexp.MustCompile(`\btotal\s*(?:=|:|：|为|是)\s*(\d+)\b`).ReplaceAllString(content, "记录数为 $1")
	content = regexp.MustCompile(`(?i)\bid\s*(?:=|为|是|:|：)?\s*(reg-\d+)\b`).ReplaceAllString(content, "新记录编号为 $1")
	content = regexp.MustCompile(`操作成功(?:[，,、]\s*操作成功)+`).ReplaceAllString(content, "操作成功")
	content = regexp.MustCompile(`\bitems\s*(?:含|包含)\s*reg-\d+(?:/\d+)*\b`).ReplaceAllStringFunc(content, func(match string) string {
		return fmt.Sprintf("查询结果包含 %d 条记录", strings.Count(match, "/")+1)
	})
	content = strings.ReplaceAll(content, "selectedTypes", "所选类型")
	content = strings.ReplaceAll(content, "formalAvailable", "正式文件可用状态")
	content = strings.ReplaceAll(content, "state", "作业状态")
	content = strings.NewReplacer("返回 操作成功", "操作成功", "返回操作成功", "操作成功").Replace(content)
	permissionAlternatives := regexp.MustCompile(`[（(]如\s*600\s*或\s*640[）)]`)
	content = permissionAlternatives.ReplaceAllString(content, "")
	return content
}

func ensureDeliveryDraftTestTime(content, testTimeHint string) string {
	lines := strings.Split(strings.TrimSpace(content), "\n")
	testTime := strings.TrimSpace(testTimeHint)
	if testTime == "" || testTime == "测试时间未记录" {
		testTime = "未记录"
	}
	body := make([]string, 0, len(lines))
	for _, line := range lines {
		trimmed := strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		removedTimeLine := false
		for _, prefix := range []string{"测试时间：", "测试时间:"} {
			if !strings.HasPrefix(trimmed, prefix) {
				continue
			}
			if value := strings.TrimSpace(strings.TrimPrefix(trimmed, prefix)); value != "" {
				testTime = value
			}
			removedTimeLine = true
			break
		}
		if removedTimeLine {
			continue
		}
		body = append(body, line)
	}
	return "测试时间：" + testTime + "\n\n" + strings.TrimSpace(strings.Join(body, "\n"))
}

func deliveryBurpSectionRange(content string) (int, int) {
	lines := strings.Split(content, "\n")
	start, end := -1, len(lines)
	for index, line := range lines {
		trimmed := strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if start < 0 {
			if trimmed == "### Burp 复现" {
				start = index
			}
			continue
		}
		if strings.HasPrefix(trimmed, "### ") || strings.HasPrefix(trimmed, "## ") {
			end = index
			break
		}
	}
	return start, end
}

func deliveryBurpEvidenceRequest(packet string) string {
	lines := strings.Split(strings.ReplaceAll(packet, "\r\n", "\n"), "\n")
	type candidate struct {
		request string
		label   string
		proof   bool
	}
	var candidates []candidate
	for index := 0; index < len(lines); {
		start := index
		proof := false
		label := ""
		if isDeliveryEvidencePacketLabel(lines[index]) {
			label = strings.TrimSpace(lines[index])
			proof = strings.Contains(lines[index], "漏洞验证")
			start++
		}
		end := start
		for end < len(lines) && !isDeliveryEvidencePacketLabel(lines[end]) {
			end++
		}
		requestStart := -1
		for lineIndex := start; lineIndex < end; lineIndex++ {
			if isDeliveryHTTPRequestLine(strings.TrimSpace(lines[lineIndex])) {
				requestStart = lineIndex
				break
			}
		}
		if requestStart >= 0 {
			requestEnd := deliveryRawHTTPRequestEnd(lines, requestStart, end)
			request := strings.TrimSpace(strings.Join(lines[requestStart:requestEnd], "\r\n"))
			request = redactDeliveryPacket(request)
			request = normalizeDeliveryRequestContentLength(request)
			candidates = append(candidates, candidate{request: request, label: label, proof: proof})
		}
		if end == len(lines) {
			break
		}
		index = end
	}
	bestScore := -1 << 30
	bestRequest := ""
	for _, item := range candidates {
		score := deliveryBurpEvidenceRequestScore(item.label, item.request)
		if item.proof {
			score += 1000
		}
		if score > bestScore {
			bestScore = score
			bestRequest = item.request
		}
	}
	return bestRequest
}

func deliveryBurpEvidenceRequestScore(label, request string) int {
	for _, term := range []string{"无身份", "不带身份", "未授权", "无凭证", "缺少编号", "缺少业务编号", "匿名"} {
		if strings.Contains(label, term) {
			return -1000
		}
	}
	score := 0
	for _, term := range []string{"漏洞验证", "越权", "他人", "其他用户", "并发提交", "并发请求", "提交修改", "修改", "写入", "删除", "上传", "创建", "执行", "注入", "真条件", "假条件", "下载", "重放", "释放锁", "占位"} {
		if strings.Contains(label, term) {
			score += 10
		}
	}
	for _, term := range []string{"基线", "修改前", "修改后", "回读", "对照", "正常查询", "退出前", "登录前"} {
		if strings.Contains(label, term) {
			score -= 20
		}
	}
	method := strings.Fields(request)
	if len(method) > 0 && method[0] != http.MethodGet && method[0] != http.MethodHead {
		score++
	}
	return score
}

func isDeliveryEvidencePacketLabel(line string) bool {
	trimmed := strings.TrimSpace(line)
	return strings.HasPrefix(trimmed, "证据绑定 ") ||
		(strings.HasPrefix(trimmed, "### ") && strings.HasSuffix(trimmed, "· 请求"))
}

func normalizeDeliveryRequestContentLength(packet string) string {
	separator := "\r\n\r\n"
	index := strings.Index(packet, separator)
	if index < 0 {
		separator = "\n\n"
		index = strings.Index(packet, separator)
	}
	if index < 0 {
		return packet
	}
	head, body := packet[:index], packet[index+len(separator):]
	lines := strings.Split(head, "\r\n")
	if len(lines) == 1 {
		lines = strings.Split(head, "\n")
	}
	for lineIndex, line := range lines {
		name, _, ok := strings.Cut(line, ":")
		if ok && strings.EqualFold(strings.TrimSpace(name), "Content-Length") {
			lines[lineIndex] = name + ": " + strconv.Itoa(len([]byte(body)))
		}
	}
	return strings.Join(lines, "\r\n") + separator + body
}

func isDeliveryHTTPRequestLine(line string) bool {
	fields := strings.Fields(line)
	return len(fields) == 3 && fields[0] != "" && fields[1] != "" && strings.HasPrefix(strings.ToUpper(fields[2]), "HTTP/")
}

func deliveryRawHTTPRequestEnd(lines []string, requestLine, sectionEnd int) int {
	headerEnd := -1
	contentLength := -1
	chunked := false
	for index := requestLine + 1; index < sectionEnd; index++ {
		line := strings.TrimSpace(strings.TrimSuffix(lines[index], "\r"))
		if line == "" {
			headerEnd = index
			break
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "content-length":
			if parsed, err := strconv.Atoi(strings.TrimSpace(value)); err == nil && parsed >= 0 {
				contentLength = parsed
			}
		case "transfer-encoding":
			chunked = strings.Contains(strings.ToLower(value), "chunked")
		}
	}
	if headerEnd < 0 {
		return sectionEnd
	}
	if contentLength == 0 || (contentLength < 0 && !chunked) {
		return headerEnd + 1
	}
	if chunked {
		for index := headerEnd + 1; index < sectionEnd; index++ {
			if strings.TrimSpace(strings.TrimSuffix(lines[index], "\r")) == "0" {
				if index+1 < sectionEnd && strings.TrimSpace(lines[index+1]) == "" {
					return index + 2
				}
				return index + 1
			}
		}
		return sectionEnd
	}
	bodyBytes := 0
	for index := headerEnd + 1; index < sectionEnd; index++ {
		if index > headerEnd+1 {
			bodyBytes++
		}
		bodyBytes += len([]byte(strings.TrimSuffix(lines[index], "\r")))
		if bodyBytes >= contentLength {
			return index + 1
		}
	}
	return sectionEnd
}

func hasExplicitDeliveryConcurrencyEvidence(input map[string]string) bool {
	source := strings.ToLower(input["summary"] + "\n" + input["evidence"])
	for _, negative := range []string{"未测试并发", "未验证并发", "未执行并发", "并发未测试", "并发未验证", "没有进行并发测试", "没有并发测试"} {
		if strings.Contains(source, negative) {
			return false
		}
	}
	for _, positive := range []string{"并发提交", "并发发送", "并发请求", "并发执行", "同时提交", "同时发送", "同时请求", "concurrent request", "concurrently sent"} {
		if strings.Contains(source, positive) {
			return true
		}
	}
	return false
}

func normalizeDeliveryDraftSubheadings(content string, headings ...string) string {
	for _, heading := range headings {
		marker := "### " + heading
		position := -1
		plainLabel := ""
		scanDeliveryMarkdown(content, func(line string, offset int, code bool) {
			if position >= 0 || code {
				return
			}
			level, title := deliveryMarkdownHeading(line)
			if level == 3 && title == heading {
				return
			}
			index := strings.Index(line, marker)
			if index >= 0 {
				position = offset + index
				return
			}
			labels := []string{heading + "：", heading + ":"}
			compactHeading := strings.ReplaceAll(heading, " ", "")
			if compactHeading != heading {
				labels = append(labels, compactHeading+"：", compactHeading+":")
			}
			for _, label := range labels {
				if index = strings.Index(line, label); index >= 0 {
					position = offset + index
					plainLabel = label
					return
				}
			}
		})
		if position < 0 {
			continue
		}
		if plainLabel != "" {
			prefix := strings.TrimRight(content[:position], " \t")
			suffix := strings.TrimLeft(content[position+len(plainLabel):], " \t")
			content = prefix + "\n\n" + marker + "\n" + suffix
			continue
		}
		if position > 0 && content[position-1] != '\n' {
			content = content[:position] + "\n\n" + content[position:]
			position += 2
		}
		headingEnd := position + len(marker)
		suffixStart := headingEnd
		if strings.HasPrefix(content[suffixStart:], "：") {
			suffixStart += len("：")
		} else if strings.HasPrefix(content[suffixStart:], ":") {
			suffixStart++
		}
		content = content[:headingEnd] + strings.TrimLeft(content[suffixStart:], " \t")
		if headingEnd < len(content) && content[headingEnd] != '\n' && content[headingEnd] != '\r' {
			content = content[:headingEnd] + "\n" + content[headingEnd:]
		}
	}
	return strings.TrimSpace(content)
}

func ensureDeliveryAttackChainTextFence(content string) string {
	return ensureDeliveryAttackChainTextFenceWithEvidence(content, "", false)
}

func normalizeDeliveryAttackChainGroupBranches(content string) string {
	lines := strings.Split(content, "\n")
	type group struct {
		index  int
		label  string
		branch string
	}
	groups := make([]group, 0, 2)
	for index, line := range lines {
		trimmed := strings.TrimSpace(line)
		marked := false
		for _, branch := range []string{"├─", "└─"} {
			if strings.HasPrefix(trimmed, branch) {
				trimmed = strings.TrimSpace(strings.TrimPrefix(trimmed, branch))
				marked = true
				break
			}
		}
		for _, candidate := range []group{{label: "主流程", branch: "├─"}, {label: "独立对照", branch: "└─"}} {
			if trimmed == candidate.label {
				candidate.index = index
				groups = append(groups, candidate)
				if marked {
					groups[len(groups)-1].branch = candidate.branch
				}
			}
		}
	}
	for groupIndex, current := range groups {
		groupIndent := 0
		if current.index > 0 {
			groupIndent = 3
		}
		lines[current.index] = strings.Repeat(" ", groupIndent) + current.branch + " " + current.label
		end := len(lines)
		for nextIndex := groupIndex + 1; nextIndex < len(groups); nextIndex++ {
			if groups[nextIndex].index > current.index {
				end = groups[nextIndex].index
				break
			}
		}
		firstChildIndentTarget := groupIndent + 3
		indentOffset := 0
		for index := current.index + 1; index < end; index++ {
			if strings.TrimSpace(lines[index]) == "" {
				continue
			}
			_, firstChildIndent := deliveryAttackTreeIndent(lines[index])
			indentOffset = firstChildIndent - firstChildIndentTarget
			break
		}
		for index := current.index + 1; index < end; index++ {
			line := lines[index]
			if strings.TrimSpace(line) == "" {
				continue
			}
			leadingIndent, visibleIndent := deliveryAttackTreeIndent(line)
			leadingIndent -= indentOffset
			visibleIndent -= indentOffset
			if visibleIndent < firstChildIndentTarget {
				leadingIndent += firstChildIndentTarget - visibleIndent
			}
			lines[index] = strings.Repeat(" ", leadingIndent) + strings.TrimLeft(line, " \t")
		}
	}
	return strings.Join(lines, "\n")
}

func deliveryAttackTreeIndent(line string) (int, int) {
	leadingIndent := len(line) - len(strings.TrimLeft(line, " \t"))
	visibleIndent := leadingIndent
	trimmed := strings.TrimLeft(line, " \t")
	if markerOffset := strings.IndexAny(trimmed, "├└"); markerOffset > 0 && strings.ContainsRune(trimmed[:markerOffset], '│') {
		visibleIndent += utf8.RuneCountInString(trimmed[:markerOffset])
	}
	return leadingIndent, visibleIndent
}

func ensureDeliveryAttackChainTextFenceWithEvidence(content, requestPacket string, allowConcurrentNormalization bool) string {
	content = strings.TrimSpace(content)
	if strings.HasPrefix(content, "```") {
		lines := strings.Split(content, "\n")
		lines = lines[1:]
		if len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) == "```" {
			lines = lines[:len(lines)-1]
		}
		content = strings.TrimSpace(strings.Join(lines, "\n"))
	}
	if chain, ok := normalizeExplicitDownArrowChain(content); ok {
		content = chain
	}
	content = normalizeDeliveryAttackChainGroupBranches(content)
	lines := strings.Split(content, "\n")
	nodes := make([]string, 0, len(lines))
	treeLines := make([]string, 0, len(lines))
	hasTreeBranch := false
	for _, line := range lines {
		rawLine := line
		line = strings.TrimSpace(line)
		if line == "" || line == "text" {
			continue
		}
		treeLines = append(treeLines, strings.TrimRight(rawLine, "\r"))
		if strings.Contains(line, "├─") || strings.Contains(line, "└─") {
			hasTreeBranch = true
		}
		line = strings.TrimLeft(line, "-*")
		for _, part := range strings.Split(strings.ReplaceAll(line, "->", "→"), "→") {
			part = strings.TrimSpace(part)
			for _, prefix := range []string{"入口：", "入口:", "身份：", "身份:", "条件：", "条件:", "操作：", "操作:", "结果：", "结果:", "影响：", "影响:"} {
				part = strings.TrimPrefix(part, prefix)
			}
			part = strings.TrimSpace(part)
			if part != "" {
				nodes = append(nodes, part)
			}
		}
	}
	if !hasTreeBranch && len(nodes) > 1 {
		content = nodes[0]
		indent := "   "
		for _, node := range nodes[1:] {
			content += "\n" + indent + "└─ " + node
			indent += "   "
		}
	} else {
		normalizedTree := make([]string, 0, len(treeLines))
		for _, line := range treeLines {
			indent := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
			trimmed := strings.TrimSpace(line)
			if strings.Trim(trimmed, "│ ") == "" {
				continue
			}
			if markerOffset := strings.IndexAny(trimmed, "├└"); markerOffset > 0 && strings.ContainsRune(trimmed[:markerOffset], '│') {
				indent += strings.Repeat(" ", utf8.RuneCountInString(trimmed[:markerOffset]))
				trimmed = strings.TrimLeft(trimmed[markerOffset:], " ")
			}
			marker := ""
			for _, candidate := range []string{"├─", "└─"} {
				if strings.HasPrefix(trimmed, candidate) {
					marker = candidate
					trimmed = strings.TrimSpace(strings.TrimPrefix(trimmed, candidate))
					break
				}
			}
			if marker != "" {
				trimmed = strings.TrimLeft(trimmed, " ─>→↓")
				trimmed = strings.TrimSpace(trimmed)
				if trimmed == "" {
					continue
				}
				line = indent + marker + " " + trimmed
			} else {
				line = trimmed
			}
			normalizedTree = append(normalizedTree, line)
		}
		content = strings.Join(normalizedTree, "\n")
	}
	if content == "" {
		return content
	}
	content = strings.Join(normalizeDeliveryAttackTreeBranches(strings.Split(content, "\n")), "\n")
	content = strings.Join(normalizeFlatDeliveryAttackChain(strings.Split(content, "\n"), requestPacket, allowConcurrentNormalization), "\n")
	content = normalizeDeliveryIndependentAttackBranches(content)
	content = normalizeDeliveryAttackChainGroupBranches(content)
	content = strings.Join(normalizeDeliveryAttackTreeBranches(strings.Split(content, "\n")), "\n")
	content = ensureDeliveryAttackChainRoot(content)
	content = normalizeDeliveryAttackChainRootIndent(content)
	return "```text\n" + content + "\n```"
}

func normalizeDeliveryIndependentAttackBranches(content string) string {
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		_, _, value, ok := deliveryAttackTreeLine(line)
		if ok && value == "独立对照" {
			return content
		}
	}
	type nodeLine struct {
		indent int
		marker string
		value  string
		line   string
	}
	var independent [][]nodeLine
	var removeRanges [][2]int
	controlTerms := []string{"缺少业务编号", "缺少编号", "无身份", "不带身份", "匿名", "未授权", "错误凭证", "无效凭证"}
	for index, line := range lines {
		indent, _, value, ok := deliveryAttackTreeLine(line)
		if !ok || deliveryHTTPMethod(value) == "" {
			continue
		}
		isControl := false
		for _, term := range controlTerms {
			if strings.Contains(value, term) {
				isControl = true
				break
			}
		}
		if !isControl {
			continue
		}
		end := index + 1
		for end < len(lines) {
			if strings.TrimSpace(lines[end]) == "" {
				end++
				continue
			}
			nextIndent, _, _, isNode := deliveryAttackTreeLine(lines[end])
			if isNode && nextIndent <= indent {
				break
			}
			end++
		}
		subtree := make([]nodeLine, 0, end-index)
		for childIndex := index; childIndex < end; childIndex++ {
			childIndent, childMarker, childValue, isNode := deliveryAttackTreeLine(lines[childIndex])
			if !isNode {
				continue
			}
			subtree = append(subtree, nodeLine{indent: childIndent, marker: childMarker, value: childValue})
		}
		if len(subtree) == 0 {
			continue
		}
		independent = append(independent, subtree)
		removeRanges = append(removeRanges, [2]int{index, end})
	}
	if len(independent) == 0 {
		return content
	}
	for index := len(removeRanges) - 1; index >= 0; index-- {
		start, end := removeRanges[index][0], removeRanges[index][1]
		lines = append(lines[:start], lines[end:]...)
	}
	lines = append(lines, "   └─ 独立对照")
	for _, subtree := range independent {
		baseIndent := subtree[0].indent
		for _, node := range subtree {
			indent := 6 + node.indent - baseIndent
			if indent < 6 {
				indent = 6
			}
			lines = append(lines, strings.Repeat(" ", indent)+node.marker+" "+node.value)
		}
	}
	return strings.Join(lines, "\n")
}

func deliveryAttackTreeLine(line string) (int, string, string, bool) {
	indent := len(line) - len(strings.TrimLeft(line, " \t"))
	trimmed := strings.TrimLeft(line, " \t")
	markerIndex := strings.IndexAny(trimmed, "├└")
	if markerIndex < 0 || !strings.HasPrefix(trimmed[markerIndex:], "├─") && !strings.HasPrefix(trimmed[markerIndex:], "└─") {
		return 0, "", "", false
	}
	if strings.ContainsRune(trimmed[:markerIndex], '│') {
		indent += utf8.RuneCountInString(trimmed[:markerIndex])
	}
	marker := trimmed[markerIndex : markerIndex+len("├─")]
	value := strings.TrimSpace(trimmed[markerIndex+len("├─"):])
	return indent, marker, value, true
}

func normalizeDeliveryAttackChainRootIndent(content string) string {
	lines := strings.Split(content, "\n")
	firstChild := -1
	for index := 1; index < len(lines); index++ {
		if strings.TrimSpace(lines[index]) != "" {
			firstChild = index
			break
		}
	}
	if firstChild < 0 {
		return content
	}
	leadingIndent, _ := deliveryAttackTreeIndent(lines[firstChild])
	trimmed := strings.TrimLeft(lines[firstChild], " \t")
	if leadingIndent != 0 || (!strings.HasPrefix(trimmed, "├─") && !strings.HasPrefix(trimmed, "└─")) {
		return content
	}
	for index := firstChild; index < len(lines); index++ {
		if strings.TrimSpace(lines[index]) != "" {
			lines[index] = "   " + lines[index]
		}
	}
	return strings.Join(lines, "\n")
}

func ensureDeliveryAttackChainRoot(content string) string {
	lines := strings.Split(content, "\n")
	if len(lines) == 0 {
		return content
	}
	first := strings.TrimSpace(lines[0])
	if strings.EqualFold(first, "root") && len(lines) > 1 {
		return ensureDeliveryAttackChainRoot(strings.Join(lines[1:], "\n"))
	}
	for _, marker := range []string{"├─", "└─"} {
		if strings.HasPrefix(first, marker) {
			lines[0] = strings.TrimSpace(strings.TrimPrefix(first, marker))
			return strings.Join(lines, "\n")
		}
	}
	return content
}

func normalizeExplicitDownArrowChain(content string) (string, bool) {
	var nodes []string
	arrows := 0
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || trimmed == "text" {
			continue
		}
		connector := trimmed
		for _, marker := range []string{"├─", "└─"} {
			if strings.HasPrefix(connector, marker) {
				connector = strings.TrimSpace(strings.TrimPrefix(connector, marker))
				break
			}
		}
		if connector == "↓" {
			arrows++
			continue
		}
		if node := stripDeliveryAttackTreeNode(trimmed); node != "" {
			nodes = append(nodes, node)
		}
	}
	if arrows == 0 || len(nodes) < 2 || arrows != len(nodes)-1 {
		return "", false
	}
	chain := nodes[0]
	indent := "   "
	for _, node := range nodes[1:] {
		chain += "\n" + indent + "└─ " + node
		indent += "   "
	}
	return chain, true
}

type deliveryAttackNode struct {
	value    string
	children []*deliveryAttackNode
}

func normalizeFlatDeliveryAttackChain(lines []string, requestPacket string, allowConcurrentNormalization bool) []string {
	if len(lines) < 3 {
		return lines
	}
	root := strings.TrimSpace(stripDeliveryAttackTreeNode(lines[0]))
	if root == "" {
		return lines
	}
	events := make([]string, 0, len(lines)-1)
	for _, line := range lines[1:] {
		if node := strings.TrimSpace(stripDeliveryAttackTreeNode(line)); node != "" {
			events = append(events, node)
		}
	}
	if len(events) == 0 {
		return lines
	}

	concurrentIndex := -1
	for index, event := range events {
		if strings.Contains(event, "并发") {
			concurrentIndex = index
			break
		}
	}
	repeatedMethod, repeatedPath, repeatedCount := "", "", 0
	if concurrentIndex >= 0 {
		repeatedMethod, repeatedPath, repeatedCount = repeatedDeliveryRequest(requestPacket, events[concurrentIndex])
	}
	if !allowConcurrentNormalization || concurrentIndex < 0 || repeatedCount < 2 || repeatedMethod == http.MethodGet {
		return lines
	}

	rootNode := &deliveryAttackNode{value: root}
	appendChain := func(parent *deliveryAttackNode, value string) *deliveryAttackNode {
		child := &deliveryAttackNode{value: value}
		parent.children = append(parent.children, child)
		return child
	}
	parent := rootNode
	for _, event := range events[:concurrentIndex] {
		parent = appendChain(parent, event)
	}
	groupTitle := events[concurrentIndex]
	if repeatedCount > 1 {
		groupTitle = fmt.Sprintf("并发提交 %d 次相同请求", repeatedCount)
	}
	group := appendChain(parent, groupTitle)
	parallelEnd := len(events)
	for index := concurrentIndex + 1; index < len(events); index++ {
		if deliveryHTTPMethod(events[index]) == http.MethodGet {
			parallelEnd = index
			break
		}
	}
	canRebuildConcurrentRequests := concurrentGroupContainsOnlyRepeatedRequest(events[concurrentIndex+1:parallelEnd], repeatedMethod, repeatedPath)
	responseEvents := make([]string, 0, parallelEnd-concurrentIndex-1)
	hasRequestNode := false
	for _, event := range events[concurrentIndex+1 : parallelEnd] {
		if deliveryHTTPMethod(event) != "" {
			hasRequestNode = true
			break
		}
		responseEvents = append(responseEvents, event)
	}
	rebuiltConcurrentRequests := hasRequestNode && canRebuildConcurrentRequests && appendMissingDeliveryConcurrentRequests(
		group, events, concurrentIndex+1, parallelEnd, repeatedMethod, repeatedPath, repeatedCount,
	)
	if !rebuiltConcurrentRequests && !hasRequestNode && len(responseEvents) >= repeatedCount {
		for index := 0; index < repeatedCount; index++ {
			request := appendChain(group, repeatedMethod+" "+repeatedPath)
			appendChain(request, responseEvents[index])
		}
		for _, event := range responseEvents[repeatedCount:] {
			appendChain(group, event)
		}
	} else if !rebuiltConcurrentRequests {
		appendDeliveryConcurrentEvents(group, events, concurrentIndex+1, parallelEnd)
	}
	if parallelEnd < len(events) {
		parent = appendChain(parent, events[parallelEnd])
		for index := parallelEnd + 1; index < len(events); index++ {
			parent = appendChain(parent, events[index])
		}
	}

	output := []string{rootNode.value}
	var render func(*deliveryAttackNode, string, bool)
	render = func(node *deliveryAttackNode, prefix string, last bool) {
		marker := "├─ "
		if last {
			marker = "└─ "
		}
		output = append(output, prefix+marker+node.value)
		childPrefix := prefix + "│  "
		if last {
			childPrefix = prefix + "   "
		}
		for index, child := range node.children {
			render(child, childPrefix, index == len(node.children)-1)
		}
	}
	for index, child := range rootNode.children {
		render(child, "   ", index == len(rootNode.children)-1)
	}
	return output
}

func concurrentGroupContainsOnlyRepeatedRequest(events []string, method, path string) bool {
	for _, event := range events {
		requestMethod := deliveryHTTPMethod(event)
		if requestMethod != "" && (requestMethod != method || deliveryHTTPPath(event) != path) {
			return false
		}
	}
	return true
}

func appendMissingDeliveryConcurrentRequests(group *deliveryAttackNode, events []string, start, end int, method, path string, expectedCount int) bool {
	explicitRequests := 0
	var results []string
	for _, event := range events[start:end] {
		if deliveryHTTPMethod(event) == method && deliveryHTTPPath(event) == path {
			explicitRequests++
			continue
		}
		if isDeliveryAttackResultNode(event) {
			results = append(results, event)
		}
	}
	if explicitRequests >= expectedCount || explicitRequests == 0 || len(results) != expectedCount {
		return false
	}
	for index := 0; index < expectedCount; index++ {
		request := &deliveryAttackNode{value: method + " " + path}
		request.children = append(request.children, &deliveryAttackNode{value: results[index]})
		group.children = append(group.children, request)
	}
	return true
}

func deliveryHTTPPath(node string) string {
	fields := strings.Fields(node)
	if deliveryHTTPMethod(node) == "" || len(fields) < 2 {
		return ""
	}
	return fields[1]
}

func isDeliveryAttackResultNode(node string) bool {
	lower := strings.ToLower(strings.TrimSpace(node))
	if strings.HasPrefix(lower, "结果：") || strings.HasPrefix(lower, "结果:") {
		return true
	}
	fields := strings.Fields(lower)
	for index, field := range fields {
		if field == "http" && index+1 < len(fields) {
			field = fields[index+1]
		}
		field = strings.Trim(field, "：:,;()[]{}")
		if len(field) != 3 {
			continue
		}
		status, err := strconv.Atoi(field)
		if err == nil && status >= 100 && status <= 599 {
			return true
		}
	}
	return false
}

func appendDeliveryConcurrentEvents(group *deliveryAttackNode, events []string, start, end int) {
	for index := start; index < end; index++ {
		event := events[index]
		request := &deliveryAttackNode{value: event}
		group.children = append(group.children, request)
		if deliveryHTTPMethod(event) != "" && index+1 < end && deliveryHTTPMethod(events[index+1]) == "" {
			index++
			request.children = append(request.children, &deliveryAttackNode{value: events[index]})
		}
	}
}

func stripDeliveryAttackTreeNode(line string) string {
	line = strings.TrimSpace(line)
	line = strings.TrimLeft(line, "│ ")
	for _, marker := range []string{"├─", "└─"} {
		if strings.HasPrefix(line, marker) {
			line = strings.TrimSpace(strings.TrimPrefix(line, marker))
			break
		}
	}
	return strings.TrimSpace(strings.TrimLeft(line, "→↓> "))
}

func deliveryHTTPMethod(node string) string {
	fields := strings.Fields(node)
	if len(fields) < 2 {
		return ""
	}
	switch fields[0] {
	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodHead, http.MethodOptions:
		if strings.HasPrefix(fields[1], "/") {
			return fields[0]
		}
	}
	return ""
}

func repeatedDeliveryRequest(packet, group string) (string, string, int) {
	type request struct {
		method string
		path   string
		count  int
	}
	requests := make([]request, 0)
	indexes := make(map[string]int)
	for position := 0; position < len(packet); {
		lineEnd := strings.IndexByte(packet[position:], '\n')
		if lineEnd < 0 {
			break
		}
		lineEnd += position
		line := strings.TrimSuffix(packet[position:lineEnd], "\r")
		fields := strings.Fields(line)
		if len(fields) < 3 || !strings.HasPrefix(fields[2], "HTTP/") || !strings.HasPrefix(fields[1], "/") {
			position = lineEnd + 1
			continue
		}
		method := deliveryHTTPMethod(fields[0] + " " + fields[1])
		if method == "" {
			position = lineEnd + 1
			continue
		}

		bodyStart := -1
		contentLength := 0
		validContentLength := true
		chunked := false
		cursor := lineEnd + 1
		for cursor <= len(packet) {
			headerEnd := strings.IndexByte(packet[cursor:], '\n')
			if headerEnd < 0 {
				break
			}
			headerEnd += cursor
			header := strings.TrimSuffix(packet[cursor:headerEnd], "\r")
			cursor = headerEnd + 1
			if header == "" {
				bodyStart = cursor
				break
			}
			name, value, ok := strings.Cut(header, ":")
			if !ok {
				continue
			}
			switch strings.ToLower(strings.TrimSpace(name)) {
			case "content-length":
				parsed, err := strconv.Atoi(strings.TrimSpace(value))
				if err != nil || parsed < 0 {
					validContentLength = false
				} else {
					contentLength = parsed
				}
			case "transfer-encoding":
				chunked = strings.Contains(strings.ToLower(value), "chunked")
			}
		}
		if bodyStart < 0 {
			position = cursor
			continue
		}
		bodyEnd := bodyStart
		if contentLength > 0 {
			if bodyStart+contentLength > len(packet) {
				break
			}
			bodyEnd += contentLength
		}
		if validContentLength && !chunked {
			signature := packet[position:bodyEnd]
			key := method + "\x00" + fields[1] + "\x00" + signature
			index, ok := indexes[key]
			if !ok {
				index = len(requests)
				indexes[key] = index
				requests = append(requests, request{method: method, path: fields[1]})
			}
			requests[index].count++
		}
		position = bodyEnd
	}
	var repeated []request
	var matching []request
	var repeatedWrites []request
	for _, candidate := range requests {
		if candidate.count < 2 {
			continue
		}
		repeated = append(repeated, candidate)
		if candidate.method != http.MethodGet && candidate.method != http.MethodHead && candidate.method != http.MethodOptions {
			repeatedWrites = append(repeatedWrites, candidate)
		}
		if strings.Contains(group, candidate.method+" "+candidate.path) {
			matching = append(matching, candidate)
		}
	}
	if len(matching) == 1 {
		return matching[0].method, matching[0].path, matching[0].count
	}
	if len(matching) > 1 {
		return "", "", 0
	}
	if len(repeated) == 1 {
		return repeated[0].method, repeated[0].path, repeated[0].count
	}
	if len(repeatedWrites) == 1 {
		return repeatedWrites[0].method, repeatedWrites[0].path, repeatedWrites[0].count
	}
	return "", "", 0
}

func normalizeDeliveryAttackTreeBranches(lines []string) []string {
	type branch struct {
		lineIndex int
		indent    int
		marker    string
	}
	branches := make([]branch, 0, len(lines))
	for index, line := range lines {
		indent := len(line) - len(strings.TrimLeft(line, " \t"))
		rest := line[indent:]
		for _, marker := range []string{"├─", "└─"} {
			if strings.HasPrefix(rest, marker) {
				branches = append(branches, branch{lineIndex: index, indent: indent, marker: marker})
				break
			}
		}
	}
	for index, current := range branches {
		hasFollowingSibling := false
		for _, next := range branches[index+1:] {
			if next.indent < current.indent {
				break
			}
			if next.indent == current.indent {
				hasFollowingSibling = true
				break
			}
		}
		marker := "└─"
		if hasFollowingSibling {
			marker = "├─"
		}
		line := lines[current.lineIndex]
		rest := strings.TrimLeft(line[current.indent+len(current.marker):], " ")
		lines[current.lineIndex] = line[:current.indent] + marker + " " + rest
	}
	return lines
}

func completeDeliveryReportWith(
	ctx context.Context,
	input map[string]string,
	evidenceVersion int64,
	complete func(context.Context, llm.CompletionRequest) (llm.Message, string, llm.Usage, error),
) (deliveryReportDraft, llm.Usage, error) {
	ctx = agent.WithDeliveryReportReasoningDisabled(ctx)
	return completeDeliveryReportDraft(ctx, input, evidenceVersion, complete)
}

func completeDeliveryReportDraft(
	ctx context.Context,
	input map[string]string,
	evidenceVersion int64,
	complete func(context.Context, llm.CompletionRequest) (llm.Message, string, llm.Usage, error),
) (deliveryReportDraft, llm.Usage, error) {
	raw, err := json.Marshal(input)
	if err != nil {
		return deliveryReportDraft{}, llm.Usage{}, err
	}
	message, stopReason, usage, err := complete(ctx, llm.CompletionRequest{
		System: []string{deliveryReportCompletionSystem()}, Messages: []llm.Message{llm.UserText(string(raw))}, MaxTokens: deliveryReportMaxTokens, Thinking: "disabled",
	})
	if err != nil {
		return deliveryReportDraft{}, usage, err
	}
	draft, err := parseDeliveryReportDraft(message, stopReason, usage, input, evidenceVersion)
	if err != nil {
		return deliveryReportDraft{}, usage, err
	}
	return draft, usage, nil
}

func parseDeliveryReportDraft(
	message llm.Message,
	stopReason string,
	usage llm.Usage,
	input map[string]string,
	evidenceVersion int64,
) (deliveryReportDraft, error) {
	text := strings.TrimSpace(message.Text())
	text = strings.TrimPrefix(text, "```json")
	text = strings.TrimPrefix(text, "```")
	text = strings.TrimSuffix(strings.TrimSpace(text), "```")
	contentBlockTypes := make([]string, 0, len(message.Content))
	for _, block := range message.Content {
		contentBlockTypes = append(contentBlockTypes, string(block.Type))
	}
	var draft deliveryReportDraft
	if err := json.Unmarshal([]byte(strings.TrimSpace(text)), &draft); err != nil {
		if markdownDraft, ok := parseDeliveryReportMarkdownDraft(text); ok {
			draft = markdownDraft
		} else {
			return deliveryReportDraft{}, &deliveryReportOutputError{
				cause: errDeliveryReportInvalidJSON, raw: text, stopReason: stopReason,
				contentBlockType: contentBlockTypes, outputTokens: usage.OutputTokens,
			}
		}
	}
	if hint := strings.TrimSpace(input["cvss_vector_hint"]); hint != "" {
		if vector, ok := normalizeCVSS4BaseVector(hint); ok {
			draft.CVSSVector = vector
		}
	}
	draft.TestProcess = normalizeDeliveryDraftSubheadings(draft.TestProcess, "发现过程与攻击思路", "失败尝试与未验证项", "Burp 复现")
	if start, end := deliveryBurpSectionRange(draft.TestProcess); start >= 0 {
		lines := strings.Split(draft.TestProcess, "\n")
		if strings.TrimSpace(draft.BurpReproduction) == "" {
			draft.BurpReproduction = strings.Join(lines[start+1:end], "\n")
		}
		draft.TestProcess = strings.Join(append(lines[:start], lines[end:]...), "\n")
	}
	draft.Description = normalizeDeliveryDraftSubheadings(draft.Description, "定级依据")
	draft.TestProcess = normalizeDeliveryDraftSubheadings(draft.TestProcess, "发现过程与攻击思路", "失败尝试与未验证项")
	draft.BurpReproduction = normalizeDeliveryDraftSubheadings(draft.BurpReproduction, "Burp 复现")
	draft.Description = stripDeliveryDraftSectionHeading(draft.Description, "描述")
	draft.Description = stripDeliveryDraftSectionHeading(draft.Description, "漏洞描述")
	draft.Description = stripRedundantDeliveryDraftSubheading(draft.Description, "定级依据")
	if strings.EqualFold(strings.TrimSpace(input["synthetic"]), "true") {
		draft.Description = ensureDeliverySyntheticBoundary(draft.Description)
	}
	draft.Remediation = stripDeliveryDraftSectionHeading(draft.Remediation, "修复建议")
	draft.Remediation = stripDeliveryDraftSectionHeading(draft.Remediation, "修复")
	draft.TestProcess = stripDeliveryDraftSectionHeading(draft.TestProcess, "测试过程")
	draft.TestProcess = stripRedundantDeliveryDraftSubheading(draft.TestProcess, "发现过程与攻击思路")
	draft.TestProcess = stripRedundantDeliveryDraftSubheading(draft.TestProcess, "失败尝试与未验证项")
	draft.TestProcess = ensureDeliveryDraftTestTime(draft.TestProcess, input["test_time_hint"])
	draft.BurpReproduction = stripDeliveryDraftSectionHeading(draft.BurpReproduction, "Burp 复现")
	draft.BurpReproduction = stripRedundantDeliveryDraftSubheading(draft.BurpReproduction, "Burp 复现")
	burpEvidence := strings.Join([]string{
		input["request_packet"],
		input["evidence"],
		input["existing_detailed_report"],
	}, "\n")
	draft.BurpReproduction = ensureDeliveryBurpSection(
		draft.BurpReproduction,
		burpEvidence,
		input["evidence_transport"],
		strings.EqualFold(strings.TrimSpace(input["synthetic"]), "true"),
	)
	draft.Description = stripRedundantDeliveryDraftSubheading(draft.Description, "描述")
	draft.Remediation = stripRedundantDeliveryDraftSubheading(draft.Remediation, "修复建议")
	draft.TestProcess = stripRedundantDeliveryDraftSubheading(draft.TestProcess, "测试过程")
	draft.Description = normalizeDeliveryNarrative(normalizeStructuredDeliveryDescription(draft.Description), true)
	draft.Remediation = normalizeDeliveryNarrative(normalizeStructuredDeliveryRemediation(draft.Remediation), true)
	draft.TestProcess = normalizeDeliveryNarrative(normalizeStructuredDeliveryTestProcess(draft.TestProcess), true)
	draft.AttackChain = stripDeliveryDraftSectionHeading(draft.AttackChain, "攻击链路")
	draft.AttackChain = stripRedundantDeliveryDraftSubheading(draft.AttackChain, "攻击链路")
	draft.AttackChain = ensureDeliveryAttackChainTextFenceWithEvidence(
		draft.AttackChain,
		input["request_packet"],
		hasExplicitDeliveryConcurrencyEvidence(input),
	)
	if strings.EqualFold(strings.TrimSpace(input["synthetic"]), "true") {
		draft.Description = normalizeDeliverySyntheticText(draft.Description)
		draft.Remediation = normalizeDeliverySyntheticText(draft.Remediation)
		draft.TestProcess = normalizeDeliverySyntheticText(draft.TestProcess)
		draft.BurpReproduction = normalizeDeliverySyntheticText(draft.BurpReproduction)
		draft.AttackChain = normalizeDeliverySyntheticText(draft.AttackChain)
	}
	if draft.Description == "" || draft.Remediation == "" || draft.TestProcess == "" ||
		draft.AttackChain == "" || draft.BurpReproduction == "" {
		return deliveryReportDraft{}, &deliveryReportOutputError{
			cause: errDeliveryReportMissingBody, raw: text, stopReason: stopReason,
			contentBlockType: contentBlockTypes, outputTokens: usage.OutputTokens,
		}
	}
	draft.EvidenceVersion = evidenceVersion
	return draft, nil
}

func parseDeliveryReportMarkdownDraft(raw string) (deliveryReportDraft, bool) {
	text := strings.TrimSpace(raw)
	if strings.HasPrefix(text, "```") && strings.HasSuffix(text, "```") {
		lines := strings.Split(text, "\n")
		if len(lines) >= 3 {
			first := strings.TrimSpace(lines[0])
			last := strings.TrimSpace(lines[len(lines)-1])
			if strings.HasPrefix(first, "```") && last == "```" {
				lines = lines[1 : len(lines)-1]
				if strings.TrimSpace(lines[0]) == "markdown" || strings.TrimSpace(lines[0]) == "md" {
					lines = lines[1:]
				}
				text = strings.Join(lines, "\n")
			}
		}
	}

	type section struct {
		name      string
		start     int
		headingAt int
	}
	aliases := map[string]string{
		"描述": "描述", "漏洞描述": "描述",
		"修复": "修复建议", "修复建议": "修复建议",
		"测试过程": "测试过程", "攻击链路": "攻击链路", "Burp 复现": "Burp 复现",
	}
	sections := make([]section, 0, 5)
	valid := true
	closed := walkDeliveryMarkdown(text, func(line string, offset int) {
		level, heading := deliveryMarkdownHeading(line)
		if level != 2 {
			return
		}
		name, known := aliases[heading]
		if !known {
			valid = false
			return
		}
		start := offset + len(line)
		if start < len(text) && text[start] == '\r' {
			start++
		}
		if start < len(text) && text[start] == '\n' {
			start++
		}
		sections = append(sections, section{name: name, start: start, headingAt: offset})
	})
	if !valid || !closed || len(sections) != 5 {
		return deliveryReportDraft{}, false
	}
	expected := []string{"描述", "攻击链路", "测试过程", "Burp 复现", "修复建议"}
	for index, section := range sections {
		if section.name != expected[index] || (index > 0 && section.headingAt <= sections[index-1].headingAt) {
			return deliveryReportDraft{}, false
		}
	}
	body := func(index int) string {
		end := len(text)
		if index+1 < len(sections) {
			end = sections[index+1].headingAt
		}
		return strings.TrimSpace(text[sections[index].start:end])
	}
	draft := deliveryReportDraft{
		Description:      body(0),
		AttackChain:      body(1),
		TestProcess:      body(2),
		BurpReproduction: body(3),
		Remediation:      body(4),
	}
	for _, line := range strings.Split(text, "\n") {
		if index := strings.Index(line, "CVSS:4.0/"); index >= 0 {
			fields := strings.Fields(line[index:])
			if len(fields) > 0 {
				candidate := strings.TrimRight(fields[0], "，,。；;`*_)")
				if vector, ok := normalizeCVSS4BaseVector(candidate); ok {
					draft.CVSSVector = vector
					break
				}
			}
		}
	}
	return draft, true
}

func (s *Server) deliveryTrafficPackets(bindings []db.FindingTrafficBinding) (string, string, error) {
	if len(bindings) == 0 {
		return missingTrafficPacket, missingTrafficPacket, nil
	}
	if err := validateDeliveryTrafficEvidenceSize(bindings); err != nil {
		return "", "", err
	}
	store := s.evidenceStore()
	requests := make([]string, 0, len(bindings))
	responses := make([]string, 0, len(bindings))
	for _, binding := range bindings {
		requestPacket, err := deliveryHTTPPacket(store, binding.Snapshot, "request")
		if err != nil {
			return "", "", err
		}
		responsePacket, err := deliveryHTTPPacket(store, binding.Snapshot, "response")
		if err != nil {
			return "", "", err
		}
		label := fmt.Sprintf("证据绑定 %d（%s）", binding.ID, deliveryBindingRoleLabel(binding.Role))
		requests = append(requests, label+"\n"+requestPacket)
		responses = append(responses, label+"\n"+responsePacket)
	}
	return strings.Join(requests, "\n\n"), strings.Join(responses, "\n\n"), nil
}

func validateDeliveryTrafficEvidenceSize(bindings []db.FindingTrafficBinding) error {
	var totalBytes int64
	for _, binding := range bindings {
		totalBytes += int64(len(binding.Snapshot.ReqHead)+len(binding.Snapshot.RespHead)) + binding.Snapshot.ReqLen + binding.Snapshot.RespLen
		if totalBytes > deliveryReportEvidenceMaxBytes {
			return fmt.Errorf("绑定流量共 %d 字节，超过交付报告完整报文上限 %d 字节；未截断或保存报告", totalBytes, deliveryReportEvidenceMaxBytes)
		}
	}
	return nil
}

func deliveryBindingRoleLabel(role string) string {
	switch role {
	case "baseline":
		return "测试基线"
	case "proof":
		return "漏洞验证"
	case "verification":
		return "复核证据"
	case "supporting":
		return "辅助证据"
	default:
		return "流量证据"
	}
}

func (s *Server) appendDeliveryTrafficEvidence(ctx context.Context, findingID, evidenceVersion int64, report string) (string, error) {
	report = stripDeliveryTrafficEvidence(report)
	traffic, err := s.m.pg.GetFindingTraffic(ctx, findingID)
	if err != nil {
		return "", err
	}
	if traffic == nil || traffic.Version != evidenceVersion {
		return "", db.ErrEvidenceConflict
	}
	appendix, err := renderDeliveryTrafficEvidence(s.evidenceStore(), traffic.Bindings)
	if err != nil {
		return "", err
	}
	return strings.TrimRight(report, "\n") + "\n\n" + deliveryEvidenceAppendixMarker + "\n" + appendix, nil
}

func renderDeliveryTrafficEvidence(store *evidence.Store, bindings []db.FindingTrafficBinding) (string, error) {
	if len(bindings) == 0 {
		return "### 平台 HTTP 流量证据\n\n该漏洞未绑定 ARTEX HTTP 流量。若正文引用了任务记录中的其他原始报文，应注明其实际来源；没有原始内容的部分不能推测补写。", nil
	}
	if err := validateDeliveryTrafficEvidenceSize(bindings); err != nil {
		return "", err
	}
	var out strings.Builder
	out.WriteString("### 平台留存的 HTTP 请求与响应\n\n以下内容取自本漏洞绑定的 ARTEX 流量证据。头部由平台采集时整理，协议首行、头部顺序和换行格式可能与网络原始字节不同；正文读取完整留存内容。这里不补造协议版本、缺失请求头或响应头。每个代码块仅含一条留存报文，复现时应核对目标协议、TLS 和认证状态。\n")
	for _, binding := range bindings {
		request, requestBinary, err := readDeliveryHTTPPacket(store, binding.Snapshot, "request")
		if err != nil {
			return "", err
		}
		response, responseBinary, err := readDeliveryHTTPPacket(store, binding.Snapshot, "response")
		if err != nil {
			return "", err
		}
		capturedAt := "未留存"
		if binding.Snapshot.CapturedAt > 0 {
			capturedAt = time.Unix(binding.Snapshot.CapturedAt, 0).In(time.FixedZone("UTC+08:00", 8*60*60)).Format(time.RFC3339)
		}
		fmt.Fprintf(&out, "\n#### 证据绑定 %d\n\n- 角色：%s\n- 来源：ARTEX 平台流量\n- 源流量编号：%s\n- 采集时间：%s\n- 请求地址：%s\n- 用途：%s\n",
			binding.ID, deliveryBindingRoleLabel(binding.Role), deliveryEvidenceMetadata(binding.Snapshot.SourceTrafficID),
			capturedAt, deliveryEvidenceMetadata(binding.Snapshot.URL), deliveryEvidenceMetadata(binding.Note))
		out.WriteString("\n##### 请求包\n\n")
		writeDeliveryPacketNotice(&out, binding.Snapshot.ReqHead, requestBinary)
		out.WriteString(markdownPacketBlock(request))
		out.WriteString("\n\n##### 响应包\n\n")
		writeDeliveryPacketNotice(&out, binding.Snapshot.RespHead, responseBinary)
		out.WriteString(markdownPacketBlock(response))
		out.WriteByte('\n')
	}
	return out.String(), nil
}

func deliveryEvidenceMetadata(value string) string {
	if strings.TrimSpace(value) == "" {
		return "未留存"
	}
	return strings.NewReplacer("\\", "\\\\", "\r", "\\r", "\n", "\\n", "`", "\\`", "*", "\\*", "_", "\\_", "[", "\\[", "]", "\\]").Replace(html.EscapeString(value))
}

func writeDeliveryPacketNotice(out *strings.Builder, head string, binaryBody bool) {
	if strings.TrimSpace(head) == "" {
		out.WriteString("该方向报文头未留存，下面仅展示已留存正文或缺失提示，不能作为完整复现报文。\n\n")
	}
	if binaryBody {
		out.WriteString("该报文含二进制正文，以下使用 Base64 表示。重放前须解码还原原始字节，此代码块不能直接粘贴重放。\n\n")
	}
}

func stripDeliveryTrafficEvidence(report string) string {
	index := -1
	walkDeliveryMarkdown(report, func(line string, offset int) {
		if index < 0 && strings.TrimSpace(line) == deliveryEvidenceAppendixMarker {
			index = offset
		}
	})
	if index >= 0 {
		return strings.TrimRight(report[:index], "\r\n")
	}
	return report
}

func markdownPacketBlock(packet string) string {
	longest := 2
	for i := 0; i < len(packet); {
		if packet[i] != '`' {
			i++
			continue
		}
		start := i
		for i < len(packet) && packet[i] == '`' {
			i++
		}
		if run := i - start; run > longest {
			longest = run
		}
	}
	fence := strings.Repeat("`", longest+1)
	return fence + "http\n" + packet + "\n" + fence
}

const missingTrafficPacket = "未绑定 ARTEX 平台 HTTP 流量。若任务证据或执行记录中另有原始请求/响应，应从原始证据中引用并注明来源；仅凭流量未绑定不能断言未采集。"

func deliveryHTTPPacket(store *evidence.Store, snapshot db.TrafficEvidenceSnapshot, side string) (string, error) {
	packet, _, err := readDeliveryHTTPPacket(store, snapshot, side)
	return packet, err
}

func readDeliveryHTTPPacket(store *evidence.Store, snapshot db.TrafficEvidenceSnapshot, side string) (string, bool, error) {
	head := snapshot.ReqHead
	if side == "response" {
		head = snapshot.RespHead
	}
	file, total, err := store.OpenBody(snapshot, side)
	if err != nil {
		return "", false, err
	}
	defer file.Close()
	data, err := io.ReadAll(file)
	if err != nil {
		return "", false, err
	}
	if int64(len(data)) != total {
		return "", false, fmt.Errorf("HTTP %s 正文不完整：证据记录 %d 字节，实际读取 %d 字节", side, total, len(data))
	}
	body := string(data)
	binaryBody := bytesContainBinary(data)
	if binaryBody {
		body = fmt.Sprintf("[二进制正文，原始长度 %d 字节；以下为原始字节的 Base64 编码]\n%s", total, base64.StdEncoding.EncodeToString(data))
	}
	packet := strings.TrimRight(head, "\r\n")
	if packet != "" {
		packet += "\r\n\r\n"
	}
	packet += body
	if packet == "" {
		packet = "[该方向的 HTTP 报文未留存]"
	}
	return packet, binaryBody, nil
}

func bytesContainBinary(raw []byte) bool {
	return bytes.IndexByte(raw, 0) >= 0 || !utf8.Valid(raw)
}

var cvss4MetricValues = map[string]map[string]bool{
	"AV": {"N": true, "A": true, "L": true, "P": true}, "AC": {"L": true, "H": true}, "AT": {"N": true, "P": true},
	"PR": {"N": true, "L": true, "H": true}, "UI": {"N": true, "P": true, "A": true},
	"VC": {"H": true, "L": true, "N": true}, "VI": {"H": true, "L": true, "N": true}, "VA": {"H": true, "L": true, "N": true},
	"SC": {"H": true, "L": true, "N": true}, "SI": {"H": true, "L": true, "N": true}, "SA": {"H": true, "L": true, "N": true},
}

func normalizeCVSS4BaseVector(raw string) (string, bool) {
	parts := strings.Split(strings.TrimSpace(raw), "/")
	if len(parts) != 12 || parts[0] != "CVSS:4.0" {
		return "", false
	}
	metrics := strings.Split("AV AC AT PR UI VC VI VA SC SI SA", " ")
	out := []string{parts[0]}
	for i, name := range metrics {
		pair := strings.SplitN(parts[i+1], ":", 2)
		if len(pair) != 2 || pair[0] != name || !cvss4MetricValues[name][pair[1]] {
			return "", false
		}
		out = append(out, name+":"+pair[1])
	}
	return strings.Join(out, "/"), true
}
