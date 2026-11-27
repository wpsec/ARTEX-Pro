package server

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/wpsec/ARTEX-local/agent"
)

var (
	deliveryNarrativeAnnotation = regexp.MustCompile(`[（(]\s*(?:(?i:seq)\s*[:：]?\s*[0-9]+(?:\s*[-–—]\s*[0-9]+)?|[1-9][0-9]*\s*字节)\s*[）)]`)
	deliveryEmptyContentNote    = regexp.MustCompile(`[（(]\s*0\s*字节\s*[）)]`)
	deliveryNarrativeTerms      = strings.NewReplacer("逐字节完全相同", "完全相同", "逐字节相同", "完全相同", "上传腿", "上传步骤", "证据显示", "测试记录显示")
	deliveryFieldLine           = regexp.MustCompile(`^(?:[-*+]\s+)?(?:\*\*)?([^：:*]+)(?:\*\*)?[：:](?:\*\*)?\s*(.*)$`)
)

type deliveryField struct {
	label   string
	missing string
}

var (
	deliveryDescriptionFields = []deliveryField{{"漏洞现象", "待核实。"}, {"已确认影响", "待核实。"}, {"触发位置", "待核实。"}, {label: "测试范围"}}
	deliveryRemediationFields = []deliveryField{{"修复措施", "待补充。"}, {"修复后验收", "待核实。"}}
	deliveryTestProcessFields = []deliveryField{{"测试角色", "待核实。"}, {"预期行为", "待核实。"}, {"实际结果", "待核实。"}, {label: "未验证范围"}}
)

func normalizeStructuredDeliveryTestProcess(body string) string {
	timeLine, remaining, found := strings.Cut(strings.TrimLeft(body, " \t\r\n"), "\n")
	if !found || !(strings.HasPrefix(timeLine, "测试时间：") || strings.HasPrefix(timeLine, "测试时间:")) {
		return body
	}
	return normalizeStructuredDeliveryFields(body, strings.TrimLeft(remaining, " \t\r\n"), agent.DeliveryReportTestFactsMarker, deliveryTestProcessFields)
}

func normalizeStructuredDeliveryFields(body, marked, expectedMarker string, orderedFields []deliveryField) string {
	marker, facts, _ := strings.Cut(marked, "\n")
	if strings.TrimSpace(marker) != expectedMarker {
		return body
	}

	separator := "\n"
	if strings.HasSuffix(marker, "\r") {
		separator = "\r\n"
	}
	fields := make(map[string][]string)
	var label string
	var parts []string
	flush := func() {
		if label != "" && len(parts) > 0 {
			fields[label] = append(fields[label], strings.Join(parts, separator+"  "))
		}
		label, parts = "", nil
	}
	nextOffset := 0
	walkDeliveryMarkdown(facts, func(line string, offset int) {
		if offset != nextOffset {
			flush()
		}
		if newline := strings.IndexByte(facts[offset:], '\n'); newline >= 0 {
			nextOffset = offset + newline + 1
		}
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && strings.HasPrefix(line, "  ") && label != "" {
			parts = append(parts, trimmed)
			return
		}
		flush()
		if match := deliveryFieldLine.FindStringSubmatch(trimmed); len(match) > 0 {
			label = strings.TrimSpace(match[1])
			if value := strings.TrimSpace(match[2]); value != "" {
				parts = append(parts, value)
			}
		}
	})
	flush()
	lines := []string{expectedMarker}
	for _, field := range orderedFields {
		values := fields[field.label]
		if len(values) == 0 && field.missing != "" {
			values = []string{field.missing}
		}
		for _, value := range values {
			lines = append(lines, field.label+"："+value)
		}
	}
	return body[:len(body)-len(marked)] + strings.Join(lines, separator) + body[len(strings.TrimRight(body, " \t\r\n")):]
}

func normalizeStructuredDeliveryDescription(body string) string {
	return normalizeStructuredDeliveryFields(body, strings.TrimLeft(body, " \t\r\n"), agent.DeliveryReportFieldsMarker, deliveryDescriptionFields)
}

func normalizeStructuredDeliveryRemediation(body string) string {
	return normalizeStructuredDeliveryFields(body, strings.TrimLeft(body, " \t\r\n"), agent.DeliveryReportFieldsMarker, deliveryRemediationFields)
}

func normalizeGeneratedDeliverySection(report, heading string, normalize func(string) string) string {
	start, end := -1, len(report)
	walkDeliveryMarkdown(report, func(line string, offset int) {
		if end != len(report) {
			return
		}
		level, name := deliveryMarkdownHeading(line)
		if start < 0 {
			if level == 2 && name == heading {
				start = len(report)
				if newline := strings.IndexByte(report[offset:], '\n'); newline >= 0 {
					start = offset + newline + 1
				}
			}
			return
		}
		if level == 1 || level == 2 || strings.TrimSpace(line) == deliveryEvidenceAppendixMarker {
			end = offset
		}
	})
	if start < 0 {
		return report
	}
	return report[:start] + normalize(report[start:end]) + report[end:]
}

// The same cleanup runs on structured drafts and before reports are stored.
// It skips code and raw records and preserves the meaning of an empty body.
func normalizeDeliveryNarrative(report string, inNarrative bool) string {
	if !inNarrative && strings.Contains(report, agent.DeliveryReportTestFactsMarker) {
		report = normalizeGeneratedDeliverySection(report, "测试过程", normalizeStructuredDeliveryTestProcess)
	}
	if !inNarrative && strings.Contains(report, agent.DeliveryReportFieldsMarker) {
		report = normalizeGeneratedDeliverySection(report, "描述", normalizeStructuredDeliveryDescription)
		report = normalizeGeneratedDeliverySection(report, "修复建议", normalizeStructuredDeliveryRemediation)
	}
	var normalized strings.Builder
	nextOffset := 0
	inAppendix := false
	walkDeliveryMarkdown(report, func(line string, offset int) {
		if inAppendix {
			return
		}
		if strings.TrimSpace(line) == deliveryEvidenceAppendixMarker {
			inAppendix = true
			return
		}
		level, heading := deliveryMarkdownHeading(line)
		switch level {
		case 1:
			inNarrative = false
		case 2:
			inNarrative = heading == "描述" || heading == "漏洞描述" || heading == "测试过程" || heading == "修复" || heading == "修复建议"
		default:
			if level > 2 && (heading == "Burp 复现" || heading == "Burp 复现包" ||
				heading == "POC 脚本（Python）" || heading == "复现脚本（Python）") {
				inNarrative = false
			}
		}
		if level > 0 || !inNarrative || strings.ContainsRune(line, '`') || strings.HasPrefix(strings.TrimSpace(line), ">") ||
			!strings.HasPrefix(report[offset:], line) {
			return
		}
		readable := deliveryEmptyContentNote.ReplaceAllString(line, "（没有内容）")
		readable = deliveryNarrativeAnnotation.ReplaceAllString(readable, "")
		readable = deliveryNarrativeTerms.Replace(readable)
		if readable == line || strings.TrimSpace(readable) == "" {
			return
		}
		normalized.WriteString(report[nextOffset:offset])
		normalized.WriteString(readable)
		nextOffset = offset + len(line)
	})
	if nextOffset == 0 {
		return report
	}
	normalized.WriteString(report[nextOffset:])
	return normalized.String()
}

// Fenced packets and HTML comments can contain Markdown-looking evidence. They
// must not satisfy report headings or be mistaken for our generated appendix.
func walkDeliveryMarkdown(report string, visit func(line string, offset int)) bool {
	return scanDeliveryMarkdown(report, func(line string, offset int, code bool) {
		if !code {
			visit(line, offset)
		}
	})
}

func scanDeliveryMarkdown(report string, visit func(line string, offset int, code bool)) bool {
	var fence byte
	fenceLength := 0
	inComment := false
	for offset := 0; offset < len(report); {
		end := strings.IndexByte(report[offset:], '\n')
		next := len(report)
		if end >= 0 {
			next = offset + end + 1
			end += offset
		} else {
			end = len(report)
		}
		line := strings.TrimSuffix(report[offset:end], "\r")
		start := offset
		offset = next
		if fence != 0 {
			trimmed := strings.TrimSpace(line)
			run := 0
			for run < len(trimmed) && trimmed[run] == fence {
				run++
			}
			if !deliveryIndentedCode(line) && run >= fenceLength && strings.TrimSpace(trimmed[run:]) == "" {
				fence, fenceLength = 0, 0
			} else {
				visit(line, start, true)
			}
			continue
		}
		if deliveryIndentedCode(line) && !inComment {
			visit(line, start, true)
			continue
		}
		if !inComment {
			if marker, length := deliveryOpeningFence(line); marker != 0 {
				fence, fenceLength = marker, length
				continue
			}
		}
		if !inComment && strings.TrimSpace(line) == deliveryEvidenceAppendixMarker {
			visit(line, start, false)
			continue
		}
		line = deliveryVisibleLine(line, &inComment)
		if deliveryIndentedCode(line) {
			continue
		}
		visit(line, start, false)
	}
	return fence == 0 && !inComment
}

func deliveryOpeningFence(line string) (byte, int) {
	trimmed := strings.TrimSpace(line)
	if len(trimmed) < 3 || (trimmed[0] != '`' && trimmed[0] != '~') {
		return 0, 0
	}
	run := 1
	for run < len(trimmed) && trimmed[run] == trimmed[0] {
		run++
	}
	if run < 3 || (trimmed[0] == '`' && strings.ContainsRune(trimmed[run:], '`')) {
		return 0, 0
	}
	return trimmed[0], run
}

func deliveryIndentedCode(line string) bool {
	left := strings.TrimLeft(line, " ")
	return len(line)-len(left) >= 4 || strings.HasPrefix(left, "\t")
}

func deliveryVisibleLine(line string, inComment *bool) string {
	if !*inComment && !strings.Contains(line, "<!--") {
		return line
	}
	visible := []byte(line)
	for i := 0; i < len(line); {
		if *inComment {
			end := strings.Index(line[i:], "-->")
			next := len(line)
			if end >= 0 {
				next = i + end + 3
				*inComment = false
			}
			for j := i; j < next; j++ {
				visible[j] = ' '
			}
			i = next
			continue
		}
		if strings.HasPrefix(line[i:], "<!--") {
			*inComment = true
			continue
		}
		if line[i] == '`' {
			run := 1
			for i+run < len(line) && line[i+run] == '`' {
				run++
			}
			end := i + run
			matched := false
			for end < len(line) {
				if line[end] != '`' {
					end++
					continue
				}
				length := 1
				for end+length < len(line) && line[end+length] == '`' {
					length++
				}
				end += length
				if length == run {
					i = end
					matched = true
					break
				}
			}
			if !matched {
				i += run
			}
			continue
		}
		i++
	}
	return string(visible)
}

func deliverySectionHasContent(body string) bool {
	hasContent := false
	scanDeliveryMarkdown(body, func(line string, _ int, code bool) {
		trimmed := strings.TrimSpace(line)
		level, _ := deliveryMarkdownHeading(line)
		if trimmed != "" && trimmed != deliveryEvidenceAppendixMarker && (code || level == 0) {
			hasContent = true
		}
	})
	return hasContent
}

func deliveryMarkdownHeading(line string) (int, string) {
	line = strings.TrimSpace(line)
	level := 0
	for level < len(line) && line[level] == '#' {
		level++
	}
	if level == 0 || level == len(line) || (line[level] != ' ' && line[level] != '\t') {
		return 0, ""
	}
	text := strings.TrimSpace(line[level:])
	if suffix := strings.TrimRight(text, "#"); len(suffix) < len(text) && strings.HasSuffix(suffix, " ") {
		text = strings.TrimSpace(suffix)
	}
	return level, text
}

func deliveryAttackChainHasTree(report string) bool {
	start, end := -1, len(report)
	inAttackChain := false
	walkDeliveryMarkdown(report, func(line string, offset int) {
		level, title := deliveryMarkdownHeading(line)
		if level != 2 {
			return
		}
		if inAttackChain && end == len(report) {
			end = offset
		}
		inAttackChain = title == "攻击链路"
		if inAttackChain {
			start = offset + len(line)
		}
	})
	if start < 0 || end < start {
		return false
	}

	body := report[start:end]
	var fence byte
	fenceLength := 0
	textFence := false
	textFenceCount := 0
	treeRoot := false
	treeRootCount := 0
	treeBranch := false
	inComment := false
	for offset := 0; offset < len(body); {
		next := len(body)
		lineEnd := strings.IndexByte(body[offset:], '\n')
		if lineEnd >= 0 {
			next = offset + lineEnd + 1
			lineEnd += offset
		} else {
			lineEnd = len(body)
		}
		line := strings.TrimSuffix(body[offset:lineEnd], "\r")
		offset = next
		trimmed := strings.TrimSpace(line)
		if fence != 0 {
			run := 0
			for run < len(trimmed) && trimmed[run] == fence {
				run++
			}
			if !deliveryIndentedCode(line) && run >= fenceLength && strings.TrimSpace(trimmed[run:]) == "" {
				fence, fenceLength, textFence = 0, 0, false
				continue
			}
			if textFence {
				node := strings.TrimLeft(trimmed, "│ \t")
				if strings.HasPrefix(node, "#") {
					continue
				}
				branch := strings.HasPrefix(node, "├─") || strings.HasPrefix(node, "└─")
				if branch && treeRoot && strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(node, "├─"), "└─")) != "" {
					treeBranch = true
				}
				if node != "" && !branch {
					treeRoot = true
					treeRootCount++
				}
			}
			continue
		}
		if deliveryIndentedCode(line) && !inComment {
			continue
		}
		line = deliveryVisibleLine(line, &inComment)
		if deliveryIndentedCode(line) {
			continue
		}
		trimmed = strings.TrimSpace(line)
		marker, length := deliveryOpeningFence(line)
		if marker == 0 {
			continue
		}
		fence, fenceLength = marker, length
		info := strings.Fields(strings.TrimSpace(trimmed[length:]))
		textFence = len(info) > 0 && info[0] == "text"
		if textFence {
			textFenceCount++
		}
	}
	return textFenceCount == 1 && treeRoot && treeRootCount == 1 && treeBranch && fence == 0 && !inComment
}

func validateDeliveryReportTemplate(report, expectedVector string) error {
	report = stripDeliveryTrafficEvidence(report)
	sections := strings.Split(agent.DeliveryReportSectionOrder, "、")
	sectionIndex, bodyStart := -1, 0
	title, cvss := false, false
	vectorOccurrences := 0
	burpBodyStart, burpBodyEnd := -1, len(report)
	var problem string
	finishSection := func(end int) {
		if problem != "" || sectionIndex < 0 {
			return
		}
		if !deliverySectionHasContent(report[bodyStart:end]) {
			problem = "“" + sections[sectionIndex] + "”章节不能为空"
		}
	}
	closed := walkDeliveryMarkdown(report, func(line string, offset int) {
		if problem != "" {
			return
		}
		if strings.Contains(line, expectedVector) {
			vectorOccurrences++
		}
		if sectionIndex >= 0 && strings.Contains(line, "CVSS 4.0") {
			problem = "CVSS 信息只在报告头出现，不要在正文重复"
			return
		}
		level, text := deliveryMarkdownHeading(line)
		if level == 1 {
			if title || sectionIndex >= 0 || text == "" {
				problem = "只能在报告头保留一个非空一级标题"
				return
			}
			title = true
		}
		if level == 2 {
			if sectionIndex >= 0 {
				finishSection(offset)
				if sections[sectionIndex] == "Burp 复现" && burpBodyEnd == len(report) {
					burpBodyEnd = offset
				}
				if problem != "" {
					return
				}
			}
			next := sectionIndex + 1
			if next >= len(sections) || text != sections[next] {
				problem = "二级标题缺失、重复或顺序错误：“" + text + "”"
				return
			}
			sectionIndex = next
			bodyStart = offset + len(line)
			if text == "Burp 复现" {
				burpBodyStart = bodyStart
			}
			return
		}
		if level == 3 {
			problem = "固定章节内不得添加额外子标题：“" + text + "”"
			return
		}
		if level > 3 {
			problem = "报告最多使用二级章节标题"
			return
		}
		if sectionIndex < 0 {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "漏洞名称：") || strings.HasPrefix(trimmed, "漏洞名称:") {
				problem = "一级标题已经是漏洞名称，不要重复输出“漏洞名称”字段"
				return
			}
			if strings.HasPrefix(trimmed, "- **CVSS 4.0") || strings.HasPrefix(trimmed, "- **漏洞等级") {
				problem = "CVSS 向量、分数和等级必须合并为一行，不要重复列出"
				return
			}
			for _, prefix := range []string{"CVSS 4.0：", "CVSS 4.0:"} {
				if strings.HasPrefix(trimmed, prefix) {
					fields := strings.Fields(strings.TrimPrefix(trimmed, prefix))
					if cvss {
						problem = "CVSS 报告头重复"
						return
					}
					if len(fields) == 0 {
						problem = "CVSS 报告头缺少完整 Base 向量"
						return
					}
					vector, valid := normalizeCVSS4BaseVector(fields[0])
					if !valid || vector != expectedVector {
						problem = "CVSS 报告头无效或与 cvss_vector 参数不一致"
						return
					}
					if !deliveryCVSSHeaderHasScore(trimmed, prefix, fields[0]) {
						problem = "CVSS 报告头须包含有效分数或标注待复核"
						return
					}
					cvss = true
				}
			}
		}
	})
	if problem == "" && sectionIndex >= 0 {
		finishSection(len(report))
	}
	if problem == "" && !closed {
		problem = "代码块或 HTML 注释未闭合"
	}
	if problem == "" && (!title || !cvss) {
		problem = "报告头须包含作为漏洞名称的一级标题及带评分的一行完整 CVSS 4.0 Base 向量"
	}
	if problem == "" && vectorOccurrences != 1 {
		problem = "CVSS 向量只能在报告头出现一次"
	}
	if problem == "" && sectionIndex != len(sections)-1 {
		problem = "缺少必需章节"
	}
	if problem == "" && burpBodyStart >= 0 {
		burpBody := report[burpBodyStart:burpBodyEnd]
		burpNotApplicable := strings.Contains(burpBody, "Burp 不适用")
		burpPacketPresent := deliveryBurpHTTPRequestBlockPresent(burpBody)
		if !burpNotApplicable && !burpPacketPresent {
			problem = "“Burp 复现”必须提供 http 请求包；仅非 HTTP 场景可注明 Burp 不适用"
		} else if !burpNotApplicable && deliveryBurpClaimsActualSend(burpBody) {
			problem = "Burp 请求包仅供工程师复现或复测，不得描述为已通过 Burp 发送或验证"
		}
	}
	if problem == "" && !deliveryAttackChainHasTree(report) {
		problem = "“攻击链路”必须包含 text 代码块树形链路，且有起点和带内容的分支"
	}
	if problem != "" {
		return fmt.Errorf("交付报告格式不符合固定模板：%s；二级标题必须按顺序为：%s。请保留各节，证据不足写“未验证”，补齐后重新保存", problem, strings.Join(sections, "、"))
	}
	return nil
}

func deliveryBurpHTTPRequestBlockPresent(content string) bool {
	lines := strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n")
	var fence byte
	fenceLength := 0
	httpFence := false
	requestFound := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if fence == 0 {
			marker, length := deliveryOpeningFence(line)
			if marker == 0 {
				continue
			}
			fence, fenceLength = marker, length
			httpFence = strings.EqualFold(strings.TrimSpace(trimmed[length:]), "http")
			requestFound = false
			continue
		}
		run := 0
		for run < len(trimmed) && trimmed[run] == fence {
			run++
		}
		if run >= fenceLength && strings.TrimSpace(trimmed[run:]) == "" {
			if httpFence && requestFound {
				return true
			}
			fence, fenceLength, httpFence, requestFound = 0, 0, false, false
			continue
		}
		if httpFence && isDeliveryHTTPRequestLine(trimmed) {
			requestFound = true
		}
	}
	return false
}

func deliveryCVSSHeaderHasScore(line, prefix, vector string) bool {
	fields := strings.Fields(strings.TrimSpace(strings.TrimPrefix(line, prefix)))
	if len(fields) < 2 || fields[0] != vector {
		return false
	}
	if strings.HasPrefix(fields[1], "评分待复核") {
		return true
	}
	if fields[1] != "评分" || len(fields) < 3 {
		return false
	}
	if strings.HasPrefix(fields[2], "待复核") {
		return true
	}
	scoreText := fields[2]
	if boundary := strings.IndexAny(scoreText, "（("); boundary >= 0 {
		scoreText = scoreText[:boundary]
	}
	score, err := strconv.ParseFloat(scoreText, 64)
	return err == nil && score >= 0 && score <= 10
}

func deliveryBurpClaimsActualSend(content string) bool {
	phrases := []string{
		"已通过 Burp 发送", "已在 Burp 中发送", "已在 Burp Repeater 中发送",
		"本次在 Burp 中发送", "实际在 Burp 中发送", "Burp Repeater 实际发送",
		"本次使用 Burp Repeater 发送", "实际使用 Burp Repeater 发送",
		"已通过 Burp Repeater 验证", "已在 Burp 中验证",
	}
	claimed := false
	scanDeliveryMarkdown(content, func(line string, _ int, code bool) {
		if claimed || code {
			return
		}
		for _, phrase := range phrases {
			searchFrom := 0
			for searchFrom < len(line) {
				relative := strings.Index(line[searchFrom:], phrase)
				if relative < 0 {
					break
				}
				position := searchFrom + relative
				clauseStart := strings.LastIndexAny(line[:position], "。！？；\n") + 1
				prefix := strings.TrimSpace(line[clauseStart:position])
				negated := false
				for _, marker := range []string{"不代表", "并未", "未曾", "尚未", "没有", "无法", "不能", "不得", "未", "不"} {
					if strings.HasSuffix(prefix, marker) {
						negated = true
						break
					}
				}
				if !negated {
					claimed = true
					return
				}
				searchFrom = position + len(phrase)
			}
		}
	})
	return claimed
}
