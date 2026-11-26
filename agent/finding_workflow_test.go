package agent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	actool "github.com/Autumn-27/norma/tool"
)

func TestFindingWorkflowSharedAssemblyAndSwitch(t *testing.T) {
	oldPolicy, oldResolve, oldAugment := FindingTrafficBindingEnabled, ToolResolve, ToolAugment
	t.Cleanup(func() { FindingTrafficBindingEnabled, ToolResolve, ToolAugment = oldPolicy, oldResolve, oldAugment })
	ToolAugment = nil
	on := false
	FindingTrafficBindingEnabled = func() bool { return on }
	ts := NewToolSet(nil, "fixture")
	ToolResolve = func(_ context.Context, _ string, base []actool.CoreTool) []actool.CoreTool {
		out := make([]actool.CoreTool, len(base))
		for i, tool := range base {
			out[i] = DecorateTool(tool, "CUSTOM DESCRIPTION", tool.InputSchema())
		}
		return out
	}
	for _, role := range []string{"worker", "planner", "mainagent", "auto", "pentest", "custom-agent"} {
		for _, enabled := range []bool{false, true, false} {
			on = enabled
			out, def, cleanup := AugmentTools(t.Context(), role, []actool.CoreTool{ts.addFinding(), ts.addHint()})
			cleanup()
			system, _ := deferredSystem("USER CUSTOM PROMPT", def)
			if !strings.HasPrefix(system[0], "USER CUSTOM PROMPT") {
				t.Fatal("custom prompt replaced")
			}
			if strings.Contains(system[0], "traffic_refs") != on {
				t.Fatalf("%s: guidance ignored switch: %v", role, on)
			}
			if on && (!strings.Contains(system[0], "TCP") || !strings.Contains(system[0], "evidence_hint_id")) {
				t.Fatal("missing optional/handoff contract")
			}
			for _, tool := range out {
				if !strings.HasPrefix(tool.Description(), "CUSTOM DESCRIPTION") {
					t.Fatal("custom description replaced")
				}
				raw, _ := json.Marshal(tool.InputSchema())
				var schema map[string]any
				json.Unmarshal(raw, &schema)
				props := schema["properties"].(map[string]any)
				if (props["traffic_refs"] != nil) != on {
					t.Fatalf("%s: binding schema ignored switch", role)
				}
				if tool.Name() == "add_hint" {
					nested := props["hints"].(map[string]any)["items"].(map[string]any)["properties"].(map[string]any)
					if (nested["traffic_refs"] != nil) != on {
						t.Fatal("nested hint schema ignored switch")
					}
				}
			}
		}
	}
	on = true
	ToolResolve = func(context.Context, string, []actool.CoreTool) []actool.CoreTool { return nil }
	out, def, cleanup := AugmentTools(t.Context(), "planner", []actool.CoreTool{ts.addFinding()})
	defer cleanup()
	if len(out) != 0 || def.FindingGuidance != "" {
		t.Fatal("reintroduced disabled tool or its guidance")
	}
}

func TestReportTemplateContractReachesCustomToolsWithBindingDisabled(t *testing.T) {
	old := FindingTrafficBindingEnabled
	FindingTrafficBindingEnabled = func() bool { return false }
	t.Cleanup(func() { FindingTrafficBindingEnabled = old })
	tool := actool.Build(actool.Spec{Name: "update_finding_report", Description: "USER CUSTOM DESCRIPTION", Schema: map[string]any{"type": "object"}})
	tools, guidance := findingWorkflowTools("custom-agent", []actool.CoreTool{tool})
	if len(tools) != 1 || !strings.HasPrefix(tools[0].Description(), tool.Description()) || !strings.Contains(tools[0].Description(), DeliveryReportSectionOrder) || !strings.Contains(tools[0].Description(), DeliveryReportEvidenceGuidance) {
		t.Fatal("report save contract was lost with custom descriptions or disabled binding")
	}
	if tool.Description() != "USER CUSTOM DESCRIPTION" {
		t.Fatal("runtime decoration modified the original tool")
	}
	if !strings.Contains(guidance, DeliveryReportRuntimeGuidance) || !strings.Contains(guidance, DeliveryReportChainGuidance) || !strings.Contains(guidance, DeliveryReportEvidenceGuidance) || !strings.Contains(guidance, DeliveryReportStyleGuidance) {
		t.Fatal("custom reporter lost the writing rules while traffic binding was disabled")
	}
}

func TestReportRuntimeGuidanceFollowsFinalPermissions(t *testing.T) {
	oldPolicy, oldResolve, oldAugment := FindingTrafficBindingEnabled, ToolResolve, ToolAugment
	t.Cleanup(func() { FindingTrafficBindingEnabled, ToolResolve, ToolAugment = oldPolicy, oldResolve, oldAugment })
	ToolAugment = nil
	report := actool.Build(actool.Spec{Name: "update_finding_report", Description: "CUSTOM REPORT TOOL", Schema: map[string]any{"type": "object"}})
	read := actool.Build(actool.Spec{Name: "get_finding_traffic", Description: "READ ONLY", Schema: map[string]any{"type": "object"}})
	for _, role := range []string{"reporter", "planner", "mainagent", "custom-agent"} {
		for _, binding := range []bool{false, true} {
			FindingTrafficBindingEnabled = func() bool { return binding }
			for _, permitted := range []bool{false, true} {
				ToolResolve = func(_ context.Context, _ string, tools []actool.CoreTool) []actool.CoreTool {
					if !permitted {
						return []actool.CoreTool{read}
					}
					return tools
				}
				tools, def, cleanup := AugmentTools(t.Context(), role, []actool.CoreTool{report, read})
				cleanup()
				system, _ := deferredSystem("USER CUSTOM PROMPT", def)
				if !strings.HasPrefix(system[0], "USER CUSTOM PROMPT") {
					t.Fatal("runtime guidance replaced user content")
				}
				if strings.Contains(system[0], DeliveryReportRuntimeGuidance) != permitted {
					t.Fatalf("role=%s binding=%v permitted=%v: writing guidance ignored final permissions", role, binding, permitted)
				}
				if strings.Contains(system[0], DeliveryReportStyleGuidance) != permitted {
					t.Fatalf("role=%s binding=%v permitted=%v: style guidance ignored final permissions", role, binding, permitted)
				}
				if strings.Contains(system[0], DeliveryReportChainGuidance) != permitted {
					t.Fatalf("role=%s binding=%v permitted=%v: chain guidance ignored final permissions", role, binding, permitted)
				}
				if strings.Contains(system[0], DeliveryReportEvidenceGuidance) != permitted {
					t.Fatalf("role=%s binding=%v permitted=%v: evidence guidance ignored final permissions", role, binding, permitted)
				}
				if !permitted {
					for _, tool := range tools {
						if tool.Name() == report.Name() {
							t.Fatal("runtime guidance restored a disabled report tool")
						}
					}
					continue
				}
				stock, _ := deferredSystem(ReporterDefaultPrompt, def)
				if strings.Count(stock[0], DeliveryReportRuntimeGuidance) != 1 || strings.Count(stock[0], DeliveryReportChainGuidance) != 1 || strings.Count(stock[0], DeliveryReportEvidenceGuidance) != 1 || strings.Count(stock[0], DeliveryReportStyleGuidance) != 1 || !strings.Contains(stock[0], findingIDGuidance) {
					t.Fatal("stock prompt duplicated the writing rules or lost the ID contract")
				}
			}
		}
	}
}

func TestReporterDefaultPromptUsesMarkdownRulesWithoutJSONContract(t *testing.T) {
	if strings.Count(ReporterDefaultPrompt, DeliveryReportWritingRules) != 1 {
		t.Fatal("Reporter default must include the Markdown writing rules exactly once")
	}
	if strings.Contains(ReporterDefaultPrompt, `"cvss_vector":""`) || strings.Contains(ReporterDefaultPrompt, "description 先写问题") {
		t.Fatal("Reporter default must not include the compatibility endpoint's JSON draft contract")
	}
}

func TestDeliveryReportKeepsExecutionLedgerOutOfDeliveryBody(t *testing.T) {
	for _, required := range []string{
		"仅适用于交付报告字段",
		"不改变详细报告的章节和台账",
		"动笔前先从原始请求/响应、命令输出和执行记录整理事实，不输出清单",
		"根因（只有源码、配置或日志能证明时才填写，否则记为未知）",
		"正文每项陈述都须能对应到这些事实",
		"状态码或响应头不能证明响应正文已返回",
		"合成、演示或占位",
		"不能单独证明跨账号访问成功、文件正文已返回、预期功能遭违反或真实数据已泄露",
		"不得称为真实用户资料、敏感数据或实际泄露",
		"本次只观察到合成样本，未验证真实数据泄露",
		"禁止声称发生任何真实数据泄露或机密性影响",
		"输入标记 synthetic=true 或证据来源标为离线合成时，描述第一句必须写",
		"不得把样本内容本身称为“合成样本泄露”",
		"Burp 复现章节必须写“Burp 不适用”，不得编造 HTTP 接口、请求行或请求包",
		"不要列出第二种措施",
		"观察到重复结果只能确认重复结果",
		"身份/权限证明",
		"行为已确认且有直接针对该行为的措施时，可建议一项措施",
		"确认 SQL 参数可改变查询逻辑时，只建议参数化查询",
		"缺陷行为未确认时只列待补证据，不给条件式代码建议",
		"业务约定一个编号只能登记一次而观察到重复记录时，描述为违反业务约定",
		"业务约定一个编号只能登记一次时，只建议阻止相同编号重复登记",
		"SQL 参数改变查询逻辑时只写“使用参数化查询”",
		"攻击链不可以省略重复请求",
		"布尔注入的真、假条件各自成并列分支",
		"非 HTTP 攻击链以“本地终端记录”为根",
		"不要把占位主机、身份、Cookie 或 Token 改成真实测试条件",
		"所有 HTTP 报告都必须有独立的 Burp 复现章节和至少一段足以复现核心结论的 HTTP 请求包",
		"首条证据请求采集时间",
		"没有可靠记录时写“测试时间：未记录”",
		"修复建议只写一项与已确认行为相符的主要措施",
		"失败尝试只写实际做过且失败的操作",
		"Repeater 串行重放不能证明并发",
		"攻击链只画一棵树。单一流程以材料中的页面或功能入口为根",
		"根节点可用“验证请求组”仅作分组",
		"每个 HTTP 请求或命令行都必须缩进并以 ├─ 或 └─ 开始",
		"命令及路径必须逐字复制原始记录",
		"request_occurrence_index 的每一条记录都必须在攻击链单独对应一个以完整 METHOD/path 开始的节点",
		"X-Eval-Actor 是合成场景标记，不是凭据",
		"HTTP METHOD/path 必须逐字复制 request_line_index",
		"独立对照放在单独分支，不得接在主流程结果之后造成因果暗示",
		"回读查询放在并发组之后",
		"多条请求不等于并发",
		"正文以 800 字为参考预算",
		"第一行写测试时间，随后逐行使用上述业务字段",
		"每项事实只展开一次",
		"正文写给开发看",
		"不要把交付报告的精简要求套到详细报告",
		"保存前在本次输出中核对结论、限制、修复和链路",
		"攻击链不超过 230 字",
		"相同结果的重复验证合并说明",
		"把字节数、逐字节比较、内部序号、脚本阶段名称和具体文件属主留在测试台账",
		"黑盒测试按功能和外部表现定位",
		"在链路树中用“入口：”“校验缺口：”“实际影响：”标明对应的业务节点",
		"缺陷行为已确认时，即使没有源码，也要写清应在什么业务环节应用哪条规则",
		"涉及多个环节的同一授权规则应覆盖所有已确认的环节",
		"<!-- artex:developer-test-facts-v1 -->",
		"<!-- artex:developer-report-fields-v1 -->",
		"描述按行写“漏洞现象：”“已确认影响：”“触发位置：”",
		"修复建议按行写“修复措施：”和“修复后验收：”",
		"材料无法确认某种影响时，在未验证范围直接说清无法确认什么",
		"用功能的业务名称开头",
		"写实际页面、菜单或按钮，以及对应的正常业务动作",
		"写接口所属模块、业务用途和浏览器入口的核实状态",
		"只有记录确认没有前台入口时，才称为隐藏接口",
		"把评分向量放在报告头",
		"业务约定和已观察结果可以定义修复目标，但不能反推出当前代码的具体实现缺陷",
		"建议中只能出现一项措施",
	} {
		if !strings.Contains(DeliveryReportWritingRules, required) {
			t.Fatalf("delivery report guidance is missing %q", required)
		}
	}
	for _, absent := range []string{"正文以 500 字符为目标、最多 800 字符", "禁用“判决项”", "执行工具：未记录"} {
		if strings.Contains(DeliveryReportWritingRules, absent) {
			t.Fatalf("delivery report guidance retains a style blacklist or hard limit: %q", absent)
		}
	}
	if !strings.Contains(DeliveryReportDraftRules, "简述测试角色、预期行为和实际结果") {
		t.Fatal("JSON drafts must lead with what the developer needs to compare")
	}
	if !strings.Contains(DeliveryReportDraftRules, "描述最后另起一行写“触发位置：…”") {
		t.Fatal("JSON drafts must include the same location guidance as Markdown reports")
	}
	if !strings.Contains(DeliveryReportDraftRules, "<!-- artex:developer-test-facts-v1 -->") {
		t.Fatal("JSON drafts must include the same verified test fields as Markdown reports")
	}
	if strings.Contains(DeliveryReportWritingRules, "JSON 的 description 字段") || !strings.Contains(DeliveryReportDraftRules, "description 用短句写问题") ||
		!strings.Contains(DeliveryReportDraftRules, "cvss_vector 优先使用输入提供的有效向量") ||
		!strings.Contains(DeliveryReportDraftRules, "attack_chain 只写一棵短树。单一流程的根节点使用实际页面或功能入口") ||
		!strings.Contains(DeliveryReportDraftRules, "格式示例：\n验证请求组\n├─ 主流程") {
		t.Fatal("JSON draft format rules must stay separate from the full Markdown Reporter rules")
	}
}
