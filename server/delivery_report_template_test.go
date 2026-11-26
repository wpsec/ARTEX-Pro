package server

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/wpsec/ARTEX-local/agent"
)

func TestNormalizeDeliveryNarrativePreservesFactsAndOriginalRecords(t *testing.T) {
	report := strings.Join([]string{
		"# 测试样本",
		"## 描述",
		"普通账号能看到其他部门的目录（seq 5–11）。",
		"## 测试过程",
		"证据显示两次返回的列表逐字节相同（87 字节）。文件详情的响应（0 字节），内容未验证。",
		"~~~text",
		"逐字节相同（seq 5–11）",
		"~~~",
		"## 攻击链路",
		"逐字节相同（seq 5–11）",
		"## 修复建议",
		"服务端返回目录前先核对访问权限。",
		deliveryEvidenceAppendixMarker,
		"## 测试过程",
		"逐字节相同（seq 5–11）",
	}, "\r\n")
	want := strings.Replace(
		report,
		"普通账号能看到其他部门的目录（seq 5–11）。",
		"普通账号能看到其他部门的目录。",
		1,
	)
	want = strings.Replace(
		want,
		"证据显示两次返回的列表逐字节相同（87 字节）。文件详情的响应（0 字节），内容未验证。",
		"测试记录显示两次返回的列表完全相同。文件详情的响应（没有内容），内容未验证。",
		1,
	)
	if got := normalizeDeliveryNarrative(report, false); got != want {
		t.Fatalf("unexpected normalized report:\n%s", got)
	}
	if got := normalizeDeliveryNarrative("内容逐字节相同（seq 5–11）。", true); got != "内容完全相同。" {
		t.Fatalf("structured draft field normalized to %q", got)
	}
}

func TestNormalizeStructuredDeliveryTestProcess(t *testing.T) {
	const time = "测试时间：未记录"
	marker := agent.DeliveryReportTestFactsMarker
	legacy := time + "\n其他部门的文件内容未验证。"
	insideFence := time + "\n~~~text\n" + marker + "\n~~~"
	for _, input := range []string{legacy, insideFence} {
		if got := normalizeStructuredDeliveryTestProcess(input); got != input {
			t.Fatalf("changed an unmarked test process: %q", got)
		}
	}
	input := strings.Join([]string{
		"", time, "", marker,
		"未验证范围：现有记录无法确认响应包含用户列表。",
		"  文件预览也未核实。",
		"- **测试角色：** 部门成员。",
		"复核分组记在台账的蓝色标签下。",
		"~~~text", "实际结果：示例台账内容。", "~~~", "", "",
	}, "\r\n")
	want := strings.Join([]string{
		"", time, "", marker,
		"测试角色：部门成员。",
		"预期行为：待核实。",
		"实际结果：待核实。",
		"未验证范围：现有记录无法确认响应包含用户列表。",
		"  文件预览也未核实。", "", "",
	}, "\r\n")
	if got := normalizeStructuredDeliveryTestProcess(input); got != want {
		t.Fatalf("unexpected marked test facts:\n%s", got)
	}
	if got := normalizeStructuredDeliveryTestProcess(want); got != want {
		t.Fatalf("normalization changed existing continuations:\n%s", got)
	}
}

func TestValidateDeliveryReportTemplate(t *testing.T) {
	vector := "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"
	valid := deliveryReportFixture("重复请求的实际影响未验证。", vector)
	cases := []struct {
		name   string
		report string
		valid  bool
	}{
		{"fixed template", valid, true},
		{"CRLF", strings.ReplaceAll(valid, "\n", "\r\n"), true},
		{"packet contains headings", valid + "\n\n" + markdownPacketBlock("HTTP/1.1 200 OK\n\n## 描述\n### Burp 复现"), true},
		{"tree contains headings", strings.Replace(valid, "请求结果和业务影响未验证", "请求结果和业务影响未验证\n## 修复建议\n", 1), true},
		{"no title", strings.Replace(valid, "# 测试系统-模块 /test 测试缺陷：测试结果", "测试报告", 1), false},
		{"duplicate finding name", strings.Replace(valid, "CVSS 4.0：", "漏洞名称：测试系统-模块 /test 测试缺陷\nCVSS 4.0：", 1), false},
		{"invalid header vector", strings.Replace(valid, vector, "CVSS:4.0/AV:N", 1), false},
		{"attack chain without tree", strings.Replace(valid, "└─ 请求结果和业务影响未验证", "请求结果和业务影响未验证", 1), false},
		{"attack chain has multiple roots", strings.Replace(valid, "└─ 请求结果和业务影响未验证", "另一个请求根节点\n└─ 请求结果和业务影响未验证", 1), false},
		{"attack chain splits into multiple trees", strings.Replace(valid, "## 测试过程", "```text\n第二个根节点\n└─ 第二个结果\n```\n\n## 测试过程", 1), false},
		{"packet cannot supply attack chain", strings.Replace(valid, "## 攻击链路", "```http\n## 攻击链路\n```", 1), false},
		{"comment cannot supply attack chain", strings.Replace(valid, "## 攻击链路", "<!--\n## 攻击链路\n-->", 1), false},
		{"wrong section order", strings.Replace(valid, "## 修复建议", "## 测试过程", 1), false},
		{"duplicate section", valid + "\n\n## 描述\n重复章节。", false},
		{"empty remediation", strings.Replace(valid, "现有材料不足以定位具体实现，需结合源码确认修复位置。", " \t\n", 1), false},
		{"unexpected nested heading", strings.Replace(valid, "测试时间：未记录", "### 非预期栏目\n\n测试时间：未记录", 1), false},
		{"missing required section", strings.Replace(valid, "## Burp 复现", "## 其他标题", 1), false},
		{"missing CVSS score", strings.Replace(valid, " 评分待复核", "", 1), false},
		{"no forced time or tool ledger", valid, true},
		{"timestamp wording is not a format gate", strings.Replace(valid, "测试时间：未记录", "测试时间：2026-11-01 10:00:00。协议和工具未记录。", 1), true},
		{"Burp wording is reviewed as content", strings.Replace(valid, "请求包供渗透测试工程师在授权目标中导入 Burp Repeater 复现或复测；请求包本身不代表已发送或验证。", "HTTP 工具请求包供授权测试人员使用。", 1), true},
		{"non-HTTP Burp note", strings.Replace(valid, "```http\nGET /test HTTP/1.1\nHost: <需从授权账号重新捕获>\n```", "Burp 不适用：本地命令验证。", 1), true},
		{"repeated CVSS in body", strings.Replace(valid, "重复请求的实际影响未验证。", "CVSS 4.0："+vector, 1), false},
		{"risk rationale in body", strings.Replace(valid, "重复请求的实际影响未验证。", "当前材料支持低危判断，重复请求的其他影响未验证。", 1), true},
		{"SQL remediation quality is reviewed as content", strings.Replace(strings.Replace(valid, "重复请求的实际影响未验证。", "SQL 注入结论待核实。", 1), "现有材料不足以定位具体实现，需结合源码确认修复位置。", "对 name 字段进行输入校验与过滤。", 1), true},
		{"unsupported extraction wording is reviewed as content", strings.Replace(valid, "重复请求的实际影响未验证。", "真假响应差异只能说明响应不同，未取得数据。", 1), true},
		{"internal wording is not a save rejection", strings.Replace(valid, "重复请求的实际影响未验证。", "W07 的归属对照仍需核验。", 1), true},
		{"domain term in body", strings.Replace(valid, "重复请求的实际影响未验证。", "响应中的文件所有者与测试账号不一致，其他影响未验证。", 1), true},
		{"inline XSS payload", strings.Replace(valid, "重复请求的实际影响未验证。", "测试参数包含 `<!--`，实际影响未验证。", 1), true},
		{"multiple-backtick payload", strings.Replace(valid, "重复请求的实际影响未验证。", "测试参数包含 ``x`<!--``，实际影响未验证。", 1), true},
		{"fence info contains comment syntax", strings.Replace(valid, "重复请求的实际影响未验证。", "```text <!--\n实际影响未验证。\n```", 1), true},
		{"inline triple backticks", strings.Replace(valid, "重复请求的实际影响未验证。", "```payload```", 1), true},
		{"different valid header vector", strings.Replace(valid, "/PR:N/", "/PR:L/", 1), false},
		{"unclosed packet", valid + "\n\n```http\nGET / HTTP/1.1", false},
		{"unclosed comment", valid + "\n\n<!-- note", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateDeliveryReportTemplate(tc.report, vector)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v, error=%v", tc.valid, err)
			}
		})
	}
}

func TestFindingReportToolRejectsInvalidTemplateBeforeDatabase(t *testing.T) {
	old := agent.FindingTrafficBindingEnabled
	agent.FindingTrafficBindingEnabled = nil
	t.Cleanup(func() { agent.FindingTrafficBindingEnabled = old })
	input, err := json.Marshal(map[string]any{
		"finding_id": 1, "report": "详细报告", "delivery_report": "缺少攻击链的报告",
		"cvss_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N", "evidence_version": 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := (&Server{}).toolUpdateFindingReport().Call(context.Background(), input, nil)
	if err != nil || !result.IsError || !strings.Contains(result.Flatten(), "固定模板") {
		t.Fatalf("invalid report was not rejected before database access: result=%v error=%v", result, err)
	}
}

func TestReporterTemplateUpgradeRecognizesDefaultsAndPreservesEdits(t *testing.T) {
	if !reporterPromptHashNeedsTemplateUpgrade("92150e16f0ec293e597f4b5b0631ac1793a5515d93fb614c1449f2c79cae53df") {
		t.Fatal("previous default prompt with duplicated JSON and Markdown rules would not receive the migration")
	}
	if !reporterPromptHashNeedsTemplateUpgrade("786d3a6b59b52c4d998398d297f41091d2db0187d2f47f21c3f531e9ec5489c2") {
		t.Fatal("previous v17 default prompt would not receive the unified fact and evidence rules")
	}
	if !reporterPromptHashNeedsTemplateUpgrade("17aa6f65e6d88922dc086b17730357c00b3ef9d55535a85d513eb3cc795ede4e") {
		t.Fatal("previous v18 default prompt would not receive the updated length and endpoint rules")
	}
	const previousV19Hash = "2e629b3e35fcab552a9a901419af419dfb721ebf15a654e9f8443f1c44d2d3ee"
	if !reporterPromptHashNeedsTemplateUpgrade(previousV19Hash) {
		t.Fatal("previous v19 stock prompt would keep duplicating the shared chain rules")
	}
	const previousV20Hash = "29a290fbc2d42bce7cf282b8c4da46605ee4deac38b9cf7df2500dad13d8171f"
	if !reporterPromptHashNeedsTemplateUpgrade(previousV20Hash) {
		t.Fatal("previous v20 stock prompt would miss the updated evidence boundaries")
	}
	const previousV21Hash = "cf8c3a66a8230ab9bf7095d32e7025e56135010936d1f86765acc413ba441023"
	if !reporterPromptHashNeedsTemplateUpgrade(previousV21Hash) {
		t.Fatal("previous v21 stock prompt would miss independent comparison and potential-impact guidance")
	}
	const previousV22Hash = "0b3a0eec07ad86b6302a9072399ad5cecf46cf3d21dabd0192ee5277b5191834"
	if !reporterPromptHashNeedsTemplateUpgrade(previousV22Hash) {
		t.Fatal("previous v22 stock prompt would miss Burp request packets and plain-language results")
	}
	const previousV23Hash = "54343d87df0ffdff1aeec0d3e58dd3bd23b7fb138884bc8719cc01ca5e85fe63"
	if !reporterPromptHashNeedsTemplateUpgrade(previousV23Hash) {
		t.Fatal("previous v23 stock prompt would omit Burp packets when Burp was used")
	}
	const previousV24Hash = "506d290c34bc78e4d52d1665b5e740466a379fe803b4cff2e3dc2efca090e371"
	if !reporterPromptHashNeedsTemplateUpgrade(previousV24Hash) {
		t.Fatal("previous v24 stock prompt would miss field budgets and de-duplication guidance")
	}
	const previousV25Hash = "f1850be22e070adce5879d7e6cf58e0afb6509fdc5892617751b97f700353ba9"
	if !reporterPromptHashNeedsTemplateUpgrade(previousV25Hash) {
		t.Fatal("previous v25 stock prompt would prevent supported behavior-based remediation proposals")
	}
	const previousV26Hash = "b444692a343f054ea0685828b3c1df90e3735d279972786fa87c053134a6502e"
	if !reporterPromptHashNeedsTemplateUpgrade(previousV26Hash) {
		t.Fatal("previous v26 stock prompt would permit synthetic-leak claims and multiple remediation alternatives")
	}
	const previousV27Hash = "26491cebbf5006c3a8d28bf29943b84bd395e3f3d55f60cffae114716be78867"
	if !reporterPromptHashNeedsTemplateUpgrade(previousV27Hash) {
		t.Fatal("previous v27 stock prompt would permit fabricated HTTP packets and conditional code fixes")
	}
	const previousV28Hash = "c9a7020f8405687afaaca33e30f5ed968ba68b9b2fa69b340685b85ead2e467b"
	if !reporterPromptHashNeedsTemplateUpgrade(previousV28Hash) {
		t.Fatal("previous v28 stock prompt would permit alternative fixes and omitted repeated requests")
	}
	const previousV29Hash = "16cc0718092b4ab57a5fd320ea70ef746da25d214e2e9ba048e13bcffca7266e"
	if !reporterPromptHashNeedsTemplateUpgrade(previousV29Hash) {
		t.Fatal("previous v29 stock prompt would permit multiple fix suggestions")
	}
	const previousV30Hash = "6922a24c94dcc6b2e4b1021163107aea7d3d87480fff40a79bee27a5211b5afd"
	if !reporterPromptHashNeedsTemplateUpgrade(previousV30Hash) {
		t.Fatal("previous v30 stock prompt would permit unsupported synthetic confidentiality claims")
	}
	const previousV31Hash = "1f5f062a02161d370dbfa89f260b2d1318941747ebc3d320a376bae4256ac086"
	if !reporterPromptHashNeedsTemplateUpgrade(previousV31Hash) {
		t.Fatal("previous v31 stock prompt would permit missing Burp packets and alternative fixes")
	}
	const previousV32Hash = "b5aa7ef16999d95655823f686c42d1eeec2e8782b0f3364209cb98fffe27e716"
	if !reporterPromptHashNeedsTemplateUpgrade(previousV32Hash) {
		t.Fatal("previous v32 stock prompt would permit synthetic confidentiality impact claims")
	}
	const previousV33Hash = "cbb9cdfde209d33d5aee3a52581d3dbb7612b4fc0be99c0dc4076acbb10e0c52"
	if !reporterPromptHashNeedsTemplateUpgrade(previousV33Hash) {
		t.Fatal("previous v33 stock prompt would omit synthetic scope and permit duplicated Burp prose")
	}
	const previousV34Hash = "487018396adc75c029f8864b55ca8d17a6b612376ea75eace5dd88a31ae15016"
	if !reporterPromptHashNeedsTemplateUpgrade(previousV34Hash) {
		t.Fatal("previous v34 stock prompt would permit a disconnected attack-chain group")
	}
	const previousV35Hash = "9d700f4f89005e55b28d163ce5eda116b5a0c81eb5d64c3563997a02ede09ae4"
	if !reporterPromptHashNeedsTemplateUpgrade(previousV35Hash) {
		t.Fatal("previous v35 stock prompt would describe synthetic files as sensitive assets")
	}
	const previousV36Hash = "b283bbd9f8f2a3ff6c94711491b0c20ca84391ee1610cab43f749e09e6b4949b"
	if !reporterPromptHashNeedsTemplateUpgrade(previousV36Hash) {
		t.Fatal("previous v36 stock prompt would retain the old delivery report structure")
	}
	if reporterPromptNeedsTemplateUpgrade(agent.ReporterDefaultPrompt) {
		t.Fatal("current stock prompt should not be migrated")
	}
	if reporterPromptNeedsTemplateUpgrade(agent.ReporterDefaultPrompt + "\n用户自定义要求。") {
		t.Fatal("an edited v23 prompt must not be migrated over")
	}
	if reporterPromptNeedsTemplateUpgrade("previous v19 stock prompt\n用户自定义要求。") {
		t.Fatal("an edited v19 prompt must not be migrated over")
	}
	previous, err := os.ReadFile("testdata/reporter-default-v3.txt")
	if err != nil {
		t.Fatal(err)
	}
	if !reporterPromptNeedsTemplateUpgrade(string(previous)) {
		t.Fatal("previous stock default would not receive the fixed template")
	}
	attackChainOnly := strings.Replace(string(previous), "- 请求与响应证据：", "- 攻击链路：交付报告必须单独使用 Markdown 二级标题“攻击链路”，说明从利用前提到已证实影响的实际过程，按发生顺序写出每一步的请求或操作、系统响应及对应证据。只连接证据支持的步骤；未验证或缺失的环节明确标出，不用箭头缩写，也不把推测写成事实。\n- 请求与响应证据：", 1)
	if !reporterPromptNeedsTemplateUpgrade(attackChainOnly) {
		t.Fatal("attack-chain-only stock default would not receive the fixed template")
	}
	latestPrevious, err := os.ReadFile("testdata/reporter-default-v4.txt")
	if err != nil {
		t.Fatal(err)
	}
	if !reporterPromptNeedsTemplateUpgrade(string(latestPrevious)) {
		t.Fatal("previous stock tree-template default would not receive the concise delivery rules")
	}
	previousV9, err := os.ReadFile("testdata/reporter-default-v9.txt")
	if err != nil {
		t.Fatal(err)
	}
	if !reporterPromptNeedsTemplateUpgrade(string(previousV9)) {
		t.Fatal("previous v9 stock default would not receive the simplified writing rules")
	}
	previousV10, err := os.ReadFile("testdata/reporter-default-v10.txt")
	if err != nil {
		t.Fatal(err)
	}
	if !reporterPromptNeedsTemplateUpgrade(string(previousV10)) {
		t.Fatal("previous v10 stock default would not receive the stricter evidence boundaries")
	}
	previousV11, err := os.ReadFile("testdata/reporter-default-v11.txt")
	if err != nil {
		t.Fatal(err)
	}
	if !reporterPromptNeedsTemplateUpgrade(string(previousV11)) {
		t.Fatal("previous v11 stock default would not receive concise hard-case examples")
	}
	previousV13, err := os.ReadFile("testdata/reporter-default-v13.txt")
	if err != nil {
		t.Fatal(err)
	}
	if !reporterPromptNeedsTemplateUpgrade(string(previousV13)) {
		t.Fatal("previous v13 stock default would not receive the current evidence rules")
	}
	previousV14, err := os.ReadFile("testdata/reporter-default-v14.txt")
	if err != nil {
		t.Fatal(err)
	}
	if !reporterPromptNeedsTemplateUpgrade(string(previousV14)) {
		t.Fatal("previous v14 stock default would not receive the current concise rules")
	}
	for _, customized := range []string{string(previous) + "\n用户自定义要求。", string(latestPrevious) + "\n用户自定义要求。", string(previousV9) + "\n用户自定义要求。", string(previousV10) + "\n用户自定义要求。", string(previousV11) + "\n用户自定义要求。", string(previousV13) + "\n用户自定义要求。", string(previousV14) + "\n用户自定义要求。", "自定义报告模板", agent.ReporterDefaultPrompt} {
		if reporterPromptNeedsTemplateUpgrade(customized) {
			t.Fatal("custom or already current prompt would be replaced")
		}
	}
}

func TestReporterTriggerUpgradeRecognizesDefaultsAndPreservesEdits(t *testing.T) {
	for _, previous := range []string{reporterToolCallMessageV1, reporterToolCallMessageV2, reporterToolCallMessageV2Legacy, reporterToolCallMessageV3, reporterToolCallMessageV4, reporterToolCallMessageV5, reporterToolCallMessageV6, reporterToolCallMessageV7, reporterToolCallMessageV8, reporterToolCallMessageV9, reporterToolCallMessageV10} {
		if !reporterTriggerMessageNeedsUpgrade(previous) {
			t.Fatal("previous stock trigger would retain superseded delivery instructions")
		}
	}
	for _, preserved := range []string{reporterToolCallMessage, reporterToolCallMessageV10 + "\n用户自定义要求。", "自定义触发内容"} {
		if reporterTriggerMessageNeedsUpgrade(preserved) {
			t.Fatal("custom or already current trigger would be replaced")
		}
	}
}

func TestReporterToolDescriptionUpgradeRecognizesPreviousVersions(t *testing.T) {
	previous := previousFindingReportToolDescriptions()
	if len(previous) != 11 {
		t.Fatalf("expected eleven historical tool descriptions, got %d", len(previous))
	}
	for _, description := range previous {
		if !reporterToolDescriptionNeedsTemplateUpgrade(description) {
			t.Fatal("previous stock tool description would retain superseded delivery instructions")
		}
	}
	for _, preserved := range []string{findingReportToolDescription, findingReportToolDescription + " 用户自定义要求。", "自定义工具说明"} {
		if reporterToolDescriptionNeedsTemplateUpgrade(preserved) {
			t.Fatal("current or customized tool description would be replaced")
		}
	}
}
