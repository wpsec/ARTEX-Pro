import { formatDeveloperDeliveryReport, formatRecordedFindingReport } from "./delivery-report";
import assert from "node:assert/strict";
import test from "node:test";

const cvssVector = "CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N";

test("registered findings without a saved report retain the delivery report template", () => {
  const report = formatRecordedFindingReport("297", {
    id: "297",
    name: "file_upload",
    vulnclass: "文件上传",
    severity: "critical",
    status: "pending",
    summary: "上传模块接受了伪装为图片的 PHP 文件。",
    evidence: "",
    traffic_count: 6,
    evidence_check_status: "not_assessed",
    ts: "2026-11-27T00:00:00Z",
  }).markdown;

  assert.match(report, /^## #297 · file\\_upload$/m);
  assert.match(report, /CVSS 4\.0：待评估/);
  assert.match(report, /向量：待评估/);
  assert.deepEqual(report.match(/^#{3,4} .+$/gm), [
    "### 漏洞描述",
    "### 测试过程",
    "#### Burp 复现包",
    "#### 攻击链路",
    "#### 复现脚本",
    "### 修复建议",
  ]);
  assert.match(report, /已确认影响：登记摘要未单独记录已确认的业务影响，待核实。/);
  assert.match(report, /#### Burp 复现包\n\n未附完整原始 HTTP 请求报文。/);
  assert.doesNotMatch(report, /已绑定 6 条 HTTP 流量/);
  assert.match(report, /\*\*修复后验证\*\*/);
});

test("legacy reports present the selected title, scored CVSS and the agreed development layout", () => {
  const stored = [
    "# 旧标题",
    "- **CVSS 4.0 评分**：1.0（低危）",
    "## 描述",
    "记录查询的权限校验不完整。",
    "### 定级依据",
    "证据：不应出现在交付稿的内部记录。",
    "## 修复建议",
    "服务端查询前校验当前用户的访问权限。",
    "## 测试过程",
    "### 发现过程与攻击思路",
    "普通账号仍可读取不属于自己的示例记录。首轮上传腿（seq 5–11）。",
    "### Burp 复现",
    "~~~http",
    "GET /fixture HTTP/1.1",
    "Host: example.invalid",
    "~~~",
    "## 攻击链路",
    "~~~text",
    "内部记录",
    "└─ GET /fixture",
    "   └─ 结果：测试发现记录可被其他账号查看。",
    "~~~",
    "## 证据说明",
    "此处为内部台账。",
    "<!-- artex:bound-traffic-evidence -->",
    "## 修复建议",
    "这行来自附件。",
  ].join("\n");

  const report = formatDeveloperDeliveryReport(stored, { name: "记录查询权限校验缺失", cvssVector, findingId: "42" });
  assert.match(report, /^# 记录查询权限校验缺失/);
  assert.match(report, /CVSS 4\.0：7\.3（高危）/);
  assert.ok(report.includes(cvssVector));
  assert.deepEqual(report.match(/^#{1,3} .+$/gm), [
    "# 记录查询权限校验缺失",
    "## 漏洞描述",
    "## 测试过程",
    "### Burp 复现包",
    "### 攻击链路",
    "### 复现脚本（Python）",
    "## 修复建议",
  ]);
  assert.match(report, /仍可读取不属于自己的示例记录/);
  assert.match(report, /记录可被其他账号查看/);
  assert.match(report, /漏洞 #42/);
  assert.match(report, /查询前校验当前用户的访问权限/);
  assert.doesNotMatch(report, /1\.0|旧标题|证据|上传腿|seq|GET|Host:|来自附件|内部记录/);
});

test("plain language keeps the meaningful observation without internal measurements and test labels", () => {
  const report = formatDeveloperDeliveryReport(
    [
      "# 记录展示异常",
      "## 漏洞描述",
      "测试时发现两次返回的内容逐字节相同。响应长度是 87 字节。被读业务文件的具体属主为 synthetic-user。",
      "## 测试过程",
      "判据拒绝不可见对象。独立对照已完成。测试发现没有权限时仍会显示该记录。",
      "## 修复建议",
      "将记录访问权限校验移到服务端。",
    ].join("\n"),
  );

  assert.match(report, /两次返回的内容相同/);
  assert.match(report, /没有权限时仍会显示该记录/);
  assert.match(report, /将记录访问权限校验移到服务端/);
  assert.doesNotMatch(report, /87|字节|属主|synthetic-user|判据|对照/);
});

test("keeps observations written using the server's normalized phrasing", () => {
  const report = formatDeveloperDeliveryReport(
    ["# 目录展示异常", "## 测试过程", "测试记录显示，列表里出现了其他部门的示例记录。"].join("\n"),
  );

  assert.match(report, /## 测试过程\n\n测试记录显示，列表里出现了其他部门的示例记录。/);
});

test("keeps business findings and outcomes written alongside inline endpoint references", () => {
  const report = formatDeveloperDeliveryReport(
    [
      "# 文档预览权限校验缺失",
      "## 描述",
      "在文档预览的运行会话中，`GET /fixture/preview` 会向未登录用户显示其他部门的目录名称。",
      "## 测试过程",
      "预期未登录时不显示目录名称。",
      "实际结果：在 `/fixture/preview` 的响应中看到了该目录名称。",
      "对照：已登录用户仍可看到自己的目录名称。",
      "向 `GET /fixture/preview` 发送请求获取目录。",
      "在终端运行工具检查列表。",
      "Authorization: Bearer synthetic-placeholder",
    ].join("\n"),
  );

  assert.match(report, /## 漏洞描述\n\n在文档预览的运行会话中，相关接口会向未登录用户显示其他部门的目录名称。/);
  assert.match(
    report,
    /## 测试过程\n\n预期未登录时不显示目录名称。在相关路径的响应中看到了该目录名称。已登录用户仍可看到自己的目录名称。/,
  );
  assert.doesNotMatch(report, /GET|\/fixture|发送请求|运行工具|对照|Authorization|synthetic-placeholder/);
});

test("places a documented browser entry and ordinary action after the finding description", () => {
  const source = [
    "# 文档预览显示异常",
    "## 描述",
    "文档预览的目录显示范围超出预期。",
    "- 触发位置：文档中心 → 预览页，日常操作是打开本人文档的预览。",
    "## 测试过程",
    "测试发现目录显示范围超出预期。",
  ].join("\n");
  const findingLocation =
    /## 漏洞描述\n\n文档预览的目录显示范围超出预期。\n\n触发位置：文档中心 → 预览页，日常操作是打开本人文档的预览。\n\n## 测试过程/;
  const report = formatDeveloperDeliveryReport(source);
  assert.match(report, findingLocation);
  assert.match(formatDeveloperDeliveryReport(report), findingLocation);
  assert.match(formatDeveloperDeliveryReport(source.replace("- 触发位置：", "**触发位置：** ")), findingLocation);
});

test("preserves an API-only observation and does not infer a hidden interface from HTTP records", () => {
  const source = [
    "# 预览范围异常",
    "## 描述",
    "预览服务会返回额外的目录名称。",
    "触发位置：仅通过文档预览服务的目录查询接口验证，浏览器入口待核实。",
    "## 复现记录",
    "~~~http",
    "触发位置：预览设置页。",
    "~~~",
  ].join("\n");
  const report = formatDeveloperDeliveryReport(source);
  assert.match(report, /触发位置：仅通过文档预览服务的目录查询接口验证，浏览器入口待核实。/);
  assert.doesNotMatch(report, /隐藏接口|预览设置页/);

  const legacy = source.replace(/^触发位置：仅通过[^\n]+\n/m, "");
  assert.match(formatDeveloperDeliveryReport(legacy), /触发位置：页面入口或接口归属待核实。/);
  const requestOnly = legacy.replace("## 描述\n", "## 描述\n触发位置：先发送 `GET /fixture`。\n");
  assert.match(formatDeveloperDeliveryReport(requestOnly), /触发位置：页面入口或接口归属待核实。/);
  assert.doesNotMatch(formatDeveloperDeliveryReport(requestOnly), /发送|\/fixture/);
});

test("keeps expectations, actual results and limits together when no attack chain is recorded", () => {
  const report = formatDeveloperDeliveryReport(
    [
      "# 目录展示异常",
      "## 测试过程",
      "预期只显示当前部门的记录。",
      "实际结果：请求已被拒绝。",
      "其他部门的文件内容未验证。",
      "请求其他部门的记录。",
    ].join("\n"),
  );

  assert.match(report, /## 测试过程\n\n预期只显示当前部门的记录。请求已被拒绝。其他部门的文件内容未验证。/);
  assert.match(report, /### 攻击链路\n\n已观察到的影响见漏洞描述和测试过程。/);
  assert.doesNotMatch(report, /请求其他部门的记录/);
});

test("renders the authored test facts and keeps an unverified impact distinct from observed results", () => {
  const source = [
    "# 目录展示异常",
    "## 测试过程",
    "测试时间：未记录",
    "<!-- artex:developer-test-facts-v1 -->",
    "**测试角色：** 部门成员。",
    "预期行为：仅显示本部门的目录名称。",
    "实际结果：列表中出现其他部门的目录名称。",
    "未验证范围：现有记录无法确认响应包含用户列表。",
    "复核状态归入蓝组记录，内部版本为金色标签。",
    "仍可看到本项归并批次的处理结果。",
  ].join("\n");

  const report = formatDeveloperDeliveryReport(source);
  assert.match(
    report,
    /## 测试过程\n\n- 测试角色：部门成员。\n- 预期行为：仅显示本部门的目录名称。\n- 实际结果：列表中出现其他部门的目录名称。\n- 未验证范围：现有记录无法确认响应包含用户列表。/,
  );
  assert.doesNotMatch(report, /蓝组|金色标签|归并批次|developer-test-facts/);
  const missingResult = formatDeveloperDeliveryReport(source.replace(/^实际结果：[^\n]+\n/m, ""));
  assert.match(missingResult, /- 实际结果：待核实。/);
  assert.doesNotMatch(missingResult, /归并批次/);
  assert.match(
    formatDeveloperDeliveryReport(source.replace(/^<!-- artex:developer-test-facts-v1 -->\n/m, "")),
    /归并批次/,
  );
});

test("keeps structured test expectations and repair acceptance phrases", () => {
  const report = formatDeveloperDeliveryReport(
    [
      "# 订单列表展示异常",
      "## 测试过程",
      "<!-- artex:developer-test-facts-v1 -->",
      "测试角色：普通用户。",
      "预期行为：请求应被拒绝。",
      "实际结果：请求返回了其他账号的订单。",
      "未验证范围：仅确认了列表。",
      "  单条订单详情尚未核实。",
      "## 修复建议",
      "<!-- artex:developer-report-fields-v1 -->",
      "修复措施：检查订单所属账号。",
      "修复后验收：拒绝无权限的读取。",
      "  有权限的读取应继续成功。",
    ].join("\n"),
  );

  assert.match(report, /预期行为：请求应被拒绝。/);
  assert.match(report, /实际结果：请求返回了其他账号的订单。/);
  assert.match(report, /未验证范围：仅确认了列表。单条订单详情尚未核实。/);
  assert.match(report, /\*\*修复后验证\*\*\s+- 拒绝无权限的读取。\n- 有权限的读取应继续成功。/);
});

test("keeps public description and repair fields without copying adjacent ledger prose", () => {
  const marker = "<!-- artex:developer-report-fields-v1 -->";
  const report = formatDeveloperDeliveryReport(
    [
      "# 目录展示异常",
      "## 描述",
      marker,
      "漏洞现象：部门成员在预览里看到了其他部门的目录。",
      "已确认影响：其他部门的目录名称可见。",
      "触发位置：文档预览页。",
      "  从文档列表打开预览。",
      "测试范围：离线合成场景，未测试真实目标。",
      "内部版本为金色标签，复核归档已关闭。",
      "## 修复建议",
      marker,
      "修复措施：服务端应按部门权限限制可见的目录。",
      "修复后验收：有权限的用户应正常看到目录。",
      "修复后验收：无权限的用户应被拒绝。",
      "内部版本为金色标签，修复复核已安排。",
    ].join("\n"),
  );
  assert.match(report, /## 漏洞描述\n\n部门成员在预览里看到了其他部门的目录。/);
  assert.match(report, /已确认影响：其他部门的目录名称可见。/);
  assert.match(report, /触发位置：文档预览页。从文档列表打开预览。/);
  assert.match(report, /测试范围：离线合成场景，未测试真实目标。/);
  assert.match(report, /## 修复建议\n\n服务端应按部门权限限制可见的目录。/);
  assert.match(report, /- 有权限的用户应正常看到目录。\n- 无权限的用户应被拒绝。/);
  assert.doesNotMatch(report, /金色标签|developer-report-fields/);
});

test("new nested sections keep impact and mark missing scores as pending", () => {
  const report = formatDeveloperDeliveryReport(
    [
      "# 文件预览范围过宽",
      "## 漏洞描述",
      "文件预览包含其他部门的示例目录。",
      "## 测试过程",
      "测试发现预览范围超出该部门。",
      "### 复现记录",
      "Burp 不适用。",
      "### 影响链路",
      "低权限账号仍可查看其他部门的目录记录。",
      "## 修复建议",
      "在服务端按部门限制可预览的目录。",
      "<!-- artex:bound-traffic-evidence -->",
      "### 平台 HTTP 流量证据",
      "",
      "该漏洞未绑定 ARTEX HTTP 流量。",
    ].join("\n"),
    { cvssVector: "not-a-vector" },
  );

  assert.match(report, /CVSS 4\.0：待评估/);
  assert.match(report, /本次为非 HTTP 测试/);
  assert.match(report, /低权限账号仍可查看其他部门的目录记录/);
  assert.doesNotMatch(report, /not-a-vector|评分 0\.0/);
  assert.equal(formatDeveloperDeliveryReport("  "), "");
});

test("appendices and actionable fragments never appear in the delivered Markdown", () => {
  const report = formatDeveloperDeliveryReport(
    [
      "# 回退展示",
      "## 漏洞描述",
      "请求 Host: service.example.invalid",
      "Authorization: Bearer synthetic-placeholder",
      "## 测试过程",
      "先执行 curl http://example.invalid。",
      "Token: synthetic-placeholder",
      "## 修复建议",
      "```http",
      "## 漏洞描述",
      "替换标题的附件文本。",
      "```",
      "\\<!-- artex:bound-traffic-evidence -->\\",
      "## 影响链路",
      "仍可访问附件中的测试内容。",
    ].join("\n"),
    { name: "GET /fixture", findingId: "[unsafe](https://example.invalid)" },
  );
  assert.match(report, /^# 回退展示/);
  assert.doesNotMatch(report, /Host:|GET|Authorization|Token|Bearer|synthetic|curl|example\.invalid|artex:|附件/);
  assert.match(report, /修复建议待补充/);
});

test("legacy prose retains complete observations beside tool records and generalizes internal paths in fixes", () => {
  const report = formatDeveloperDeliveryReport(
    [
      "# 文件预览异常",
      "## 描述",
      "请求行 GET /fixture。普通用户可以看到其他部门的预览内容。",
      "## 测试过程",
      "测试发现返回了其他部门的预览内容。更深层目录未验证。",
      "## 修复建议",
      "为 `GET /fixture` 增加部门范围校验。",
    ].join("\n"),
  );
  assert.match(report, /## 漏洞描述\n\n普通用户可以看到其他部门的预览内容/);
  assert.match(report, /## 测试过程\n\n更深层目录未验证/);
  assert.match(report, /### 攻击链路\n\n- 测试发现返回了其他部门的预览内容/);
  assert.match(report, /为相关接口增加部门范围校验/);
  assert.doesNotMatch(report, /GET|\/fixture|待补充|待整理/);
});

test("retains permission conditions and unverified outcomes from older report subsections", () => {
  const report = formatDeveloperDeliveryReport(
    [
      "# 文档查看范围异常",
      "## 描述",
      "已登录用户可以看到其他部门的目录名称。",
      "### 定级依据",
      "PR:L，测试只覆盖普通用户。管理员权限未验证。",
      "## 测试过程",
      "### 失败尝试与未验证项",
      "没有取得文件内容。仅证明目录名称可见。测试记录不足以确认数据已经读取。",
      "## 攻击链路",
      "~~~text",
      "查看目录",
      "└─ 结果：目录名称可见",
      "~~~",
      "## 修复建议",
      "服务端按部门限制目录列表。",
    ].join("\n"),
  );
  assert.match(report, /测试只覆盖普通用户。管理员权限未验证/);
  assert.match(report, /没有取得文件内容。仅证明目录名称可见。测试记录不足以确认数据已经读取/);
  assert.match(report, /### 攻击链路\n\n- 目录名称可见/);
  assert.doesNotMatch(report, /定级依据|PR:L|失败尝试与未验证项/);
});

test("distinguishes a legacy HTTP example from captured test records", () => {
  const content = "# 合成案例\n## Burp 复现\n~~~http\nGET /fixture HTTP/1.1\n~~~";
  const appendix = `${content}\n<!-- artex:bound-traffic-evidence -->\n`;
  assert.match(formatDeveloperDeliveryReport(content), /核对实际执行情况/);
  assert.match(formatDeveloperDeliveryReport(appendix), /核对实际执行情况/);
  assert.match(
    formatDeveloperDeliveryReport(`${appendix}### 平台 HTTP 流量证据\n\n该漏洞未绑定 ARTEX HTTP 流量。`),
    /核对实际执行情况/,
  );
  assert.match(
    formatDeveloperDeliveryReport(
      `${appendix}### 平台留存的 HTTP 请求与响应\n\n以下内容取自绑定记录。\n\n#### 证据绑定 1`,
      { findingId: "42", burpPackageAvailable: true },
    ),
    /未附完整原始 HTTP 请求报文/,
  );
  assert.doesNotMatch(formatDeveloperDeliveryReport(content), /GET|\/fixture/);
});

test("shows verification and evidence versions when a bound request cannot be rendered", () => {
  const options = {
    findingId: "42",
    burpPackageAvailable: true,
    reportEvidenceVersion: 0,
    currentEvidenceVersion: 3,
  };
  const report = formatDeveloperDeliveryReport("# 记录展示异常\n## Burp 复现\n未在 Burp 中验证。", options);
  assert.match(report, /Burp 验证状态：未在 Burp 中验证。/);
  assert.match(report, /报告证据版本：0。页面加载时的附件证据版本：3。版本不一致/);
  assert.match(report, /未附完整原始 HTTP 请求报文/);
  assert.doesNotMatch(report, /下载 Burp 复测包/);

  const matching = formatDeveloperDeliveryReport(
    "# 记录展示异常\n## Burp 复现\n本次已在 Burp Suite Repeater 中验证。",
    { ...options, reportEvidenceVersion: 3 },
  );
  assert.match(matching, /Burp 验证状态：已在 Burp 中验证。/);
  assert.doesNotMatch(matching, /版本不一致/);
});

test("retains repository source locations in fixes without retaining HTTP requests or runtime paths", () => {
  const report = formatDeveloperDeliveryReport(
    [
      "# 记录权限校验缺失",
      "## 修复建议",
      "在 `src/server/records.test.ts:42` 对列表结果增加部门权限校验。",
      "检查 `internal/records/access.go:73:9` 是否使用相同的权限条件。",
      "为 `GET /fixture` 增加对象权限校验。",
      "重新核对 `/var/tmp/sample.txt` 的访问范围。",
      "测试配置从 `.env:14` 读取。",
      "另有定位引用 `../external/fixture.go:8`。",
    ].join("\n"),
  );
  assert.match(report, /src\/server\/records\.test\.ts:42/);
  assert.match(report, /internal\/records\/access\.go:73:9/);
  assert.match(report, /相关接口增加对象权限校验/);
  assert.match(report, /相关路径的访问范围/);
  assert.doesNotMatch(report, /GET|\/fixture|\/var\/tmp|\.env|\.\.\/external/);
});

test("presents confirmed business stages from an existing chain as separate items", () => {
  const report = formatDeveloperDeliveryReport(
    [
      "# 文档展示范围异常",
      "## 攻击链路",
      "~~~text",
      "入口：文档中心的预览功能。",
      "├── GET /fixture HTTP/1.1",
      "│   └── 校验缺口：预览服务未校验目录可见范围。",
      "└── 实际影响：普通账号看到其他部门的目录。",
      "    └── 200 返回了 530B 的归档包。",
      "~~~",
      "## 修复建议",
      "服务端应按部门权限限制目录预览。",
    ].join("\n"),
  );

  assert.match(report, /- 入口：文档中心的预览功能。\n- 校验缺口：预览服务未校验目录可见范围。/);
  assert.match(report, /- 实际影响：普通账号看到其他部门的目录。\n- 返回了归档包。/);
  assert.doesNotMatch(report, /GET|\/fixture|HTTP\/1|200|530B/);
});

test("marks missing remediation and keeps the expected repair outcome without the replay wording", () => {
  const report = formatDeveloperDeliveryReport(
    [
      "# 文档展示范围异常",
      "## 修复建议",
      "源码位置与现有实现尚未核实。",
      "### 修复后验证",
      "修复后用同一会话重放上述两个请求，应拒绝未授权访问。",
    ].join("\n"),
  );
  assert.match(report, /## 修复建议\n\n修复建议待补充/);
  assert.match(report, /- 修复后应拒绝未授权访问。/);
  assert.doesNotMatch(report, /源码位置|重放/);
});

test("keeps previously written repair expectations under remediation without raw reproduction material", () => {
  const content = [
    "# 记录权限校验缺失",
    "## 修复建议",
    "服务端按用户权限返回可访问的记录。",
    "## 证据说明",
    "### 复测标准",
    "有访问权限的用户应继续正常读取记录。",
    "没有访问权限的用户应被拒绝，响应不得包含记录内容。",
    "匿名请求不应返回 80 字节的业务文件内容，响应不得显示文件的具体属主为 `synthetic_user`。",
    "无权限时应返回 `0` 字节。",
    "修复后系统应拒绝访问，不再返回原响应中的 `recorded-fixture` 对应字节。",
    "发送示例请求并查看响应。",
    "<!-- artex:bound-traffic-evidence -->",
    "### 复测标准",
    "响应不应出现附件里的这句话。",
  ].join("\n");
  const report = formatDeveloperDeliveryReport(content);
  assert.match(report, /### 复现脚本（Python）\n\n本报告未附 Python 脚本。复测预期见「修复后验证」。/);
  assert.match(
    report,
    /## 修复建议\n\n服务端按用户权限返回可访问的记录。\n\n\*\*修复后验证\*\*\n\n- 有访问权限的用户应继续正常读取记录。\n- 没有访问权限的用户应被拒绝，响应不得包含记录内容。/,
  );
  assert.doesNotMatch(report, /示例请求|附件里的/);
  assert.match(report, /匿名请求不应返回先前记录中的业务文件内容，响应不得显示文件所有者信息/);
  assert.match(report, /无权限时应返回空内容/);
  assert.match(report, /修复后系统应拒绝访问，不再返回先前记录中的内容/);
  assert.doesNotMatch(report, /80|字节|属主|synthetic_user|recorded-fixture/);
  assert.doesNotMatch(formatDeveloperDeliveryReport("## 修复建议\n服务端按用户权限返回记录。"), /修复后验证/);
});

test("keeps the repair verification section when the source uses the delivery label", () => {
  const verification = /\*\*修复后验证\*\*\n\n- 有权限的用户应继续看到记录。\n- 无权限访问应返回空内容。/;
  for (const heading of ["### 修复后验证", "**修复后验证**"]) {
    const source = [
      "# 记录展示异常",
      "## 修复建议",
      "在服务端查询时按用户所属部门过滤。",
      heading,
      "- 有权限的用户应继续看到记录。",
      "- 无权限访问应返回 0 字节。",
    ].join("\n");

    const report = formatDeveloperDeliveryReport(source);
    assert.match(report, verification);
    assert.match(formatDeveloperDeliveryReport(report), verification);
  }
});

test("prints the Python attachment status without copying executable blocks from older reports", () => {
  const report = formatDeveloperDeliveryReport(
    [
      "# 记录访问异常",
      "## 测试过程",
      "观察到受限记录出现在列表里。",
      "### POC 脚本（Python）",
      "~~~python",
      'print("fixture-script-marker")',
      "~~~",
      "## 修复建议",
      "读取时按部门校验。",
    ].join("\n"),
  );
  assert.match(report, /### 复现脚本（Python）\n\n本报告未附 Python 脚本。/);
  assert.doesNotMatch(report, /fixture-script-marker/);
});

test("keeps the recorded Python regression test reference and expected result", () => {
  const report = formatDeveloperDeliveryReport(
    [
      "# 记录展示异常",
      "## 测试过程",
      "### 复现脚本（Python）",
      "用例位置：`tests/test_access.py:14`",
      "预期结果：拒绝无权限的读取。",
      "~~~python",
      'print("fixture-script-marker")',
      "~~~",
    ].join("\n"),
  );

  for (const text of [report, formatDeveloperDeliveryReport(report)]) {
    assert.match(text, /用例位置：`tests\/test_access\.py:14`/);
    assert.match(text, /预期结果：拒绝无权限的读取。/);
    assert.doesNotMatch(text, /fixture-script-marker/);
  }
});

test("renders the bound supporting request and builds its Python replay script", () => {
  const report = formatDeveloperDeliveryReport(
    [
      "# 记录访问异常",
      "## 漏洞描述",
      "列表返回了其他账号的记录。",
      "## 测试过程",
      "测试角色：普通账号。",
      "## 攻击链路",
      "已观察到记录越权。",
      "## 修复建议",
      "服务端查询前校验记录归属。",
      "<!-- artex:bound-traffic-evidence -->",
      "### 平台留存的 HTTP 请求与响应",
      "#### 证据绑定 23（辅助证据）",
      "- 请求地址：https://audit.example.test/api/records?id=other",
      "##### 请求包",
      "```http",
      "POST /api/records?id=other HTTP/1.1",
      "Host: audit.example.test",
      "Authorization: Bearer captured-fixture-token",
      "Content-Type: application/json",
      "Content-Length: 13",
      "",
      '{"id":"other"}',
      "```",
      "##### 响应包",
      "~~~http",
      "HTTP/1.1 200 OK",
      "~~~",
    ].join("\n"),
  );

  assert.match(report, /### 复现脚本（Python）/);
  assert.match(
    report,
    /### Burp 复现包[\s\S]*```http\nPOST \/api\/records\?id=other HTTP\/1\.1\nHost: audit\.example\.test\nAuthorization: Bearer captured-fixture-token/,
  );
  assert.match(report, /默认直连；设置 `BURP_PROXY=http:\/\/127\.0\.0\.1:8080` 后经 Burp 发送。/);
  assert.match(report, /TARGET_URL = "https:\/\/audit\.example\.test\/api\/records\?id=other"/);
  assert.match(report, /METHOD = "POST"/);
  assert.match(report, /"Authorization"[\s\S]*"Bearer captured-fixture-token"/);
  assert.match(report, /BURP_PROXY=http:\/\/127\.0\.0\.1:8080 python3 replay\.py/);
  assert.match(report, /connection\.set_tunnel\(target_host, target_port\)/);
  assert.doesNotMatch(report, /captured-fixture-token.*\*/);
});

test("does not generate an executable replay script from baseline-only or incomplete traffic", () => {
  const report = formatDeveloperDeliveryReport(
    [
      "# 记录访问异常",
      "## 测试过程",
      "普通账号无法读取其他账号的记录。",
      "<!-- artex:bound-traffic-evidence -->",
      "### 平台留存的 HTTP 请求与响应",
      "#### 证据绑定 22（测试基线）",
      "- 请求地址：https://audit.example.test/api/records",
      "##### 请求包",
      "~~~http",
      "GET /api/records HTTP/1.1",
      "Host: audit.example.test",
      "~~~",
    ].join("\n"),
  );

  assert.match(report, /本报告未附 Python 脚本。/);
  assert.doesNotMatch(report, /BURP_PROXY|TARGET_URL =/);
});

test("renders a replay request and script for a header-only supporting request", () => {
  const report = formatDeveloperDeliveryReport(
    [
      "# 记录访问异常",
      "## 测试过程",
      "普通账号读取到其他账号的记录。",
      "<!-- artex:bound-traffic-evidence -->",
      "### 平台留存的 HTTP 请求与响应",
      "#### 证据绑定 24（辅助证据）",
      "- 请求地址：https://audit.example.test/api/records/42",
      "##### 请求包",
      "```http",
      "GET /api/records/42 HTTP/1.1",
      "Host: audit.example.test",
      "",
      "",
      "```",
      "##### 响应包",
      "```http",
      "HTTP/1.1 200 OK",
      "",
      "",
      "```",
    ].join("\n"),
  );

  assert.match(report, /```http\nGET \/api\/records\/42 HTTP\/1\.1\nHost: audit\.example\.test/);
  assert.match(report, /TARGET_URL = "https:\/\/audit\.example\.test\/api\/records\/42"/);
  assert.match(report, /METHOD = "GET"/);
});
