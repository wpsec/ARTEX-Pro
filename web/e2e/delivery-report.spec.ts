import { expect, test } from "@playwright/test";

import { authCookieName } from "../src/lib/auth-cookie";
import { scoreCVSS4Base } from "../src/lib/cvss-v4";
import { randomUUID } from "node:crypto";

const officialVectors = [
  {
    vector: "CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    score: 7.3,
    severity: "高危",
  },
  {
    vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N",
    score: 5.1,
    severity: "中危",
  },
  {
    vector: "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    score: 8.5,
    severity: "高危",
  },
  {
    vector: "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    score: 8.2,
    severity: "高危",
  },
  {
    vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    score: 7.1,
    severity: "高危",
  },
  {
    vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    score: 9.3,
    severity: "严重",
  },
  {
    vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    score: 8.7,
    severity: "高危",
  },
];

test("CVSS-B score matches published FIRST CVSS v4.0 Base examples", () => {
  for (const example of officialVectors) {
    expect(scoreCVSS4Base(example.vector)).toMatchObject({ score: example.score, severity: example.severity });
  }
});

test("CVSS-B scoring follows FIRST's reference lookup for a conflicting example", () => {
  const vector = "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N";
  expect(scoreCVSS4Base(vector)).toMatchObject({ score: 9.2, severity: "严重" });
});

test("task report aggregates only this task's delivery reports across pages", async ({ context, page, baseURL }) => {
  if (!baseURL) throw new Error("Playwright baseURL is required");
  const token = randomUUID();
  await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  await context.addCookies([{ name: authCookieName(new URL(baseURL).port), value: token, url: baseURL }]);
  await context.addInitScript((value) => localStorage.setItem("artex_token", value), token);

  const task = { id: "73", name: "合成交付报告任务", description: "验收任务", status: "done", created_at: 1764115200 };
  const finding = (id: string, name: string, taskId = task.id) => ({
    id,
    finding_id: id,
    task_id: taskId,
    name,
    vulnclass: "权限校验",
    status: "confirmed",
    severity: "high",
    summary: "目录显示范围超出预期。",
  });
  const requestedPages = new Set<string>();
  const requestedReports = new Set<string>();
  let legacyRequested = false;
  let reportUnavailable = true;
  let allReportsSaved = false;
  await page.route("**/api/**", async (route) => {
    const url = new URL(route.request().url());
    const path = url.pathname;
    if (path === "/api/tasks/73") return route.fulfill({ json: task });
    if (path === "/api/report") {
      legacyRequested = true;
      return route.fulfill({ body: "旧任务原稿标记" });
    }
    if (path === "/api/exploration/findings" && url.searchParams.get("task_id") === task.id) {
      const pageNumber = url.searchParams.get("page") ?? "";
      requestedPages.add(pageNumber);
      const items =
        pageNumber === "1"
          ? [finding("1001", "文档预览范围异常"), finding("1002", "附件预览范围异常")]
          : [finding("1003", "目录展示 | 范围异常"), finding("1004", "其他任务记录", "74")];
      return route.fulfill({ json: { items, total: 4, page_size: 2 } });
    }
    const id = /^\/api\/tasks\/73\/findings\/(\d+)\/delivery-report$/.exec(path)?.[1];
    if (id) {
      requestedReports.add(id);
      if (id === "1002" && !allReportsSaved) {
        return route.fulfill({ json: { exists: false, content: "", has_detailed_report: false } });
      }
      if (id === "1003" && reportUnavailable) return route.fulfill({ status: 503, json: { error: "暂时不可用" } });
      return route.fulfill({
        json: {
          exists: true,
          has_detailed_report: id === "1001" || allReportsSaved,
          content: [
            "## 描述",
            "<!-- artex:developer-report-fields-v1 -->",
            "漏洞现象：目录显示范围超出预期。",
            "已确认影响：其他部门的目录名称可见。",
            "触发位置：文档中心 → 预览页，日常操作是打开文档预览。",
            "## 攻击链路",
            "入口：文档中心的预览功能。",
            "校验缺口：预览服务未校验目录可见范围。",
            "实际影响：普通账号看到其他部门的目录。",
            "## 测试过程",
            "测试时间：未记录",
            "<!-- artex:developer-test-facts-v1 -->",
            "测试角色：部门成员。",
            "预期行为：仅显示本部门的目录。",
            "实际结果：显示了其他部门的目录。",
            "未验证范围：现有记录无法确认响应包含用户列表。",
            "仍可查看这条内部台账的处理结果。",
            "## Burp 复现",
            "Burp 不适用：本次证据为本地运行记录。",
            "## 修复建议",
            "<!-- artex:developer-report-fields-v1 -->",
            "修复措施：查询目录时校验访问范围。",
            "修复后验收：无权限时应拒绝访问。",
          ].join("\n"),
          cvss_vector: id === "1001" || allReportsSaved ? officialVectors[0].vector : "",
          evidence_version: id === "1001" && !allReportsSaved ? 1 : 2,
          current_evidence_version: 2,
        },
      });
    }
    return route.fulfill({ json: {} });
  });

  await page.goto("/function/tasks/detail?id=73&tab=report");
  await expect(page.getByRole("heading", { name: "任务报告草稿", level: 2 })).toBeVisible();
  await expect(page.getByText("任务 #73 · 截止汇总 · 共纳入 3 项登记发现")).toBeVisible();
  await expect(page.getByText(/交付报告已保存 1 份，未保存 1 份，读取失败 1 份/)).toBeVisible();
  await expect(page.getByText(/详细报告已保存 1 份，未保存 1 份，状态未知 1 份/)).toBeVisible();
  await expect(page.getByText("交付报告未保存，以下为登记摘要。详细报告未保存。")).toBeVisible();
  await expect(page.getByText("交付报告读取失败，以下为登记摘要。")).toBeVisible();
  await expect(page.getByRole("link", { name: "查看详细报告" })).toHaveAttribute(
    "href",
    "/function/findings/detail?id=1001&context_task=73#detailed-report",
  );
  await expect(page.getByText(/测试记录有更新，交付前请核对报告/)).toBeVisible();
  await expect(page.getByText("未验证范围：现有记录无法确认响应包含用户列表。")).toBeVisible();
  await expect(page.getByText("已确认影响：其他部门的目录名称可见。")).toBeVisible();
  await expect(page.getByRole("heading", { name: "漏洞目录", level: 3 })).toBeVisible();
  const directory = page.getByRole("table");
  await expect(directory.getByRole("columnheader")).toHaveText(["编号", "漏洞名称", "漏洞等级"]);
  await expect(directory.getByRole("row")).toHaveCount(4);
  await expect(directory.getByRole("row", { name: /#1001/ }).getByRole("cell")).toHaveText([
    "#1001",
    "文档预览范围异常",
    "高危",
  ]);

  reportUnavailable = false;
  await page.getByRole("button", { name: "刷新报告" }).click();
  await expect(page.getByText(/交付报告已保存 2 份，未保存 1 份。详细报告已保存 1 份，未保存 2 份。/)).toBeVisible();
  await expect(directory.getByRole("row")).toHaveCount(4);
  const secondRow = directory.getByRole("row", { name: /#1003/ });
  await expect(secondRow.getByRole("cell")).toHaveText(["#1003", "目录展示 | 范围异常", "待评估"]);
  await secondRow.getByRole("link", { name: "目录展示 | 范围异常" }).click();
  await expect(page).toHaveURL(/#finding-1003$/);
  await expect(page.getByRole("heading", { name: "#1003 · 目录展示 | 范围异常", level: 3 })).toBeInViewport();
  await expect(page.getByText(/交付报告加载失败/)).toHaveCount(0);
  await expect(page.getByRole("button", { name: "复制交付报告", exact: true })).toHaveCount(0);
  await page.getByRole("button", { name: "复制报告草稿", exact: true }).click();
  const copied = await page.evaluate(() => navigator.clipboard.readText());
  expect(copied).toMatch(/^# 任务报告草稿\n/);
  expect(copied).toContain("## 漏洞目录");
  expect(copied).toContain("| #1001 | 文档预览范围异常 | 高危 |");
  expect(copied).toContain("| #1003 | 目录展示 \\| 范围异常 | 待评估 |");
  expect(copied).toContain("## #1001 · 文档预览范围异常");
  expect(copied).toContain("## #1002 · 附件预览范围异常");
  expect(copied).toContain("交付报告未保存，以下为登记摘要。详细报告未保存。");
  expect(copied).not.toContain("交付报告读取失败");
  expect(copied).toContain("## #1003 · 目录展示 \\| 范围异常");
  expect(copied).toContain("### 漏洞描述");
  expect(copied).toContain("触发位置：文档中心 → 预览页");
  expect(copied).toContain("- 校验缺口：预览服务未校验目录可见范围。");
  expect(copied).toContain("- 未验证范围：现有记录无法确认响应包含用户列表。");
  expect(copied).toContain("- 无权限时应拒绝访问。");
  expect(copied).toContain("测试记录有更新");
  expect(copied).not.toMatch(/旧任务原稿标记|其他任务记录|内部台账的处理结果/);
  expect([...requestedPages].sort()).toEqual(["1", "2"]);
  expect([...requestedReports].sort()).toEqual(["1001", "1002", "1003"]);
  expect(legacyRequested).toBe(false);

  allReportsSaved = true;
  await page.getByRole("button", { name: "刷新报告" }).click();
  await expect(page.getByRole("heading", { name: "任务交付报告", exact: true })).toBeVisible();
  await page.getByRole("button", { name: "复制交付报告", exact: true }).click();
  await expect.poll(() => page.evaluate(() => navigator.clipboard.readText())).toMatch(/^# 任务交付报告\n/);
});

test("the report tab refreshes at window closure and can be copied before saved reports load", async ({
  context,
  page,
  baseURL,
}) => {
  if (!baseURL) throw new Error("Playwright baseURL is required");
  const token = randomUUID();
  await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  await context.addCookies([{ name: authCookieName(new URL(baseURL).port), value: token, url: baseURL }]);
  await context.addInitScript((value) => localStorage.setItem("artex_token", value), token);
  await page.clock.install({ time: new Date("2026-11-27T01:19:55+08:00") });

  let closed = false;
  let releaseSavedReport: (() => void) | undefined;
  const savedReportPending = new Promise<void>((resolve) => {
    releaseSavedReport = resolve;
  });

  await page.route("**/api/**", async (route) => {
    const { pathname } = new URL(route.request().url());
    if (pathname === "/api/tasks/74") {
      return route.fulfill({
        json: {
          id: "74",
          name: "交付截止验收",
          status: closed ? "paused" : "running",
          run_window: { end: "01:20", time_zone: "Asia/Shanghai" },
          run_window_status: closed ? "closed" : "approved",
        },
      });
    }
    if (pathname === "/api/exploration/findings") {
      const items = closed
        ? [
            {
              id: "1005",
              finding_id: "1005",
              task_id: "74",
              name: "目录展示范围异常",
              vulnclass: "权限校验",
              status: "pending",
              severity: "medium",
              summary: "目录中出现了其他部门的名称。",
              evidence_check_status: "not_assessed",
              traffic_count: 2,
            },
          ]
        : [];
      return route.fulfill({ json: { items, total: items.length, page_size: 100 } });
    }
    if (pathname === "/api/tasks/74/findings/1005/delivery-report") {
      await savedReportPending;
      return route.fulfill({ json: { exists: false, content: "" } });
    }
    return route.fulfill({ json: {} });
  });

  try {
    await page.goto("/function/tasks/detail?id=74&tab=report");
    await expect(page.getByText("任务 #74 · 当前汇总 · 共纳入 0 项登记发现")).toBeVisible();
    const copyButton = page.getByRole("button", { name: "复制报告草稿" });
    await copyButton.click();
    expect(await page.evaluate(() => navigator.clipboard.readText())).toContain("当前任务没有已登记的发现");

    closed = true;
    await page.clock.fastForward(5_100);
    await expect(page.getByText("任务 #74 · 截止汇总 · 共纳入 1 项登记发现")).toBeVisible();
    await expect(page.getByText("正在读取已保存的分项报告，当前可复制草稿。")).toBeVisible();
    await expect(page.getByText("未附完整原始 HTTP 请求报文。")).toBeVisible();
    await copyButton.click();
    const copied = await page.evaluate(() => navigator.clipboard.readText());
    expect(copied).toContain("| #1005 | 目录展示范围异常 | 中危 |");
    expect(copied).toContain("## #1005 · 目录展示范围异常");
    expect(copied).toContain("目录中出现了其他部门的名称。");
    expect(copied).toContain("证据引用尚未核对。");
    expect(copied).toContain("### 漏洞描述");
    expect(copied).toContain("### 测试过程");
    expect(copied).toContain("#### Burp 复现包");
    expect(copied).not.toContain("已绑定 2 条 HTTP 流量");
    expect(copied).not.toContain("```http");
    expect(copied).toContain("#### 攻击链路");
    expect(copied).toContain("#### 复现脚本");
    expect(copied).toContain("### 修复建议");
    expect(copied).toContain("**修复后验证**");
  } finally {
    releaseSavedReport?.();
  }
  await expect(page.getByText("正在读取已保存的分项报告，当前可复制草稿。")).toHaveCount(0);
  await expect(page.getByRole("button", { name: "复制交付报告" })).toHaveCount(0);
});

test("finding detail previews and copies the same developer report", async ({ context, page, baseURL }) => {
  if (!baseURL) throw new Error("Playwright baseURL is required");
  const token = randomUUID();
  const name = authCookieName(new URL(baseURL).port);
  await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  await context.addCookies([{ name, value: token, url: baseURL }]);
  await context.addInitScript((value) => localStorage.setItem("artex_token", value), token);

  const reportText = [
    "# 权限校验缺失",
    "",
    `- **CVSS 4.0 Base 向量（CVSS-B）**：${officialVectors[0].vector}`,
    "- **CVSS 4.0 评分**：1.0（CVSS-B）",
    "- **漏洞等级**：低危",
    "",
    "## 描述",
    "列表通过 `GET /api/records/42` 返回了其他用户的记录。",
    "触发位置：记录中心 → 我的记录，日常操作是打开记录列表。",
    "",
    "## 攻击链路",
    "```text\n普通用户访问记录接口\n└─ GET /api/records/42\n   └─ 返回其他用户的记录\n```",
    "",
    "## 测试过程",
    "测试时间：未记录",
    "预期只显示当前账号的记录。测试记录显示，列表里出现了其他账号的记录。首轮上传腿（seq 5–11）。",
    "",
    "## Burp 复现",
    "未在 Burp 中验证。",
    "以下请求包供渗透测试工程师在授权目标中导入 Burp Repeater 复现或复测；请求包本身不代表已通过 Burp 发送或验证。",
    "```http\nGET /api/records/42 HTTP/1.1\nHost: app.example\n```",
    "",
    "## 修复建议",
    "在 `src/server/records.ts:42` 读取记录前校验当前用户是否有权访问该记录。",
    "### 修复后验证",
    "有权限的用户应继续正常读取记录。没有权限的用户应被拒绝。",
    "",
    "<!-- artex:bound-traffic-evidence -->",
    "### 平台留存的 HTTP 请求与响应",
    "",
    "#### 证据绑定 1（辅助证据）",
    "- 请求地址：http://app.example/api/records/42",
    "##### 请求包",
    "```http",
    "GET /api/records/42 HTTP/1.1",
    "Host: app.example",
    "",
    "",
    "```",
    "##### 响应包",
    "```http",
    "HTTP/1.1 200 OK",
    "",
    "```",
  ].join("\n");
  let reportStale = false;
  let reportHasAppendix = true;

  await page.route("**/api/**", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    const path = url.pathname;
    const method = request.method();
    const json = (value: unknown, status = 200) =>
      route.fulfill({ status, contentType: "application/json", body: JSON.stringify(value) });

    if (path === "/api/exploration/findings/1001" && method === "GET") {
      await json({
        id: "1001",
        finding_id: "1001",
        task_id: "73",
        name: "权限校验缺失",
        vulnclass: "越权",
        severity: "high",
        status: "confirmed",
        summary: "接口未校验当前用户是否拥有目标记录的访问权限。",
        evidence: "使用低权限账号读取其他用户的记录。",
        report: "# 详细报告\n\n详细报告原文保持不变。",
        report_stale: false,
        traffic_count: 1,
        delivery_report: reportHasAppendix ? reportText : reportText.split("<!-- artex:bound-traffic-evidence -->")[0],
        delivery_report_cvss_vector: officialVectors[0].vector,
        delivery_report_evidence_version: 1,
        delivery_report_current_evidence_version: reportStale ? 2 : 1,
        delivery_report_stale: reportStale,
        ts: new Date().toISOString(),
      });
      return;
    }
    if (path === "/api/exploration/findings/1001/traffic" && method === "GET") {
      await json({ finding_id: "1001", version: 1, report_version: 0, bindings: [] });
      return;
    }
    if (path === "/api/exploration/findings/1001/retests" && method === "GET") {
      await json({ retests: [] });
      return;
    }

    await json({});
  });

  await page.goto("/function/findings/detail?id=1001");
  await expect(page.getByText("详细报告原文保持不变。")).toBeVisible();
  await expect(page.getByText("交付报告", { exact: true })).toBeVisible();
  await page.getByRole("tab", { name: "交付报告" }).click();
  await expect(page.getByText("CVSS 4.0：7.3（高危）")).toBeVisible();
  await expect(page.getByText("列表通过相关接口返回了其他用户的记录。")).toBeVisible();
  await expect(page.getByText("触发位置：记录中心 → 我的记录，日常操作是打开记录列表。")).toBeVisible();
  await expect(page.getByText("预期只显示当前账号的记录。测试记录显示，列表里出现了其他账号的记录。")).toBeVisible();
  await expect(page.getByText(/以下请求按证据绑定记录生成/)).toBeVisible();
  await expect(page.getByText(/GET \/api\/records\/42 HTTP\/1\.1\s+Host: app\.example/)).toBeVisible();
  await expect(page.getByText(/TARGET_URL = "http:\/\/app\.example\/api\/records\/42"/)).toBeVisible();
  await expect(page.getByText(/src\/server\/records\.ts:42/)).toBeVisible();
  await expect(page.getByText("修复后验证", { exact: true })).toBeVisible();
  await expect(page.getByText("没有权限的用户应被拒绝。")).toBeVisible();
  for (const heading of ["漏洞描述", "测试过程", "Burp 复现包", "攻击链路", "复现脚本（Python）", "修复建议"]) {
    await expect(page.getByText(heading, { exact: true })).toBeVisible();
  }
  await expect(page.getByText(/首轮上传腿/)).toHaveCount(0);
  await expect(page.getByRole("button", { name: "下载 Burp 复测包" })).toHaveCount(0);
  await expect(page.getByText(/漏洞等级.*高危/)).toHaveCount(0);
  await expect(page.getByText(officialVectors[0].vector)).toBeVisible();
  await expect(page.getByText("选择漏洞", { exact: true })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "生成草稿" })).toHaveCount(0);
  await expect(page.getByRole("textbox", { name: "Markdown 编辑" })).toHaveCount(0);

  await page.getByRole("button", { name: "复制交付报告" }).click();
  const copied = await page.evaluate(() => navigator.clipboard.readText());
  expect(copied).toContain("CVSS 4.0：7.3（高危）");
  expect(copied).toContain("列表通过相关接口返回了其他用户的记录。");
  expect(copied).toContain("触发位置：记录中心 → 我的记录，日常操作是打开记录列表。");
  expect(copied).toContain(officialVectors[0].vector);
  expect(copied).toContain("预期只显示当前账号的记录。测试记录显示，列表里出现了其他账号的记录。");
  expect(copied).toContain("以下请求按证据绑定记录生成");
  expect(copied).toContain("GET /api/records/42 HTTP/1.1");
  expect(copied).toContain("Host: app.example");
  expect(copied).toContain('TARGET_URL = "http://app.example/api/records/42"');
  expect(copied).toContain("src/server/records.ts:42");
  expect(copied).toContain("没有权限的用户应被拒绝。");
  expect(copied).toMatch(
    /### Burp 复现包\n[\s\S]*```http\nGET \/api\/records\/42 HTTP\/1\.1[\s\S]*### 攻击链路\n[\s\S]*### 复现脚本（Python）\n[\s\S]*TARGET_URL = "http:\/\/app\.example\/api\/records\/42"[\s\S]*## 修复建议/,
  );
  expect(copied).not.toMatch(/首轮上传腿|seq/);
  expect(copied).not.toContain("CVSS-B");
  expect(copied).not.toContain("漏洞等级");
  expect(copied).not.toContain("测试记录有更新");

  reportStale = true;
  await page.reload();
  await page.getByRole("tab", { name: "交付报告" }).click();
  await expect(page.getByText("报告草稿：测试记录有更新，交付前请核对报告。")).toBeVisible();
  await page.getByRole("button", { name: "复制报告草稿" }).click();
  await expect
    .poll(() => page.evaluate(() => navigator.clipboard.readText()))
    .toMatch(/^> 报告草稿：测试记录有更新，交付前请核对报告。\n\n/);
  expect(await page.evaluate(() => navigator.clipboard.readText())).toContain("页面加载时的附件证据版本：2。");
  await page.getByRole("tab", { name: "概览" }).click();
  await expect(page.getByText("详细报告原文保持不变。")).toBeVisible();

  reportStale = false;
  reportHasAppendix = false;
  await page.reload();
  await page.getByRole("tab", { name: "交付报告" }).click();
  await expect(page.getByText("报告草稿：缺少完整原始 HTTP 请求报文。")).toBeVisible();
  await expect(page.getByRole("button", { name: "复制交付报告" })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "复制报告草稿" })).toBeEnabled();
});
