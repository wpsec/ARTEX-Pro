import type { BrowserContext, Page } from "@playwright/test";
import { expect, test } from "@playwright/test";

import { randomUUID } from "node:crypto";

async function authenticateAndMockAPI(
  context: BrowserContext,
  page: Page,
  baseURL: string | undefined,
  responder: (pathname: string, search: URLSearchParams) => unknown,
  writes: string[],
  reads: string[],
) {
  if (!baseURL) throw new Error("Playwright baseURL is required");
  const token = randomUUID();
  const { port } = new URL(baseURL);
  const cookieName = port && port !== "80" && port !== "443" ? `artex_token_p${port}` : "artex_token";

  await context.addCookies([{ name: cookieName, value: token, url: baseURL }]);
  await context.addInitScript((value) => {
    localStorage.setItem("artex_token", value);
  }, token);

  await page.route("**/api/**", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    const requestKey = `${request.method()} ${url.pathname}${url.search}`;
    if (request.method() === "GET") reads.push(requestKey);
    else writes.push(requestKey);

    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(responder(url.pathname, url.searchParams) ?? {}),
    });
  });
}

test("task findings stay scoped and detail navigation returns to the task tab", async ({ context, page, baseURL }) => {
  const writes: string[] = [];
  const reads: string[] = [];
  const finding = {
    id: "node-11",
    finding_id: "11",
    task_id: "42",
    name: "当前任务发现",
    vulnclass: "合成验证",
    severity: "high",
    status: "pending",
    summary: "仅用于本地界面回归的合成记录",
    evidence: "合成证据",
    ts: "2026-11-26T08:00:00Z",
  };

  await authenticateAndMockAPI(
    context,
    page,
    baseURL,
    (pathname, search) => {
      if (pathname === "/api/tasks/42") {
        return {
          id: "42",
          name: "合成任务",
          description: "本地 UI 夹具",
          goal: "验证发现页上下文",
          status: "done",
          created_at: "2026-11-26T08:00:00Z",
          paused: false,
          queued: false,
        };
      }
      if (pathname === "/api/stats") return {};
      if (pathname === "/api/llm/profiles") return { profiles: [] };
      if (pathname === "/api/intercept/task/42") return { items: [] };
      if (pathname === "/api/exploration/findings" && search.get("task") === "42") {
        return [
          finding,
          {
            ...finding,
            id: "node-22",
            finding_id: "22",
            task_id: "99",
            name: "其他任务发现",
          },
        ];
      }
      if (pathname === "/api/exploration/findings/11") return finding;
      if (pathname === "/api/exploration/findings/11/retests") return { retests: [] };
      if (pathname === "/api/exploration/findings/11/traffic") return { bindings: [], version: 1 };
      return {};
    },
    writes,
    reads,
  );

  await page.goto("/function/tasks/detail?id=42&tab=findings");
  await expect(page.getByText("当前任务发现", { exact: true })).toBeVisible();
  await expect(page.getByText("其他任务发现", { exact: true })).toHaveCount(0);

  await page.getByRole("link", { name: "详情" }).click();
  await expect(page).toHaveURL(/\/function\/findings\/detail\?id=11&context_task=42$/);
  await expect(page.getByRole("heading", { name: "当前任务发现" })).toBeVisible();

  const taskFindingsBackLink = page.locator('header a[href="/function/tasks/detail?id=42&tab=findings"]');
  await expect(taskFindingsBackLink).toHaveCount(1);
  await taskFindingsBackLink.click();
  await expect(page).toHaveURL(/\/function\/tasks\/detail\?id=42&tab=findings$/);
  await expect(page.getByText("当前任务发现", { exact: true })).toBeVisible();
  await expect(page.getByText("其他任务发现", { exact: true })).toHaveCount(0);
  expect(reads).toContain("GET /api/exploration/findings/11?context_task=42");
  expect(writes).toEqual([]);
});

test("MCP server totals match the displayed per-tool call counts", async ({ context, page, baseURL }) => {
  const writes: string[] = [];
  const reads: string[] = [];

  await authenticateAndMockAPI(
    context,
    page,
    baseURL,
    (pathname) => {
      if (pathname === "/api/agents") return { agents: [] };
      if (pathname === "/api/mcp") {
        return {
          servers: [
            {
              id: 7,
              name: "OWASP ZAP",
              transport: "http",
              args: [],
              env: {},
              url: "http://127.0.0.1:8282",
              enabled: true,
              tools: ["browser_navigate", "http_request"],
              calls: 13,
            },
          ],
        };
      }
      if (pathname === "/api/visibility/mcp/7") return { agents: [] };
      if (pathname === "/api/mcp/7/tools") {
        return {
          tools: [
            { name: "browser_navigate", description: "合成导航工具", calls: 13 },
            { name: "http_request", description: "合成请求工具", calls: 0 },
          ],
        };
      }
      return {};
    },
    writes,
    reads,
  );

  await page.goto("/system/mcp");
  await expect(page.getByText("2 个工具 · 调用 13 次", { exact: true })).toBeVisible();

  await page.getByText("OWASP ZAP", { exact: true }).click();
  const dialog = page.getByRole("dialog");
  await dialog.getByRole("tab", { name: "工具列表（2）" }).click();
  await expect(dialog.getByText("调用 13 次", { exact: true })).toHaveCount(1);
  await expect(dialog.getByText("调用 0 次", { exact: true })).toHaveCount(1);
  expect(reads).toContain("GET /api/mcp");
  expect(reads).toContain("GET /api/mcp/7/tools");
  expect(writes).toEqual([]);
});
