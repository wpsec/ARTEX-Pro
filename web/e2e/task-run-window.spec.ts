import { expect, test } from "@playwright/test";

import { authCookieName } from "../src/lib/auth-cookie";
import { randomUUID } from "node:crypto";

const currentWindow = { end: "08:00", time_zone: "Asia/Shanghai" };
const task = {
  id: "42",
  name: "合成任务",
  description: "停止时间验证",
  goal: "验证配置",
  created_at: "2026-11-26T08:00:00Z",
  created_unix: 1795680000,
  status: "running",
  paused: false,
  queued: false,
  run_window: currentWindow,
  run_window_revision: 1,
  run_window_status: "approved",
  run_window_next_at: "2026-11-27T00:00:00Z",
};

test.beforeEach(async ({ context, baseURL }) => {
  if (!baseURL) throw new Error("Playwright baseURL is required");
  const token = randomUUID();
  await context.addCookies([{ name: authCookieName(new URL(baseURL).port), value: token, url: baseURL }]);
  await context.addInitScript((value) => localStorage.setItem("artex_token", value), token);
});

test("task creation stores its stop time and the list displays it", async ({ page }) => {
  const creations: unknown[] = [];
  let listedTask = task;
  await page.route("**/api/**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    let response: unknown = {};
    if (path === "/api/tasks" && request.method() === "POST") {
      creations.push(request.postDataJSON());
      response = task;
    } else if (path === "/api/tasks") {
      response = { tasks: creations.length ? [listedTask] : [], active: "" };
    } else if (path === "/api/llm/profiles") {
      response = { profiles: [] };
    } else if (path === "/api/companies") {
      response = [];
    }
    await route.fulfill({ json: response });
  });

  await page.goto("/function/tasks");
  await page.getByRole("button", { name: "新建任务" }).click();
  const sheet = page.getByRole("dialog");
  await sheet.locator("#description").fill("停止时间验证");
  await sheet.locator("#goal").fill("验证配置");
  await sheet.getByRole("checkbox", { name: "设置每日停止时间" }).check();
  await sheet.getByLabel("渗透停止时间").fill("08:00");
  await sheet.getByLabel("时区").fill("Asia/Shanghai");
  await expect(sheet.getByText("到停止时间自动暂停。")).toBeVisible();
  await sheet.getByRole("button", { name: "创建", exact: true }).click();
  await expect.poll(() => creations.length).toBe(1);
  expect(creations[0]).toMatchObject({ run_window: currentWindow, seed_first_intent: false });
  await expect(page.getByText("停止 08:00 Asia/Shanghai", { exact: true })).toBeVisible();
  await expect(page.getByText("渗透测试结束时间已确认 · 停止时间 2026/11/27 08:00", { exact: true })).toBeVisible();

  listedTask = { ...task, run_window_next_at: "2027-01-01T14:00:00Z" };
  await page.reload();
  await expect(page.getByText("渗透测试结束时间已确认 · 停止时间 2027/1/1 22:00", { exact: true })).toBeVisible();

  listedTask = { ...listedTask, status: "paused", paused: true, run_window_status: "closed" };
  await page.reload();
  await expect(page.getByText("已到停止时间，任务已暂停", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "继续任务", exact: true })).toBeDisabled();
});
