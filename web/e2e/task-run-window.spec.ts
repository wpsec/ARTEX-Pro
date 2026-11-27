import { expect, test } from "@playwright/test";

import { authCookieName } from "../src/lib/auth-cookie";
import { randomUUID } from "node:crypto";

const currentWindow = { end: "08:00", time_zone: "Asia/Shanghai" };
const task = {
  id: "42",
  name: "合成任务",
  description: "暂停时间验证",
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

test("a new task sends a one-time scheduled run window", async ({ page }) => {
  const scheduledWindow = {
    start_at: "2026-11-28T10:00",
    pause_at: "2026-11-28T20:00",
    time_zone: "Asia/Shanghai",
  };
  const scheduledTask = {
    ...task,
    status: "scheduled",
    run_window: scheduledWindow,
    run_window_status: "scheduled",
    run_window_next_at: "2026-11-28T02:00:00Z",
  };
  const creations: unknown[] = [];
  let listedTask = scheduledTask;
  await page.route("**/api/**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    let response: unknown = {};
    if (path === "/api/tasks" && request.method() === "POST") {
      creations.push(request.postDataJSON());
      response = scheduledTask;
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
  await sheet.locator("#description").fill("暂停时间验证");
  await sheet.locator("#goal").fill("验证配置");
  await sheet.getByRole("checkbox", { name: "设置定时任务" }).check();
  await sheet.getByLabel("自动启动时间").fill(scheduledWindow.start_at);
  await sheet.getByLabel("自动暂停时间").fill(scheduledWindow.pause_at);
  await sheet.getByLabel("时区").fill("Asia/Shanghai");
  await expect(sheet.getByText(/指定年月日自动启动和自动暂停，各执行一次/)).toBeVisible();
  await sheet.getByRole("button", { name: "创建", exact: true }).click();
  await expect.poll(() => creations.length).toBe(1);
  expect(creations[0]).toMatchObject({ run_window: scheduledWindow, seed_first_intent: false });
  await expect(
    page.getByText("定时安排 2026-11-28 10:00 启动 · 2026-11-28 20:00 暂停（Asia/Shanghai）", { exact: true }),
  ).toBeVisible();

  listedTask = { ...scheduledTask, run_window_next_at: "2027-01-01T14:00:00Z" };
  await page.reload();
  await expect(page.getByText("等待定时启动 · 自动启动时间 2027/1/1 22:00", { exact: true })).toBeVisible();
});

test("a chat proposal saves one pause time and resumes without another confirmation", async ({ page }) => {
  const writes: { path: string; payload: unknown }[] = [];
  const editedWindow = { end: "23:00", time_zone: "Asia/Shanghai" };
  let currentTask = task;
  await page.route("**/api/**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    let response: unknown = {};
    if (request.method() !== "GET" && path.endsWith("/run-window")) {
      writes.push({ path, payload: request.postDataJSON() });
    }
    if (path === "/api/agents")
      response = { agents: [{ key: "auto", name: "自动", builtin: true, role: "assistant" }] };
    if (path === "/api/conversations") response = { conversations: [] };
    if (path === "/api/llm/profiles") response = { profiles: [] };
    if (path === "/api/tasks") response = { tasks: [currentTask, { ...task, id: "99", name: "另一任务" }] };
    if (path === "/api/tasks/42") response = currentTask;
    if (path === "/api/tasks/42/run-window" && request.method() === "PUT") {
      const runWindowWriteCount = writes.length;
      currentTask = {
        ...currentTask,
        status: "running",
        paused: false,
        queued: false,
        run_window: runWindowWriteCount > 1 ? { ...editedWindow, end: "08:00" } : editedWindow,
        run_window_revision: currentTask.run_window_revision + 1,
        run_window_status: "approved",
        run_window_next_at: runWindowWriteCount > 1 ? "2026-11-27T00:00:00Z" : "2026-11-26T15:00:00Z",
      };
      response = currentTask;
    }
    await route.fulfill({ json: response });
  });

  await page.goto("/chat");
  const composer = page.getByPlaceholder(/输入消息/);
  await expect(composer).toBeEnabled();
  const dialog = page.getByRole("dialog", { name: "设置任务定时计划" });
  await composer.fill("把任务 #42 和 #99 的暂停时间改为晚上11点");
  await composer.press("Enter");
  await expect(dialog.getByLabel("选择任务")).toBeVisible();
  await expect(dialog.getByRole("button", { name: "确认保存" })).toBeDisabled();
  await dialog.getByRole("button", { name: "取消" }).click();
  expect(writes).toEqual([]);

  await composer.fill("把任务 #42 的暂停时间改为晚上11点");
  await composer.press("Enter");
  await expect(dialog.getByText("原定时安排 旧版每日 08:00 暂停（Asia/Shanghai）")).toBeVisible();
  await expect(dialog.getByText("新定时安排 旧版每日 23:00 暂停（Asia/Shanghai）")).toBeVisible();
  await dialog.getByRole("button", { name: "确认保存" }).click();
  await expect
    .poll(() => writes)
    .toEqual([
      {
        path: "/api/tasks/42/run-window",
        payload: { revision: 1, window: editedWindow },
      },
    ]);
  await expect(dialog).toBeHidden();

  await page.goto("/function/tasks/detail?id=42");
  await page.getByRole("button", { name: "运行窗口", exact: true }).click();
  await expect(dialog.getByText("原定时安排 旧版每日 23:00 暂停（Asia/Shanghai）")).toBeVisible();
  await expect(dialog.getByLabel("选择任务")).toHaveCount(0);
  await dialog.getByLabel("旧版每日暂停时间").fill("08:00");
  await dialog.getByRole("button", { name: "确认保存" }).click();
  await expect(dialog).toBeHidden();
  await expect(page).toHaveURL(/\/function\/tasks\/detail\/?\?id=42/);
  await expect(page.getByText("定时安排 旧版每日 08:00 暂停（Asia/Shanghai）", { exact: true })).toBeVisible();
  expect(writes).toEqual([
    { path: "/api/tasks/42/run-window", payload: { revision: 1, window: editedWindow } },
    { path: "/api/tasks/42/run-window", payload: { revision: 2, window: { ...editedWindow, end: "08:00" } } },
  ]);
});
