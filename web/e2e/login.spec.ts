import { expect, test } from "@playwright/test";

test("login remembers only the confirmed version of the usage notice", async ({ page }) => {
  await page.route("**/api/auth/status", (route) => route.fulfill({ json: { initialized: true } }));
  await page.goto("/login");

  const agreement = page.getByRole("checkbox");
  await expect(agreement).not.toBeChecked();
  await page.getByRole("button", { name: "《使用须知》" }).click();
  const notice = page.getByRole("dialog", { name: "ARTEX-Pro 使用须知" });
  await notice.locator(".overflow-y-auto").evaluate((element) => {
    element.scrollTop = element.scrollHeight;
  });
  await notice.getByRole("button", { name: "我已阅读并确认使用须知" }).click();
  await expect(agreement).toBeChecked();

  await page.reload();
  await expect(agreement).toBeChecked();
  await expect(page.getByRole("button", { name: "登录", exact: true })).toBeDisabled();

  await agreement.uncheck();
  await page.reload();
  await expect(agreement).not.toBeChecked();
  await agreement.check();
  await page.reload();
  await expect(agreement).toBeChecked();

  await page.evaluate(() => localStorage.setItem("artex_login_terms_version", "v0"));
  await page.reload();
  await expect(agreement).not.toBeChecked();
});
