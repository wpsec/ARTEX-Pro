"use client";

import { useCallback, useEffect, useState } from "react";

import { LoaderCircle, Play } from "lucide-react";
import { toast } from "sonner";

import { CyberspaceSearchIcon } from "@/components/cyberspace-search-icon";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Switch } from "@/components/ui/switch";
import { api } from "@/lib/api";
import type { CyberspaceSearchProvider } from "@/lib/types";

const reasons: Record<string, string> = {
  account_not_found: "找不到指定用户 ID",
  account_required: "填写用户 ID 后才能验证",
  access_denied: "账户权限或套餐不足",
  credential_storage_error: "服务端无法解密凭据",
  invalid_credential: "凭据无效或已过期",
  invalid_response: "供应商回包格式不符合预期",
  network_error: "无法连接供应商",
  probe_error: "连接测试无法启动",
  probe_unavailable: "暂无独立的凭据验证方式",
  provider_unavailable: "供应商服务异常",
  rate_limited: "供应商限流或额度不足",
  request_rejected: "供应商拒绝检查",
  timeout: "等待供应商响应超时",
};

const timeFormat = new Intl.DateTimeFormat("zh-CN", {
  year: "numeric",
  month: "2-digit",
  day: "2-digit",
  hour: "2-digit",
  minute: "2-digit",
});

function TestResult({ provider, testing }: { provider: CyberspaceSearchProvider; testing: boolean }) {
  if (!provider.configured || !provider.enabled) {
    return <span className="text-muted-foreground text-sm">已跳过</span>;
  }
  if (testing) return <span className="text-muted-foreground text-sm">测试中</span>;
  if (!provider.test) return <span className="text-muted-foreground text-sm">尚未测试</span>;

  const { status, reason, tested_at } = provider.test;
  return (
    <div className="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1">
      {status === "passed" ? (
        <Badge className="bg-emerald-500/10 text-emerald-700 dark:text-emerald-400">通过</Badge>
      ) : (
        <Badge variant={status === "failed" ? "destructive" : "outline"}>
          {status === "failed" ? "失败" : "未验证"}
        </Badge>
      )}
      {reason && <span className="text-muted-foreground text-xs">{reasons[reason] ?? "检查未完成"}</span>}
      <time className="text-muted-foreground text-xs" dateTime={tested_at}>
        {timeFormat.format(new Date(tested_at))}
      </time>
    </div>
  );
}

function ProviderEditor({
  provider,
  onClose,
  onSaved,
}: {
  provider: CyberspaceSearchProvider;
  onClose: () => void;
  onSaved: (provider: CyberspaceSearchProvider) => void;
}) {
  const [enabled, setEnabled] = useState(provider.enabled);
  const [key, setKey] = useState("");
  const [account, setAccount] = useState("");
  const [email, setEmail] = useState("");
  const [removeEmail, setRemoveEmail] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");

  async function save(clear = false) {
    setSaving(true);
    setError("");
    try {
      const updated = await api.saveCyberspaceSearchProvider(provider.id, {
        revision: provider.revision,
        enabled,
        ...(clear
          ? { clear: true }
          : {
              api_key: key.trim() || undefined,
              account_id: account.trim() || undefined,
              email: removeEmail ? "" : email.trim() || undefined,
            }),
      });
      setKey("");
      setAccount("");
      setEmail("");
      onSaved(updated);
      toast.success(clear ? "已清除凭据" : "已保存搜索引擎配置");
    } catch (err) {
      setError(err instanceof Error ? err.message : "配置保存失败");
    } finally {
      setSaving(false);
    }
  }

  return (
    <Sheet open onOpenChange={(open) => !open && !saving && onClose()}>
      <SheetContent className="w-full sm:max-w-md">
        <SheetHeader>
          <SheetTitle>{provider.name}</SheetTitle>
          <SheetDescription>凭据保存后隐藏。留空保留已保存的值。</SheetDescription>
        </SheetHeader>
        <form
          className="flex flex-col gap-5 px-4 pb-5"
          onSubmit={(event) => {
            event.preventDefault();
            void save();
          }}
        >
          <div className="flex items-center justify-between rounded-lg border px-3 py-2.5">
            <Label htmlFor="cyberspace-enabled">启用连接测试</Label>
            <Switch id="cyberspace-enabled" checked={enabled} disabled={saving} onCheckedChange={setEnabled} />
          </div>
          <div className="space-y-2">
            <Label htmlFor="cyberspace-key">{provider.credential}</Label>
            <Input
              id="cyberspace-key"
              type="password"
              autoComplete="new-password"
              maxLength={2048}
              disabled={saving}
              value={key}
              onChange={(event) => setKey(event.target.value)}
              placeholder={provider.configured ? "已配置，填写新值可替换" : "输入凭据"}
            />
          </div>
          {provider.supports_email && (
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <Label htmlFor="cyberspace-email">注册邮箱（旧版选填）</Label>
                {provider.email_set && (
                  <Button
                    type="button"
                    size="sm"
                    variant="ghost"
                    disabled={saving}
                    onClick={() => {
                      setRemoveEmail(!removeEmail);
                      setEmail("");
                    }}
                  >
                    {removeEmail ? "保留邮箱" : "清除邮箱"}
                  </Button>
                )}
              </div>
              <Input
                id="cyberspace-email"
                type="email"
                autoComplete="off"
                maxLength={254}
                disabled={saving || removeEmail}
                value={email}
                onChange={(event) => setEmail(event.target.value)}
                placeholder={provider.email_set ? "已配置，填写新值可替换" : "填写 FOFA 注册邮箱"}
              />
              <p className="text-muted-foreground text-xs">
                {removeEmail ? "保存后将仅使用 API Key。" : "当前版只需 API Key。旧版要求邮箱时再填写。"}
              </p>
            </div>
          )}
          {provider.needs_account_id && (
            <div className="space-y-2">
              <Label htmlFor="cyberspace-account">用户 ID（连接测试选填）</Label>
              <Input
                id="cyberspace-account"
                type="password"
                autoComplete="new-password"
                maxLength={128}
                disabled={saving}
                value={account}
                onChange={(event) => setAccount(event.target.value)}
                placeholder={provider.account_id_set ? "已配置，填写新值可替换" : "用于验证账户，可稍后配置"}
              />
              <p className="text-muted-foreground text-xs">填写 VirusTotal 账户的用户 ID。</p>
            </div>
          )}
          {error && (
            <p className="text-destructive text-sm" role="alert">
              {error}
            </p>
          )}
          <div className="flex items-center justify-between gap-2">
            <div>
              {(provider.configured || provider.account_id_set || provider.email_set) && (
                <AlertDialog>
                  <AlertDialogTrigger asChild>
                    <Button type="button" variant="outline" className="text-destructive" disabled={saving}>
                      清除凭据
                    </Button>
                  </AlertDialogTrigger>
                  <AlertDialogContent>
                    <AlertDialogHeader>
                      <AlertDialogTitle>清除 {provider.name} 的凭据</AlertDialogTitle>
                      <AlertDialogDescription>清除后，批量测试将跳过此引擎。</AlertDialogDescription>
                    </AlertDialogHeader>
                    <AlertDialogFooter>
                      <AlertDialogCancel>取消</AlertDialogCancel>
                      <AlertDialogAction onClick={() => void save(true)}>确认清除</AlertDialogAction>
                    </AlertDialogFooter>
                  </AlertDialogContent>
                </AlertDialog>
              )}
            </div>
            <Button type="submit" disabled={saving}>
              {saving ? "保存中" : "保存"}
            </Button>
          </div>
        </form>
      </SheetContent>
    </Sheet>
  );
}

export default function CyberspaceSearchPage() {
  const [providers, setProviders] = useState<CyberspaceSearchProvider[]>([]);
  const [editor, setEditor] = useState<CyberspaceSearchProvider | null>(null);
  const [loading, setLoading] = useState(true);
  const [testing, setTesting] = useState(false);
  const [error, setError] = useState("");
  const configured = providers.filter((provider) => provider.configured && provider.enabled).length;

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      setProviders(await api.cyberspaceSearchProviders());
    } catch (err) {
      setError(err instanceof Error ? err.message : "读取配置失败");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function testAll() {
    setTesting(true);
    try {
      setProviders(await api.testCyberspaceSearchProviders());
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "连接测试失败");
      await load();
    } finally {
      setTesting(false);
    }
  }

  return (
    <div className="w-full max-w-5xl space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="grid size-11 shrink-0 place-items-center rounded-xl bg-indigo-500/10 text-indigo-700 dark:text-indigo-300">
            <CyberspaceSearchIcon className="size-6" aria-hidden="true" />
          </div>
          <div>
            <h1 className="font-semibold text-xl tracking-tight">网络空间搜索引擎</h1>
            <p className="text-muted-foreground text-sm">连接测试只检查供应商账户，不发送任务资产。</p>
          </div>
        </div>
        <Button onClick={() => void testAll()} disabled={loading || testing || !configured || Boolean(error)}>
          {testing ? <LoaderCircle className="size-4 animate-spin" /> : <Play className="size-4" />}
          {testing ? `正在测试 ${configured} 家` : "测试全部"}
        </Button>
      </div>

      {loading || error ? (
        <div className="flex min-h-36 items-center justify-center gap-3 rounded-xl border p-4 text-sm">
          <p className={error ? "text-destructive" : "text-muted-foreground"} role={error ? "alert" : "status"}>
            {error || "正在读取配置…"}
          </p>
          {error && (
            <Button variant="outline" size="sm" onClick={() => void load()}>
              重试
            </Button>
          )}
        </div>
      ) : (
        <div className="overflow-hidden rounded-xl border bg-card">
          <div className="hidden grid-cols-[minmax(0,1.1fr)_minmax(0,.7fr)_minmax(0,1.7fr)_auto] items-center gap-4 bg-muted/50 px-4 py-2.5 font-medium text-muted-foreground text-xs md:grid">
            <span>搜索引擎</span>
            <span>配置状态</span>
            <span>最近测试</span>
            <span className="w-14 text-center">操作</span>
          </div>
          <ul className="divide-y border-t" aria-live="polite" aria-busy={testing}>
            {providers.map((provider) => (
              <li
                key={provider.id}
                className="grid grid-cols-[1fr_auto] items-center gap-x-3 gap-y-2 px-4 py-3 md:grid-cols-[minmax(0,1.1fr)_minmax(0,.7fr)_minmax(0,1.7fr)_auto] md:gap-4"
              >
                <span className="font-medium text-sm">{provider.name}</span>
                <Badge variant="secondary" className="row-start-2 md:row-auto">
                  {provider.configured && provider.enabled && "已配置"}
                  {provider.configured && !provider.enabled && "已停用"}
                  {!provider.configured && "未配置"}
                </Badge>
                <div className="col-span-2 md:col-span-1">
                  <TestResult provider={provider} testing={testing} />
                </div>
                <Button
                  variant="outline"
                  size="sm"
                  className="col-start-2 row-start-1 w-14 md:col-start-auto md:row-start-auto"
                  aria-label={`配置 ${provider.name}`}
                  disabled={testing}
                  onClick={() => setEditor(provider)}
                >
                  配置
                </Button>
              </li>
            ))}
          </ul>
        </div>
      )}

      {editor && (
        <ProviderEditor
          key={editor.id}
          provider={editor}
          onClose={() => setEditor(null)}
          onSaved={(updated) => {
            setProviders((current) => current.map((provider) => (provider.id === updated.id ? updated : provider)));
            setEditor(null);
          }}
        />
      )}
    </div>
  );
}
