"use client";

import * as React from "react";

import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { api } from "@/lib/api";
import type { Task, TaskRunWindow } from "@/lib/types";

export function defaultRunWindow(): TaskRunWindow {
  return { start_at: "", pause_at: "", time_zone: Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC" };
}

export function TaskRunWindowFields({
  value,
  onChange,
}: {
  value: TaskRunWindow;
  onChange: (value: TaskRunWindow) => void;
}) {
  const legacyDaily = value.end !== undefined && !value.start_at && !value.pause_at;
  return (
    <div className="grid gap-3">
      {legacyDaily ? (
        <>
          <Label className="grid gap-1.5">
            旧版每日暂停时间
            <Input type="time" value={value.end ?? ""} onChange={(event) => onChange({ ...value, end: event.target.value })} />
          </Label>
          <button
            type="button"
            className="text-left text-primary text-sm underline-offset-4 hover:underline"
            onClick={() => onChange({ start_at: "", pause_at: "", time_zone: value.time_zone })}
          >
            改为指定日期的一次性定时任务
          </button>
        </>
      ) : (
        <>
          <Label className="grid gap-1.5">
            自动启动时间
            <Input
              type="datetime-local"
              value={value.start_at ?? ""}
              onChange={(event) => onChange({ ...value, end: undefined, start_at: event.target.value })}
            />
          </Label>
          <Label className="grid gap-1.5">
            自动暂停时间
            <Input
              type="datetime-local"
              value={value.pause_at ?? ""}
              onChange={(event) => onChange({ ...value, end: undefined, pause_at: event.target.value })}
            />
          </Label>
        </>
      )}
      <Label className="grid gap-1.5">
        时区
        <Input
          value={value.time_zone}
          placeholder="Asia/Shanghai"
          onChange={(event) => onChange({ ...value, time_zone: event.target.value })}
        />
      </Label>
    </div>
  );
}

const windowStatuses = {
  scheduled: { label: "等待定时启动", nextEvent: "自动启动时间" },
  approved: { label: "渗透测试运行中", nextEvent: "自动暂停时间" },
  closed: { label: "渗透测试已暂停", nextEvent: null },
  pausing: { label: "渗透测试暂停中", nextEvent: null },
};

function formatTime(value?: string, timeZone?: string) {
  if (!value) return null;
  try {
    return new Intl.DateTimeFormat("zh-CN", {
      timeZone,
      year: "numeric",
      month: "numeric",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      hourCycle: "h23",
    }).format(new Date(value));
  } catch (error) {
    if (error instanceof RangeError) return value;
    throw error;
  }
}

export function TaskRunWindowStatus({ task }: { task: Task }) {
  if (!task.run_window) return task.run_window_status === "pausing" ? <span>渗透测试暂停中</span> : null;
  const status = task.run_window_status && windowStatuses[task.run_window_status];
  const next = status?.nextEvent ? formatTime(task.run_window_next_at, task.run_window.time_zone) : null;
  const deadline = formatTime(task.deadline_at, task.run_window.time_zone);
  return (
    <div className="space-y-0.5 text-muted-foreground text-xs">
      <div>定时安排 {runWindowText(task.run_window)}</div>
      {status && (
        <div>
          {status.label}
          {next && ` · ${status.nextEvent} ${next}`}
        </div>
      )}
      {deadline && <div>任务截止 {deadline}</div>}
    </div>
  );
}

function runWindowText(window?: TaskRunWindow) {
  if (!window) return "未设置";
  if (window.start_at || window.pause_at) {
    const start = window.start_at?.replace("T", " ") || "未设置";
    const pause = window.pause_at?.replace("T", " ") || "未设置";
    return `${start} 启动 · ${pause} 暂停（${window.time_zone}）`;
  }
  return window.end ? `旧版每日 ${window.end} 暂停（${window.time_zone}）` : "未设置";
}

interface WindowRequest {
  taskId?: string;
  draft?: TaskRunWindow;
}

function conversationalTime(value: string) {
  const match = /^(凌晨|早上|上午|中午|下午|晚上)?\s*(\d{1,2})\s*(?:[:：](\d{2})|点(?:(\d{1,2})分|半)?)$/.exec(value);
  if (!match) return "";
  const [, period, hours, clockMinutes, spokenMinutes] = match;
  let hour = Number(hours);
  const minute = Number(clockMinutes ?? spokenMinutes ?? (value.endsWith("半") ? 30 : 0));
  if (period && hour > 12) return "";
  if (["下午", "晚上", "中午"].includes(period) && hour < 12) hour += 12;
  if (["凌晨", "早上", "上午"].includes(period) && hour === 12) hour = 0;
  if (hour > 23 || minute > 59) return "";
  return `${String(hour).padStart(2, "0")}:${String(minute).padStart(2, "0")}`;
}

function readWindowCommand(message: string, currentTaskId?: string): WindowRequest | null {
  const value = message.trim();
  const direct = /^\/window(?:\s|$)/i.test(value);
  const conversational = /^(?:把|将|设置|调整|修改)\s*(?:任务|本任务).*(?:自动启动时间|自动暂停时间|启动时间|开始时间|停止时间|暂停时间|运行时段|运行窗口|运行时间)/.test(value);
  if (!direct && !conversational) return null;
  const text = direct ? value.replace(/^\/window\s*/i, "") : value;
  const taskIds = direct
    ? [text.match(/^#?([1-9]\d*)(?=\s|$)/)?.[1]].filter(Boolean)
    : [...text.matchAll(/(?:任务\s*#?\s*|#)([1-9]\d*)/g)].map((match) => match[1]);
  const uniqueIds = [...new Set(taskIds)];
  const taskId = uniqueIds.length <= 1 ? (uniqueIds[0] ?? currentTaskId) : undefined;
  const dateTimes = [...text.matchAll(/(\d{4})[-/.年]\s*(\d{1,2})[-/.月]\s*(\d{1,2})日?\s*(\d{1,2})[:：](\d{2})/g)];
  const dateTime = dateTimes.at(-1);
  const zone = text.match(/\b(?:UTC|[A-Za-z_]+(?:\/[A-Za-z_+\-\d]+)+)\b/)?.[0];
  if (dateTime) {
    const [, year, month, day, hour, minute] = dateTime;
    const parsed = new Date(Date.UTC(Number(year), Number(month) - 1, Number(day), Number(hour), Number(minute)));
    if (
      parsed.getUTCFullYear() !== Number(year) ||
      parsed.getUTCMonth() !== Number(month) - 1 ||
      parsed.getUTCDate() !== Number(day) ||
      parsed.getUTCHours() !== Number(hour) ||
      parsed.getUTCMinutes() !== Number(minute)
    ) {
      return { taskId };
    }
    const field = /启动|开始/.test(text) && !/暂停/.test(text) ? "start_at" : "pause_at";
    const draft: TaskRunWindow = { time_zone: zone ?? "" };
    draft[field] = `${year}-${String(month).padStart(2, "0")}-${String(day).padStart(2, "0")}T${String(hour).padStart(2, "0")}:${minute}`;
    draft.end = undefined;
    return { taskId, draft };
  }
  const timePattern = String.raw`(?:凌晨|早上|上午|中午|下午|晚上)?\s*\d{1,2}\s*(?:[:：]\d{2}|点(?:\d{1,2}分|半)?)`;
  const times = [...text.matchAll(new RegExp(timePattern, "g"))];
  const match = times.at(-1);
  if (!match) return { taskId };
  if (/启动|开始/.test(text) && !/暂停/.test(text)) return { taskId };
  const end = conversationalTime(match[0].trim());
  if (!end) return { taskId };
  return {
    taskId,
    draft: {
      end,
      time_zone: zone ?? "",
    },
  };
}

function RunWindowDialog({
  request,
  currentTaskId,
  onCurrentTaskSaved,
  onClose,
}: {
  request: WindowRequest;
  currentTaskId?: string;
  onCurrentTaskSaved?: (task: Task) => void;
  onClose: () => void;
}) {
  const [selected, setSelected] = React.useState(request.taskId ?? "");
  const [tasks, setTasks] = React.useState<Task[]>([]);
  const [task, setTask] = React.useState<Task>();
  const [value, setValue] = React.useState(defaultRunWindow);
  const [enabled, setEnabled] = React.useState(true);
  const [loading, setLoading] = React.useState(!!request.taskId);
  const [saving, setSaving] = React.useState(false);
  const [error, setError] = React.useState("");

  React.useEffect(() => {
    if (request.taskId) return;
    let active = true;
    void api
      .tasks()
      .then(({ tasks }) => {
        if (active) setTasks(tasks.filter((item) => !["done", "failed", "timeout"].includes(item.status)));
      })
      .catch((cause: unknown) => {
        if (active) setError(cause instanceof Error ? cause.message : "读取任务失败");
      });
    return () => {
      active = false;
    };
  }, [request.taskId]);

  React.useEffect(() => {
    if (!selected) return;
    let active = true;
    setLoading(true);
    setError("");
    setTask(undefined);
    void api
      .task(selected)
      .then((current) => {
        if (!active) return;
        setTask(current);
        const original = current.run_window ?? defaultRunWindow();
        const draft = request.draft;
        const merged = draft
          ? { ...original, ...draft, time_zone: draft.time_zone || original.time_zone }
          : original;
        if (draft?.end && original.pause_at && !draft.start_at && !draft.pause_at) {
          merged.end = undefined;
          merged.pause_at = `${original.pause_at.slice(0, 10)}T${draft.end}`;
        }
        setValue(merged);
        setEnabled(true);
      })
      .catch((cause: unknown) => {
        if (active) setError(cause instanceof Error ? cause.message : "读取任务失败");
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [request.draft, selected]);

  async function save() {
    if (!task || loading || saving || task.id !== selected) return;
    setSaving(true);
    setError("");
    try {
      const updated = await api.updateTaskRunWindow(task.id, task.run_window_revision ?? 0, enabled ? value : null);
      if (updated.id === currentTaskId) {
        onCurrentTaskSaved?.(updated);
      }
      toast.success(
        updated.run_window_status === "scheduled"
          ? "定时任务已保存，等待自动启动"
          : updated.queued
            ? "定时任务已保存，任务已加入执行队列"
            : enabled
              ? "自动暂停时间已保存，任务已继续执行"
              : "定时限制已移除，任务已继续执行",
      );
      onClose();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "保存运行窗口失败");
    } finally {
      setSaving(false);
    }
  }

  return (
    <Dialog
      open
      onOpenChange={(open) => {
        if (!open && !saving) onClose();
      }}
    >
      <DialogContent>
        <DialogHeader>
          <DialogTitle>设置任务定时计划</DialogTitle>
          <DialogDescription>
            指定日期自动启动一次，到暂停时间后任务改为暂停；暂停后仍会继续完善已有漏洞报告。
          </DialogDescription>
        </DialogHeader>
        {!request.taskId && (
          <Label className="grid gap-1.5">
            选择任务
            <select
              className="rounded-md border bg-background px-2 py-2 text-sm"
              disabled={saving}
              value={selected}
              onChange={(event) => setSelected(event.target.value)}
            >
              <option value="">请选择具体任务</option>
              {tasks.map((item) => (
                <option key={item.id} value={item.id}>
                  #{item.id} {item.name || item.description}
                </option>
              ))}
            </select>
          </Label>
        )}
        {task && (
          <div className="grid gap-3">
            <div className="font-medium text-sm">
              #{task.id} {task.name || task.description}
            </div>
            <p className="text-muted-foreground text-sm">原定时安排 {runWindowText(task.run_window)}</p>
            {task.run_window && (
              <Label>
                <input type="checkbox" checked={enabled} onChange={(event) => setEnabled(event.target.checked)} />{" "}
                设置任务定时计划
              </Label>
            )}
            {enabled && (
              <>
                <TaskRunWindowFields value={value} onChange={setValue} />
                <p className="text-muted-foreground text-sm">自动暂停后任务进入暂停状态；已登记漏洞的报告会继续撰写并补全。</p>
              </>
            )}
            <p className="text-muted-foreground text-sm">新定时安排 {runWindowText(enabled ? value : undefined)}</p>
          </div>
        )}
        {loading && <p className="text-muted-foreground text-sm">正在读取窗口配置…</p>}
        {error && (
          <p role="alert" className="text-destructive text-sm">
            {error}
          </p>
        )}
        <DialogFooter>
          <Button variant="outline" onClick={onClose} disabled={saving}>
            取消
          </Button>
          <Button
            onClick={() => void save()}
            disabled={
              !task ||
              loading ||
              saving ||
              (enabled &&
                (!value.time_zone ||
                  (value.end === undefined && (!value.start_at || !value.pause_at)) ||
                  (value.end === undefined && Boolean(value.start_at && value.pause_at && value.pause_at <= value.start_at)) ||
                  (value.end !== undefined && Boolean(!value.end || value.start_at || value.pause_at))))
            }
          >
            确认保存
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export function useTaskRunWindowDialog(currentTaskId?: string, onCurrentTaskSaved?: (task: Task) => void) {
  const [request, setRequest] = React.useState<WindowRequest | null>(null);
  return {
    open: () => setRequest({ taskId: currentTaskId }),
    intercept: (message: string, clear: () => void) => {
      const command = readWindowCommand(message, currentTaskId);
      if (!command) return false;
      setRequest(command);
      clear();
      return true;
    },
    dialog: request ? (
      <RunWindowDialog
        request={request}
        currentTaskId={currentTaskId}
        onCurrentTaskSaved={onCurrentTaskSaved}
        onClose={() => setRequest(null)}
      />
    ) : null,
  };
}
