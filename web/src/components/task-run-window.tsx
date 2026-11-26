"use client";

import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import type { Task, TaskRunWindow } from "@/lib/types";

export function defaultRunWindow(): TaskRunWindow {
  return { end: "08:00", time_zone: Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC" };
}

export function TaskRunWindowFields({
  value,
  onChange,
}: {
  value: TaskRunWindow;
  onChange: (value: TaskRunWindow) => void;
}) {
  return (
    <div className="grid gap-3">
      <Label className="grid gap-1.5">
        渗透停止时间
        <Input type="time" value={value.end} onChange={(event) => onChange({ ...value, end: event.target.value })} />
      </Label>
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
  approved: { label: "渗透测试结束时间已确认", nextEvent: "停止时间" },
  closed: { label: "已到停止时间，任务已暂停", nextEvent: null },
  pausing: { label: "暂停中", nextEvent: null },
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
  if (!task.run_window) return task.run_window_status === "pausing" ? <span>暂停中</span> : null;
  const status = task.run_window_status && windowStatuses[task.run_window_status];
  const next = status?.nextEvent ? formatTime(task.run_window_next_at, task.run_window.time_zone) : null;
  const deadline = formatTime(task.deadline_at, task.run_window.time_zone);
  return (
    <div className="space-y-0.5 text-muted-foreground text-xs">
      <div>{runWindowText(task.run_window)}</div>
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
  return window ? `停止 ${window.end} ${window.time_zone}` : "未设置";
}
