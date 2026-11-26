"use client";

import * as React from "react";

import Link from "next/link";

import { CopyButton } from "@/components/copy-button";
import { Markdown } from "@/components/markdown";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { api } from "@/lib/api";
import { formatRecordedFindingReport, prepareDeveloperDeliveryReport } from "@/lib/delivery-report";
import type { Finding, Task } from "@/lib/types";

type DeliveryState = "loading" | "saved" | "missing" | "unavailable";
type ReportDocument = ReturnType<typeof formatRecordedFindingReport> & {
  delivery: DeliveryState;
  detailed?: boolean;
  issues?: string[];
};
type ReportState =
  | { status: "loading" }
  | { status: "error" }
  | {
      status: "ready";
      intro: string;
      documents: ReportDocument[];
      markdown: string;
      loadingSaved: boolean;
      deliverable: boolean;
    };

function reportDirectory(documents: ReportDocument[], linkToSections: boolean) {
  if (documents.length === 0) return "";
  return [
    "## 漏洞目录",
    "",
    "| 编号 | 漏洞名称 | 漏洞等级 |",
    "| --- | --- | --- |",
    ...documents.map(({ findingId, title, severity }) => {
      const name = linkToSections ? `[${title}](#finding-${findingId})` : title;
      return `| #${findingId} | ${name} | ${severity} |`;
    }),
  ].join("\n");
}

function taskDeliveryReport(taskId: string, closed: boolean, documents: ReportDocument[]): ReportState {
  const loadingSaved = documents.some(({ delivery }) => delivery === "loading");
  const savedCount = documents.filter(({ delivery }) => delivery === "saved").length;
  const missingCount = documents.filter(({ delivery }) => delivery === "missing").length;
  const unavailableCount = documents.filter(({ delivery }) => delivery === "unavailable").length;
  const detailedCount = documents.filter(({ detailed }) => detailed === true).length;
  const detailedMissingCount = documents.filter(({ detailed }) => detailed === false).length;
  const detailedUnknownCount = documents.length - detailedCount - detailedMissingCount;
  const deliverable = closed && documents.every(({ delivery, issues }) => delivery === "saved" && issues?.length === 0);
  const deliverySummary = `交付报告已保存 ${savedCount} 份，未保存 ${missingCount} 份${unavailableCount ? `，读取失败 ${unavailableCount} 份` : ""}。`;
  const detailedSummary = `详细报告已保存 ${detailedCount} 份，未保存 ${detailedMissingCount} 份${detailedUnknownCount ? `，状态未知 ${detailedUnknownCount} 份` : ""}。`;
  const reportSummary = loadingSaved ? "正在读取报告保存状态。" : `${deliverySummary}${detailedSummary}`;
  const intro = [
    deliverable ? "# 任务交付报告" : "# 任务报告草稿",
    `任务 #${taskId} · ${closed ? "截止汇总" : "当前汇总"} · 共纳入 ${documents.length} 项登记发现`,
    documents.length === 0 ? "当前任务没有已登记的发现。报告范围以已保存的测试记录为准。" : reportSummary,
  ].join("\n\n");
  const copyIntro = [intro, reportDirectory(documents, false)].filter(Boolean).join("\n\n");
  const annotatedDocuments = documents.map(withReportStatus);
  return {
    status: "ready",
    intro: [intro, reportDirectory(documents, true)].filter(Boolean).join("\n\n"),
    documents: annotatedDocuments,
    markdown: [copyIntro, ...annotatedDocuments.map(({ markdown }) => markdown)].join("\n\n---\n\n"),
    loadingSaved,
    deliverable,
  };
}

function withReportStatus(document: ReportDocument): ReportDocument {
  const deliveryStatus: Record<DeliveryState, string> = {
    loading: "正在读取交付报告，以下为登记摘要。",
    saved: "交付报告已保存。",
    missing: "交付报告未保存，以下为登记摘要。",
    unavailable: "交付报告读取失败，以下为登记摘要。",
  };
  const detailedStatus = document.detailed ? "详细报告已保存。" : "详细报告未保存。";
  const status = deliveryStatus[document.delivery] + (document.detailed === undefined ? "" : detailedStatus);
  const issues = document.issues?.length ? `草稿待补齐：${document.issues.join("、")}。` : "";
  return {
    ...document,
    markdown: document.markdown.replace("\n\n", `\n\n> ${status}${issues}\n\n`),
  };
}

async function loadTaskDeliveryReport(
  taskId: string,
  closed: boolean,
  signal: AbortSignal,
  publish: (report: ReportState) => void,
) {
  if (!/^[1-9]\d*$/.test(taskId) || BigInt(taskId) > BigInt("9223372036854775807")) {
    throw new Error("任务编号无效");
  }

  const findings = new Map<string, Finding>();
  for (let page = 1; ; page++) {
    const response = await api.findingsPage({ task: taskId, page, pageSize: 100, sort: "severity" }, signal);
    for (const item of response.items ?? []) {
      if (item.task_id === taskId && item.finding_id && /^[1-9]\d*$/.test(item.finding_id)) {
        findings.set(item.finding_id, item);
      }
    }
    if (!response.items?.length || page * response.page_size >= response.total) break;
  }

  const items = [...findings];
  const documents: ReportDocument[] = items.map(([id, finding]) => ({
    ...formatRecordedFindingReport(id, finding),
    delivery: "loading",
  }));
  signal.throwIfAborted();
  publish(taskDeliveryReport(taskId, closed, documents));
  if (documents.length === 0) return;

  const parallelRequests = 6;
  for (let start = 0; start < items.length; start += parallelRequests) {
    signal.throwIfAborted();
    const batch = await Promise.allSettled(
      items.slice(start, start + parallelRequests).map(async ([id, finding], index): Promise<ReportDocument> => {
        const saved = await api.findingDeliveryReport(taskId, id, signal);
        const recorded = documents[start + index];
        const detailed = saved.has_detailed_report;
        if (!saved.exists) return { ...recorded, delivery: "missing", detailed };
        const {
          markdown: report,
          severity,
          issues,
        } = prepareDeveloperDeliveryReport(saved.content, {
          name: finding.name,
          category: finding.vulnclass,
          summary: finding.summary,
          findingId: id,
          cvssVector: saved.cvss_vector,
          reportEvidenceVersion: saved.evidence_version,
          currentEvidenceVersion: saved.current_evidence_version,
          burpPackageAvailable: (finding.traffic_count ?? 0) > 0,
          hasDetailedReport: detailed,
        });
        if (!report) return { ...recorded, delivery: "missing", detailed };
        const title = report.slice(2, report.indexOf("\n"));
        const section = report.replace(/^(#{1,3})(?= )/gm, "$1#").replace(/^## /, `## #${id} · `);
        return {
          findingId: id,
          title,
          severity,
          delivery: "saved",
          detailed,
          issues,
          markdown: section,
        };
      }),
    );
    for (const [index, result] of batch.entries()) {
      const offset = start + index;
      documents[offset] =
        result.status === "fulfilled" ? result.value : { ...documents[offset], delivery: "unavailable" };
    }
  }

  signal.throwIfAborted();
  publish(taskDeliveryReport(taskId, closed, documents));
}

export function ReportTab({ task }: { task: Task }) {
  const taskId = task.id;
  const deadline = Date.parse(task.deadline_at ?? "");
  const closed =
    ["done", "failed", "timeout"].includes(task.status) ||
    task.run_window_status === "closed" ||
    deadline <= Date.now();
  const [state, setState] = React.useState<ReportState>({ status: "loading" });
  const activeRequest = React.useRef<AbortController | null>(null);

  const refresh = React.useCallback(() => {
    activeRequest.current?.abort();
    const controller = new AbortController();
    activeRequest.current = controller;
    setState({ status: "loading" });
    void loadTaskDeliveryReport(taskId, closed, controller.signal, setState).catch(() => {
      if (!controller.signal.aborted) setState({ status: "error" });
    });
  }, [taskId, closed]);

  React.useEffect(() => {
    refresh();
    return () => activeRequest.current?.abort();
  }, [refresh]);

  const deliverable = state.status === "ready" && state.deliverable;
  return (
    <Card>
      <CardHeader className="flex flex-row flex-wrap items-center justify-start gap-2">
        <CopyButton
          text={state.status === "ready" ? state.markdown : undefined}
          label={deliverable ? "复制交付报告" : "复制报告草稿"}
          successMessage={deliverable ? "已复制任务交付报告" : "已复制任务报告草稿"}
        />
        <Button type="button" size="sm" variant="outline" disabled={state.status === "loading"} onClick={refresh}>
          刷新报告
        </Button>
      </CardHeader>
      <CardContent className="mx-auto w-full max-w-5xl pb-4 [&_hr]:my-6 [&_p]:my-2">
        {state.status === "loading" && (
          <p role="status" className="py-12 text-center text-muted-foreground text-sm">
            正在加载交付报告…
          </p>
        )}
        {state.status === "error" && (
          <Alert variant="destructive">
            <AlertDescription>交付报告加载失败，请刷新重试。</AlertDescription>
          </Alert>
        )}
        {state.status === "ready" ? (
          <>
            {state.loadingSaved ? (
              <p role="status" className="text-muted-foreground text-sm">
                正在读取已保存的分项报告，当前可复制草稿。
              </p>
            ) : null}
            <Markdown text={state.intro} variant="report" />
            {state.documents.map((document) => (
              <section
                key={document.findingId}
                id={`finding-${document.findingId}`}
                className="scroll-mt-44 space-y-2 border-t pt-4"
              >
                <Markdown text={document.markdown} variant="report" />
                <Link
                  href={`/function/findings/detail?id=${document.findingId}&context_task=${taskId}${document.detailed ? "#detailed-report" : ""}`}
                  className="text-sm underline underline-offset-4"
                >
                  {document.detailed ? "查看详细报告" : "查看漏洞详情"}
                </Link>
              </section>
            ))}
          </>
        ) : null}
      </CardContent>
    </Card>
  );
}
