import { CopyButton } from "@/components/copy-button";
import { Markdown } from "@/components/markdown";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { prepareDeveloperDeliveryReport } from "@/lib/delivery-report";

export function DeliveryReportSection({
  content,
  name,
  category,
  summary,
  findingId,
  trafficCount,
  cvssVector,
  reportEvidenceVersion,
  currentEvidenceVersion,
  stale,
  hasDetailedReport,
}: {
  content?: string;
  name?: string;
  category?: string;
  summary?: string;
  findingId?: string;
  trafficCount?: number;
  cvssVector?: string;
  reportEvidenceVersion?: number;
  currentEvidenceVersion?: number;
  stale?: boolean;
  hasDetailedReport: boolean;
}) {
  const burpPackageAvailable = (trafficCount ?? 0) > 0;
  const { markdown: report, issues } = prepareDeveloperDeliveryReport(content ?? "", {
    name,
    category,
    summary,
    findingId,
    cvssVector,
    reportEvidenceVersion,
    currentEvidenceVersion,
    burpPackageAvailable,
    hasDetailedReport,
    stale,
  });
  const reviewNotice = issues.length ? `报告草稿：${issues.join("、")}。` : "";
  const copyText = reviewNotice ? `> ${reviewNotice}\n\n${report}` : report;

  return (
    <Card>
      {report ? (
        <CardHeader className="flex-row flex-wrap items-center justify-start gap-2">
          <CopyButton
            text={copyText}
            label={reviewNotice ? "复制报告草稿" : "复制交付报告"}
            successMessage={reviewNotice ? "已复制报告草稿" : "已复制交付报告"}
          />
        </CardHeader>
      ) : null}
      <CardContent className="space-y-3">
        {report && reviewNotice ? (
          <Alert>
            <AlertDescription>{reviewNotice}</AlertDescription>
          </Alert>
        ) : null}
        {report ? <Markdown text={report} /> : <p className="text-muted-foreground text-sm">交付报告尚未保存。</p>}
      </CardContent>
    </Card>
  );
}
