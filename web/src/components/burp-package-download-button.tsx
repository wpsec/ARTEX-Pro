"use client";

import * as React from "react";

import { DownloadIcon } from "lucide-react";

import { Button } from "@/components/ui/button";
import { api } from "@/lib/api";

export function BurpPackageDownloadButton({ taskId, findingId }: { taskId: string; findingId: string }) {
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState("");

  const download = async () => {
    setLoading(true);
    setError("");
    try {
      await api.downloadFindingBurpPackage(taskId, findingId);
    } catch (cause) {
      setError((cause as Error).message || "Burp 复测包下载失败");
    } finally {
      setLoading(false);
    }
  };

  return (
    <span className="inline-flex flex-col items-end gap-1">
      <Button type="button" size="sm" variant="outline" disabled={loading} onClick={download}>
        <DownloadIcon />
        {loading ? "正在打包…" : "下载 Burp 复测包"}
      </Button>
      {error ? (
        <span role="alert" className="max-w-xs text-right text-destructive text-xs">
          {error}
        </span>
      ) : null}
    </span>
  );
}
