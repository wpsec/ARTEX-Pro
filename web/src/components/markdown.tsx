"use client";

import * as React from "react";

import ReactMarkdown, { type Components } from "react-markdown";
import remarkGfm from "remark-gfm";

import { CopyButton } from "@/components/copy-button";

// Tailwind-styled element overrides (no typography plugin in this project, so we
// style each element). `node` is stripped — it's not a valid DOM attribute.
const components: Components = {
  h1: ({ node, ...p }) => <div className="mt-2.5 text-base font-semibold" {...p} />,
  h2: ({ node, ...p }) => <div className="mt-2 text-sm font-semibold" {...p} />,
  h3: ({ node, ...p }) => <div className="mt-1.5 text-sm font-medium text-foreground/90" {...p} />,
  h4: ({ node, ...p }) => <div className="mt-1.5 text-sm font-medium text-foreground/90" {...p} />,
  p: ({ node, ...p }) => <p className="leading-relaxed" {...p} />,
  ul: ({ node, ...p }) => <ul className="my-1 list-disc space-y-0.5 pl-5" {...p} />,
  ol: ({ node, ...p }) => <ol className="my-1 list-decimal space-y-0.5 pl-5" {...p} />,
  strong: ({ node, ...p }) => <strong className="font-semibold" {...p} />,
  a: ({ node, href, ...p }) => (
    <a
      className="text-primary underline underline-offset-2"
      href={href}
      target={href?.startsWith("#") ? undefined : "_blank"}
      rel="noreferrer"
      {...p}
    />
  ),
  hr: () => <hr className="my-2 border-border" />,
  blockquote: ({ node, ...p }) => (
    <blockquote className="my-1 border-l-2 border-border pl-2.5 text-muted-foreground" {...p} />
  ),
  pre: ({ node, ...p }) => (
    <pre className="my-1.5 overflow-auto rounded-md bg-muted/70 p-2.5 text-xs leading-relaxed" {...p} />
  ),
  code: ({ node, className, children, ...rest }) => {
    const block = /language-/.test(className || "");
    return block ? (
      <code className={"font-mono text-xs " + (className || "")} {...rest}>
        {children}
      </code>
    ) : (
      <code className="break-all rounded bg-muted px-1 py-0.5 font-mono text-[0.85em]" {...rest}>
        {children}
      </code>
    );
  },
  table: ({ node, ...p }) => (
    <div className="my-1.5 overflow-x-auto">
      <table className="w-full border-collapse text-xs" {...p} />
    </div>
  ),
  th: ({ node, ...p }) => <th className="border border-border bg-muted/60 px-2 py-1 text-left font-medium" {...p} />,
  td: ({ node, ...p }) => <td className="border border-border px-2 py-1 align-top" {...p} />,
};

const reportComponents: Components = {
  ...components,
  h1: ({ node, ...p }) => <h2 className="mb-2 font-semibold text-xl" {...p} />,
  h2: ({ node, ...p }) => <h3 className="mt-5 mb-2 font-semibold text-base" {...p} />,
  h3: ({ node, ...p }) => <h4 className="mt-4 font-semibold text-sm" {...p} />,
  h4: ({ node, ...p }) => <h5 className="mt-3 font-medium text-muted-foreground text-sm" {...p} />,
};

function reproductionCopyAction(language: string | undefined) {
  if (language === "python") {
    return { label: "复制脚本", successMessage: "已复制 Python 复现脚本" };
  }
  if (language === "http") {
    return { label: "复制 Burp 数据包", successMessage: "已复制 Burp HTTP 数据包" };
  }
  return undefined;
}

const copyReproductionComponents: Components = {
  ...components,
  pre: ({ node, children, ...p }) => {
    const codeNode = React.Children.toArray(children)[0];
    const code = React.isValidElement(codeNode)
      ? (codeNode as React.ReactElement<{ className?: string; children?: React.ReactNode }>)
      : undefined;
    const language = /language-([\w-]+)/.exec(code?.props.className ?? "")?.[1]?.toLowerCase();
    const copyAction = reproductionCopyAction(language);
    const codeText = typeof code?.props.children === "string" ? code.props.children.replace(/\r?\n$/, "") : "";

    if (!copyAction || !codeText.trim()) {
      return (
        <pre className="my-1.5 overflow-auto rounded-md bg-muted/70 p-2.5 text-xs leading-relaxed" {...p}>
          {children}
        </pre>
      );
    }

    return (
      <div className="my-1.5 overflow-hidden rounded-md bg-muted/70">
        <div className="flex justify-end border-border/70 border-b px-2 py-1">
          <CopyButton
            text={codeText}
            label={copyAction.label}
            successMessage={copyAction.successMessage}
            size="sm"
            variant="ghost"
            className="h-7 px-2"
          />
        </div>
        <pre {...p} className="m-0 overflow-auto bg-transparent p-2.5 text-xs leading-relaxed">
          {children}
        </pre>
      </div>
    );
  },
};

export function Markdown({
  text,
  variant,
  copyReproductionBlocks = false,
}: {
  text: string;
  variant?: "report";
  copyReproductionBlocks?: boolean;
}) {
  let markdownComponents = components;
  if (variant === "report") markdownComponents = reportComponents;
  if (copyReproductionBlocks) markdownComponents = copyReproductionComponents;

  return (
    <div className="min-w-0 space-y-1.5 text-sm [&>*:first-child]:mt-0">
      <ReactMarkdown remarkPlugins={[remarkGfm]} components={markdownComponents}>
        {text}
      </ReactMarkdown>
    </div>
  );
}
