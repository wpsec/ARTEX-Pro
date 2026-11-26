import { scoreCVSS4Base } from "./cvss-v4";
import { statusMeta } from "./status";
import type { Finding } from "./types";

type ReportSection =
  | "description"
  | "location"
  | "scope"
  | "process"
  | "chain"
  | "remediation"
  | "acceptance"
  | "reproduction"
  | "python";

const repairVerificationTitle = "修复后验证";
const repairVerificationLabel = `**${repairVerificationTitle}**`;
const sectionNames = new Map<string, ReportSection>([
  ["描述", "description"],
  ["漏洞描述", "description"],
  ["测试过程", "process"],
  ["发现过程与攻击思路", "process"],
  ["影响链路", "chain"],
  ["攻击链路", "chain"],
  ["修复", "remediation"],
  ["修复建议", "remediation"],
  ["复测标准", "acceptance"],
  ["修复验收", "acceptance"],
  [repairVerificationTitle, "acceptance"],
  ["Burp 复现", "reproduction"],
  ["Burp 复现包", "reproduction"],
  ["复现记录", "reproduction"],
  ["复现脚本（Python）", "python"],
  ["POC 脚本（Python）", "python"],
]);

const pythonSourceLocation = /^(?:[a-z0-9_][a-z0-9_.-]*\/)*[a-z0-9_][a-z0-9_.-]*\.py(?::[1-9]\d*)?$/i;
const burpStatus =
  /^(?:本次\s*)?(未|已)(?:在|通过)\s*Burp(?:\s+Suite)?(?:\s+Repeater)?\s*(?:中\s*)?(?:完成)?(?:验证|复测)(?=\s*(?:[。！？.，,；;]|$))/i;
const locationLine = /^(?:[-*+]\s+)?(?:触发位置[：:]|\*\*触发位置(?:[：:]\*\*|\*\*[：:]))\s*(.*)$/;
const reportFieldLine = /^(?:[-*+]\s+)?(?:\*\*)?([^：:*]+)(?:\*\*)?[：:](?:\*\*)?\s*(.*)$/;
const requiredTestFacts = ["测试角色", "预期行为", "实际结果"];
const testFactsMarker = "<!-- artex:developer-test-facts-v1 -->";
const reportFieldsMarker = "<!-- artex:developer-report-fields-v1 -->";
const chainStage = /^(入口|校验缺口|实际影响)[：:]\s*/;
const implementationOnly =
  /^(?:源码位置(?:与(?:现有|当前|具体)实现)?|(?:现有|当前|具体)实现|根因)(?:尚未|未|待)(?:核实|确认|定位|验证)[。！？；]?$/;
const appendixMarker = /^(?:\\)?<!--\s*artex:bound-traffic-evidence\s*-->(?:\\)?$/;
const packetFence = /^(?:http|https|curl)(?:\s|$)/i;
const requestLine = /(?:^|[\s`])(?:GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS|CONNECT|TRACE)\s+(?:\/|https?:|\*)/i;
const credentials =
  /\b(?:authorization|proxy-authorization|cookie|set-cookie|token|api[-_ ]?key|password)\s*[:=]|\bbearer\s+\S|(?:密码|令牌|密钥|凭据)\s*[:：=]/i;
const tooling =
  /(?:^|\s)(?:curl|wget|python[23]?|bash|sh|powershell|ncat|sqlmap)\s+|\bHTTP\/\d|[├└│]|<[^>]+>|\]\(|https?:\/\/|\[[^\]]+\]|\{[^}]+\}/i;
const hostOrPath =
  /(?:\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[a-z0-9-]+(?:\.[a-z0-9-]+)+\.[a-z]{2,}\b)|(?:^|\s|[（(：:])(?:[a-z]:\\|\.{0,2}\/)[^\s。]+/i;
const internalNotes =
  /(?:证据|对照|判据|属主|所有者(?:是|为|等于)|字节|上传腿|(?:首轮|次轮|第[一二三四五六七八九十\d]+轮)上传|\bseq\b|\bsha(?:1|256|512)\b|\b(?:差分|阴性)\b)/i;
const processOutcome =
  /观察到|测试(?:中|时|记录)?(?:发现|确认|显示)|(?:成功|未能)(?:读取|访问|修改|创建|删除|执行)|返回了?|仍然|仍可|拒绝|未验证|未覆盖|不属于|超出|重复|无权|未登录|权限不足/;
const scopeCondition =
  /普通用户|低权限|管理员|已登录|未登录|拥有权限|只在|仅在|仅限|仅证明|仅表明|仅观察到|前提是|仅能|只能|未能|未见|未读取|未获得|未复现|没有(?:取得|读取|返回|看到|发现)|未(?:出现|返回|执行|发生|验证|覆盖|测试|检查)|尚未(?:核实|验证)|无法确认|不足以确认|不代表|不能(?:确认|说明|证明)/;
const expectedBehavior =
  /预期|修复后|应(?:当|能|可|仅|被|继续|正常|成功|拒绝|禁止|返回|保持|停止|阻止|校验|限制|记录|失效)|不应|不再|不得|仍(?:可|能|然)|可(?:正常|继续)|无法(?:读取|访问|修改|执行)|不能(?:读取|访问|修改|执行)|保持不变/;
const testExpectation = /^预期/;
const processInstruction =
  /^(?:第[一二三四五六七八九十\d]+步|步骤|先|然后|接着|再次|通过以下|向.+发送|发送|发起|请求(?!(?:已|未)?被拒绝)|调用|执行|运行(?!会话)|替换|构造|将.+(?:改|换)为|在.+(?:输入|运行(?!会话)|发送))|(?:按顺序|参数(?:设置|改为)|请求体|请求头)/;
const packetOrCommandLine = /^(?:(?:host|content-type|content-length|user-agent|referer)\s*:|[{}]|\$\s)/i;

type BoundHTTPRequest = {
  url: string;
  method: string;
  headers: [string, string][];
  body: string;
  bodyBase64?: string;
  packet: string;
};

function unescapeEvidenceMetadata(value: string) {
  return value
    .replaceAll("&lt;", "<")
    .replaceAll("&gt;", ">")
    .replaceAll("&#34;", '"')
    .replaceAll("&#39;", "'")
    .replaceAll("&amp;", "&")
    .replaceAll("\\_", "_")
    .replaceAll("\\[", "[")
    .replaceAll("\\]", "]")
    .replaceAll("\\*", "*")
    .replaceAll("\\`", "`")
    .replaceAll("\\{", "{")
    .replaceAll("\\}", "}")
    .replaceAll("\\<", "<")
    .replaceAll("\\>", ">")
    .replaceAll("\\|", "|")
    .replaceAll("\\\\", "\\")
    .replaceAll("\\r", "\r")
    .replaceAll("\\n", "\n");
}

function parseBoundHTTPRequest(urlValue: string, packet: string): BoundHTTPRequest | undefined {
  const urlText = unescapeEvidenceMetadata(urlValue.trim());
  let url: URL;
  try {
    url = new URL(urlText);
  } catch {
    return undefined;
  }
  if ((url.protocol !== "http:" && url.protocol !== "https:") || !url.hostname) return undefined;

  const separator = packet.includes("\r\n\r\n") ? "\r\n\r\n" : "\n\n";
  const separatorIndex = packet.indexOf(separator);
  if (separatorIndex < 0) return undefined;
  const headerText = packet.slice(0, separatorIndex);
  const body = packet.slice(separatorIndex + separator.length);
  const [requestLine, ...headerLines] = headerText.split(/\r?\n/);
  const request = /^([A-Z]+)\s+\S+\s+HTTP\/\d(?:\.\d)?$/i.exec(requestLine ?? "");
  if (!request) return undefined;

  const headers: [string, string][] = [];
  for (const line of headerLines) {
    const match = /^([^:\s]+):[ \t]*(.*)$/.exec(line);
    if (!match) return undefined;
    headers.push([match[1], match[2]]);
  }

  const binaryBody =
    /^\[二进制正文，原始长度 \d+ 字节；以下为原始字节的 Base64 编码\]\r?\n([A-Za-z0-9+/=\r\n]*)\s*$/.exec(body);
  if (binaryBody) {
    return {
      url: urlText,
      method: request[1].toUpperCase(),
      headers,
      body: "",
      bodyBase64: binaryBody[1].replace(/\s/g, ""),
      packet,
    };
  }
  if (body === "[该方向的 HTTP 报文未留存]") return undefined;
  return { url: urlText, method: request[1].toUpperCase(), headers, body, packet };
}

function boundHTTPRequestForReplay(content: string): BoundHTTPRequest | undefined {
  const marker = "<!-- artex:bound-traffic-evidence -->";
  const markerIndex = content.indexOf(marker);
  if (markerIndex < 0) return undefined;
  const appendix = content.slice(markerIndex + marker.length);
  const bindingPattern = /(?:^|\n)#### 证据绑定 \d+（([^）]+)）\s*\r?\n/g;
  const blocks: { role: string; text: string }[] = [];
  const starts = [...appendix.matchAll(bindingPattern)];
  for (const [index, match] of starts.entries()) {
    const blockStart = (match.index ?? 0) + match[0].length;
    const blockEnd = starts[index + 1]?.index ?? appendix.length;
    blocks.push({ role: match[1], text: appendix.slice(blockStart, blockEnd) });
  }

  let fallback: BoundHTTPRequest | undefined;
  for (const block of blocks) {
    const urlMatch = /^- 请求地址：[ \t]*(.+)$/m.exec(block.text);
    const requestHeading = block.text.indexOf("##### 请求包");
    const responseHeading = block.text.indexOf("##### 响应包", requestHeading + 1);
    const requestSection =
      requestHeading >= 0 && responseHeading > requestHeading
        ? block.text.slice(requestHeading + "##### 请求包".length, responseHeading)
        : "";
    if (!urlMatch || !requestSection) continue;
    const packetMatch = /(?:^|\n)(`{3,})http[ \t]*\r?\n([\s\S]*?)\r?\n\1[ \t]*(?:\r?$|\n)/i.exec(requestSection);
    if (!packetMatch) continue;
    // The server adds the fence separator after the stored packet. Preserve the
    // packet's terminating blank line so header-only requests remain parseable.
    const packet = packetMatch[2];
    const parsed = parseBoundHTTPRequest(urlMatch[1], packet);
    if (!parsed || /测试基线/.test(block.role)) continue;
    if (/漏洞验证|复核证据/.test(block.role)) return parsed;
    fallback ??= parsed;
  }
  return fallback;
}

function pythonString(value: string) {
  return JSON.stringify(value).replace(/[\u2028\u2029]/g, (char) => (char === "\u2028" ? "\\u2028" : "\\u2029"));
}

function renderPythonReplayScript(request: BoundHTTPRequest) {
  const headers = JSON.stringify(request.headers, null, 4);
  let body = "None";
  if (request.bodyBase64) body = `base64.b64decode(${pythonString(request.bodyBase64)})`;
  else if (request.body) body = `${pythonString(request.body)}.encode("utf-8")`;
  return [
    "# 默认直连；设置 BURP_PROXY 后才经 Burp 发送。",
    "# 示例：BURP_PROXY=http://127.0.0.1:8080 python3 replay.py",
    "# HTTPS 拦截时，可通过 BURP_CA_CERT 指向 Burp CA PEM 证书。",
    "# 显式配置的代理不可用时会报错，不会回退直连。",
    "import base64",
    "import http.client",
    "import os",
    "import ssl",
    "import sys",
    "from urllib.parse import urlsplit",
    "",
    `TARGET_URL = ${pythonString(request.url)}`,
    `METHOD = ${pythonString(request.method)}`,
    `HEADERS = ${headers}`,
    `BODY = ${body}`,
    "",
    "def main():",
    "    target = urlsplit(TARGET_URL)",
    "    target_host = target.hostname",
    '    target_port = target.port or (443 if target.scheme == "https" else 80)',
    '    target_path = target.path or "/"',
    "    if target.query:",
    '        target_path += "?" + target.query',
    '    proxy_text = os.environ.get("BURP_PROXY", "").strip()',
    "    proxy = None",
    "    if proxy_text:",
    '        proxy = urlsplit(proxy_text if "://" in proxy_text else "http://" + proxy_text)',
    '        if proxy.scheme != "http" or not proxy.hostname:',
    '            raise SystemExit("BURP_PROXY 须为 http:// 主机:端口")',
    '    if target.scheme == "https":',
    "        context = ssl.create_default_context()",
    '        ca_file = os.environ.get("BURP_CA_CERT", "").strip()',
    "        if ca_file:",
    "            context.load_verify_locations(cafile=ca_file)",
    "        if proxy:",
    "            connection = http.client.HTTPSConnection(proxy.hostname, proxy.port or 8080, timeout=30, context=context)",
    "            connection.set_tunnel(target_host, target_port)",
    "        else:",
    "            connection = http.client.HTTPSConnection(target_host, target_port, timeout=30, context=context)",
    '    elif target.scheme == "http":',
    "        connection = http.client.HTTPConnection(proxy.hostname, proxy.port or 8080, timeout=30) if proxy else http.client.HTTPConnection(target_host, target_port, timeout=30)",
    "        if proxy:",
    '            target_path = target.scheme + "://" + target.netloc + target_path',
    "    else:",
    '        raise SystemExit("仅支持 HTTP/HTTPS 证据")',
    "",
    '    captured_host = any(name.lower() == "host" for name, _ in HEADERS)',
    "    connection.putrequest(METHOD, target_path, skip_host=captured_host, skip_accept_encoding=True)",
    "    had_content_length = False",
    "    for name, value in HEADERS:",
    "        lowered = name.lower()",
    '        if lowered == "transfer-encoding":',
    "            continue",
    '        if lowered == "content-length":',
    "            had_content_length = True",
    "            continue",
    "        connection.putheader(name, value)",
    "    if BODY is not None:",
    '        connection.putheader("Content-Length", str(len(BODY)))',
    "    elif had_content_length:",
    '        connection.putheader("Content-Length", "0")',
    "    connection.endheaders(BODY)",
    "    response = connection.getresponse()",
    '    print(f"HTTP {response.status} {response.reason}")',
    "    for name, value in response.getheaders():",
    '        print(f"{name}: {value}")',
    '    sys.stdout.buffer.write(b"\\n" + response.read())',
    "    connection.close()",
    "",
    'if __name__ == "__main__":',
    "    main()",
  ].join("\n");
}

const inlineValue = /`[^\s`]*[:=/][^`]*`|\b[a-f0-9]{24,}\b/i;
const quotedEndpoint = /[ \t]*`(?:GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS)\s+\/[^\s`]+`[ \t]*/gi;
const quotedPath = /[ \t]*`\/(?!\/)[^\s`]+`[ \t]*/g;
const quotedSourceLocation =
  /`((?:[a-z0-9_][a-z0-9_.-]*\/)*[a-z0-9_][a-z0-9_.-]*\.(?:go|tsx?|jsx?|py|java|kt|rs|cs|rb|php|vue|svelte|cpp|cc|c|h|hpp):[1-9]\d{0,6}(?::[1-9]\d{0,6})?)`/gi;

function simplifyRepairExpectation(prose: string) {
  return prose
    .replace(/^修复后[^，,。]*重放[^，,。]*[，,]\s*/, "修复后")
    .replace(/[（(]\s*`[^`]+`\s*[）)]/g, "")
    .replace(
      /(?:文件(?:的)?(?:具体)?|具体)?属主(?:\s*(?:为|是|等于|[：:=])\s*(?:`[^`]+`|[^\s，。！？；、和及与]+))?/g,
      "文件所有者信息",
    )
    .replace(
      /((?:不再|不得|不应)返回)[^，,。！？；]*`(?!0`)[^`]+`[^，,。！？；]*字节(?:的)?(?:正文|内容|数据|响应|文件)?/g,
      "$1先前记录中的内容",
    )
    .replace(/(响应|返回|读取|显示)\s*`(?!\d+`)[^`]+`(?=\s*(?:\d+\s*)?字节)/g, "$1")
    .replace(/\s*(?:`0`|\b0|零)\s*字节/g, "空内容")
    .replace(/\s*(?:`\d+`|\d+)\s*字节(?:的)?(?=正文|内容|数据|响应|文件|业务文件)/g, "先前记录中的")
    .replace(/\s*(?:`\d+`|\d+)\s*字节/g, "先前记录中的内容")
    .replace(/文件字节/g, "文件内容")
    .replace(/(返回|读取)\s*字节/g, "$1对应内容");
}

function takeProse(lines: string[], mode: ReportSection, structured = false): string[] {
  const sentences = new Set<string>();
  for (const line of lines) {
    const value = line.replace(/^\s*(?:[-*+]|\d+[.)、])\s*/, "").trim();
    if (!value || packetOrCommandLine.test(value)) continue;
    for (const source of value.match(/[^。！？；]+[。！？；]?/g) ?? []) {
      const explicitObservation = /^(?:观察结果|实际结果|测试结果|结果|已观察到)[：:]\s*/.exec(source.trim());
      const stage = mode === "chain" ? chainStage.exec(source.trim()) : null;
      const prefix = explicitObservation ?? stage;
      const sentence = prefix ? source.trim().slice(prefix[0].length) : source;
      let prose = sentence
        .trim()
        .replace(/[（(]\s*(?:seq\s*[\d\s–—-]+|\d+\s*字节)\s*[）)]/gi, "")
        .replace(/逐字节(?:完全)?相同/g, "相同")
        .replace(/^(?:根据|依据)(?:现有|已有|当前)?证据[，,]\s*/, "")
        .replace(/证据(?:不足以证明|尚不足以证明)/g, "尚不足以确认")
        .replace(/(?:现有|已有)?证据(?:表明|显示)/g, "测试显示");
      if (mode === "scope") {
        prose = prose.replace(/^\s*(?:PR|UI|VC|VI|VA|SC|SI|SA)[:：][A-Z]\s*[，,：:]\s*/, "");
      }
      if (mode === "process") prose = prose.replace(/^(?:独立)?对照(?:检查|测试)?[：:]\s*/, "");
      if (mode === "chain") {
        prose = prose
          .replace(/^(?:HTTP\s*)?[1-5]\d{2}(?:[：:]\s*|\s+(?=返回|拒绝))/i, "")
          .replace(/\s*\b[1-9]\d*\s*(?:B|KB|MB)\b\s*的\s*/gi, "");
      }
      if (mode === "description" || mode === "process" || mode === "remediation" || mode === "acceptance") {
        prose = prose.replace(quotedEndpoint, "相关接口").replace(quotedPath, "相关路径");
      }
      if (mode === "acceptance") prose = simplifyRepairExpectation(prose);
      if (mode === "remediation" && implementationOnly.test(prose)) continue;
      // A source file and line help locate the fix without publishing test inputs.
      const proseForChecks = mode === "remediation" ? prose.replace(quotedSourceLocation, "") : prose;
      if (
        !prose ||
        [internalNotes, requestLine, credentials, tooling, hostOrPath, inlineValue].some((rule) =>
          rule.test(proseForChecks),
        )
      ) {
        continue;
      }
      if (!structured && mode !== "remediation" && processInstruction.test(prose)) continue;
      if (mode === "scope" && !scopeCondition.test(prose)) continue;
      if (!structured && mode === "acceptance" && !expectedBehavior.test(prose)) continue;
      if (
        (mode === "process" || mode === "chain") &&
        !stage &&
        !explicitObservation &&
        !processOutcome.test(prose) &&
        !scopeCondition.test(prose) &&
        !(mode === "process" && testExpectation.test(prose))
      ) {
        continue;
      }
      if (stage) prose = `${stage[1]}：${prose}`;
      sentences.add(mode === "remediation" ? prose.replace(quotedSourceLocation, "$1") : prose);
    }
  }
  return [...sentences];
}

function readReportFields(lines: string[]) {
  const fields = new Map<string, string[]>();
  let label = "";
  let parts: string[] = [];
  const flush = () => {
    if (label && parts.length) fields.set(label, [...(fields.get(label) ?? []), parts.join(" ")]);
    label = "";
    parts = [];
  };
  for (const line of lines) {
    const trimmed = line.trim();
    if (label && trimmed && line.startsWith("  ")) {
      parts.push(trimmed);
      continue;
    }
    flush();
    const field = reportFieldLine.exec(trimmed);
    if (!field) continue;
    label = field[1].trim();
    if (field[2].trim()) parts.push(field[2].trim());
  }
  flush();
  return fields;
}

function readBurpVerification(lines: string[]) {
  const states = new Set<string>();
  for (const line of lines) {
    const status = line
      .trim()
      .replace(/^[-*+]\s+/, "")
      .replaceAll("**", "")
      .replace(/^Burp\s*验证状态[：:]\s*/i, "");
    const match = burpStatus.exec(status);
    if (match) states.add(match[1]);
  }
  if (states.size > 1) return "Burp 验证状态：原报告记录不一致，待核对。";
  if (states.has("已")) return "Burp 验证状态：已在 Burp 中验证。";
  if (states.has("未")) return "Burp 验证状态：未在 Burp 中验证。";
  return "";
}

function splitDeliveryReport(content: string) {
  const sections: Record<ReportSection, string[]> = {
    description: [],
    location: [],
    scope: [],
    process: [],
    chain: [],
    remediation: [],
    acceptance: [],
    reproduction: [],
    python: [],
  };
  let title = "";
  let section: ReportSection | undefined;
  let parent: ReportSection | undefined;
  let fence = "";
  let inChainFence = false;
  let httpRecorded = false;
  let httpExample = false;
  let nonHTTP = false;
  const markedSections = new Set<ReportSection>();

  const lines = content.split(/\r?\n/);
  for (const [index, line] of lines.entries()) {
    const fenceLine = /^\s*(`{3,}|~{3,})(.*)$/.exec(line);
    if (fenceLine) {
      const [, marker, suffix] = fenceLine;
      if (!fence) {
        if (section) sections[section].push("");
        fence = marker;
        inChainFence = section === "chain" && /^text\s*$/i.test(suffix.trim());
        if (section === "reproduction" && packetFence.test(suffix.trim())) httpExample = true;
      } else if (marker[0] === fence[0] && marker.length >= fence.length && !suffix.trim()) {
        fence = "";
        inChainFence = false;
      }
      continue;
    }
    if (fence) {
      if (inChainFence) {
        const node = /^[\s│]*[├└]─+\s*(.+)$/.exec(line)?.[1] ?? line.trim();
        if (node) sections.chain.push(node);
      }
      continue;
    }
    if (appendixMarker.test(line.trim())) {
      // The server also appends the marker when no traffic is bound.
      httpRecorded = lines[index + 1]?.trim() === "### 平台留存的 HTTP 请求与响应";
      break;
    }

    if (parent === "remediation" && line.trimEnd() === repairVerificationLabel) {
      section = "acceptance";
      continue;
    }
    const heading = /^ {0,3}(#{1,6})\s+(.+?)\s*#*\s*$/.exec(line);
    if (heading) {
      const level = heading[1].length;
      const name = heading[2].trim().replace(/[：:]$/, "");
      if (level === 1 && !title) title = name;
      const next = sectionNames.get(name);
      if (level <= 2) parent = next;
      section = next;
      if (level > 2 && parent === "description" && name === "定级依据") section = "scope";
      if (level > 2 && next !== "reproduction" && /未验证|未覆盖/.test(name)) section = parent;
      continue;
    }
    if (section === "reproduction" && /Burp\s*不适用/i.test(line)) nonHTTP = true;
    if (section === "process" && line.trim() === testFactsMarker) markedSections.add(section);
    if ((section === "description" || section === "remediation") && line.trim() === reportFieldsMarker) {
      markedSections.add(section);
    }
    if (!section) continue;
    if (/^\s{4}|^\s*>|^\s*<!--/.test(line)) {
      sections[section].push("");
      continue;
    }
    const location = section === "description" && !markedSections.has(section) ? locationLine.exec(line.trim()) : null;
    sections[location ? "location" : section].push(location?.[1] ?? line);
  }
  return { title, sections, httpRecorded, httpExample, nonHTTP, markedSections };
}

function escapeMarkdownText(value: string) {
  return value.replace(/[\\`*_{}[\]<>|]/g, "\\$&");
}

function deliveryReportTitle(...names: string[]) {
  return (
    names
      .map((name) => name.replace(/\s+/g, " ").trim())
      .find(
        (name) => name && ![requestLine, credentials, tooling, hostOrPath, internalNotes].some((r) => r.test(name)),
      ) ?? "漏洞报告"
  );
}

export function formatRecordedFindingReport(findingId: string, finding: Finding) {
  const title = escapeMarkdownText(deliveryReportTitle(finding.name ?? "", finding.vulnclass));
  const severity = escapeMarkdownText(statusMeta("severity", finding.severity).label);
  const status = escapeMarkdownText(statusMeta("finding", finding.status).label);
  const summary = takeProse(finding.summary.split(/\r?\n/), "description").map(escapeMarkdownText).join("\n\n");
  const evidenceStatus = {
    matched: "证据引用与平台留存记录匹配。",
    unmatched: "证据引用未能与平台留存记录匹配，相关结论仍需核对。",
    not_assessed: "证据引用尚未核对。",
  }[finding.evidence_check_status ?? "not_assessed"];

  return {
    findingId,
    title,
    severity,
    markdown: [
      `## #${findingId} · ${title}`,
      `登记等级：${severity} · 处置状态：${status}`,
      "CVSS 4.0：待评估",
      "向量：待评估",
      "### 漏洞描述",
      summary || "该发现已登记，现有摘要未提供可用于交付的现象或影响说明。",
      "已确认影响：登记摘要未单独记录已确认的业务影响，待核实。",
      "触发位置：待核实。",
      "### 测试过程",
      "- 测试角色：登记记录未提供，待核实。",
      "- 预期行为：登记记录未提供，待核实。",
      "- 实际结果：见漏洞描述中的登记摘要。",
      "- 未验证范围：此登记摘要中的影响范围及证据引用待核实。",
      evidenceStatus,
      "#### Burp 复现包",
      "未附完整原始 HTTP 请求报文。",
      "#### 攻击链路",
      "登记记录未提供可逐项确认的入口、校验缺口和实际影响，待核实。",
      "#### 复现脚本",
      "尚未提供完整的验证或复核请求，未生成复现脚本。",
      "### 修复建议",
      "请依据已记录的异常和证据核实受影响功能后，补充具体修复措施。",
      repairVerificationLabel,
      "- 修复后应确认异常行为已消除，且正常业务仍可使用。",
    ]
      .filter(Boolean)
      .join("\n\n"),
  };
}

type DeliveryReportOptions = {
  name?: string;
  category?: string;
  summary?: string;
  cvssVector?: string;
  findingId?: string;
  burpPackageAvailable?: boolean;
  reportEvidenceVersion?: number;
  currentEvidenceVersion?: number;
  hasDetailedReport?: boolean;
  stale?: boolean;
};

export function prepareDeveloperDeliveryReport(
  content: string,
  {
    name = "",
    category = "",
    summary = "",
    cvssVector = "",
    findingId = "",
    burpPackageAvailable = false,
    reportEvidenceVersion,
    currentEvidenceVersion,
    hasDetailedReport,
    stale,
  }: DeliveryReportOptions = {},
) {
  if (!content.trim()) return { markdown: "", severity: "待评估", issues: ["交付报告未保存"] };

  const { title, sections, httpRecorded, httpExample, nonHTTP, markedSections } = splitDeliveryReport(content);
  const displayName = deliveryReportTitle(name, title, category);
  const score = scoreCVSS4Base(cvssVector);
  const rating = score
    ? `CVSS 4.0：${score.score.toFixed(1)}（${score.severity}）\n\n向量：\`${score.vector}\``
    : "CVSS 4.0：待评估";
  const descriptionFields = markedSections.has("description") ? readReportFields(sections.description) : undefined;
  const description = takeProse(
    descriptionFields ? (descriptionFields.get("漏洞现象") ?? []) : sections.description,
    "description",
  );
  if (!descriptionFields) {
    if (!description.length && summary) description.push(...takeProse(summary.split(/\r?\n/), "description"));
    description.push(...takeProse(sections.scope, "scope").filter((sentence) => !description.includes(sentence)));
  }
  const location = takeProse(descriptionFields?.get("触发位置") ?? sections.location, "location");
  const testFacts = markedSections.has("process") ? readReportFields(sections.process) : undefined;
  const process = testFacts
    ? []
    : takeProse(sections.process, "process").filter((sentence) => !description.includes(sentence));
  const chain = takeProse(sections.chain, "chain").filter(
    (sentence) => !description.includes(sentence) && !process.includes(sentence),
  );
  if (!chain.length && process.length > 1 && !process.some((sentence) => testExpectation.test(sentence))) {
    const outcome = process.findIndex((sentence) => !/未验证|未覆盖|尚未/.test(sentence));
    if (outcome >= 0) chain.push(...process.splice(outcome, 1));
  }
  const remediationFields = markedSections.has("remediation") ? readReportFields(sections.remediation) : undefined;
  const remediation = takeProse(
    remediationFields ? (remediationFields.get("修复措施") ?? []) : sections.remediation,
    "remediation",
  );
  const acceptance = takeProse(
    remediationFields ? (remediationFields.get("修复后验收") ?? []) : sections.acceptance,
    "acceptance",
    Boolean(remediationFields),
  ).filter((sentence) => !remediation.includes(sentence));
  const ref = /^\d+$/.test(findingId) ? `（漏洞 #${findingId}）` : "";
  const replayRequest = boundHTTPRequestForReplay(content);
  let reproduction = "原报告未注明复现记录。";
  if (replayRequest) {
    reproduction = [
      "以下请求取自该漏洞绑定的流量证据，可复制到 Burp Suite Repeater 复现或复测。请求包本身不代表已发送或已验证。",
      ...(replayRequest.bodyBase64
        ? ["请求正文为二进制内容，以下以 Base64 留存。导入 Repeater 前须还原原始字节。"]
        : []),
      `\`\`\`http\n${replayRequest.packet}\n\`\`\``,
    ].join("\n\n");
  } else if (burpPackageAvailable) {
    reproduction = "未附完整原始 HTTP 请求报文。";
  } else if (httpRecorded) {
    reproduction = `未附完整原始 HTTP 请求报文，请在漏洞详情中核对${ref}。`;
  } else if (nonHTTP) {
    reproduction = `本次为非 HTTP 测试，请在有访问权限的漏洞详情中查阅记录${ref}。`;
  } else if (httpExample) {
    reproduction = `原报告含 HTTP 复测说明，请在漏洞详情中核对实际执行情况${ref}。`;
  }
  const recordedVerification = readBurpVerification(sections.reproduction);
  const verification = recordedVerification || (burpPackageAvailable ? "Burp 验证状态：原报告未记录。" : "");
  const evidenceVersions =
    burpPackageAvailable && reportEvidenceVersion !== undefined && currentEvidenceVersion !== undefined
      ? `报告证据版本：${reportEvidenceVersion}。页面加载时的附件证据版本：${currentEvidenceVersion}。${
          reportEvidenceVersion === currentEvidenceVersion ? "" : "版本不一致，交付前请核对。"
        }`
      : "";
  const formatSentence = (sentence: string) =>
    escapeMarkdownText(/[。！？；.!?]$/.test(sentence) ? sentence : `${sentence}。`);
  const paragraph = (sentences: string[], fallback: string) =>
    sentences.length ? sentences.map(formatSentence).join("") : fallback;
  const testProcess = testFacts
    ? [...requiredTestFacts, ...(testFacts.has("未验证范围") ? ["未验证范围"] : [])]
        .map(
          (label) => `- ${label}：${paragraph(takeProse(testFacts.get(label) ?? [], "description", true), "待核实。")}`,
        )
        .join("\n")
    : paragraph(process, "原报告未提供可直接用于交付的测试摘要。");

  const pythonFields = readReportFields(sections.python);
  const pythonLocations = (pythonFields.get("用例位置") ?? [])
    .map((line) =>
      line
        .trim()
        .replace(/^`([^`]+)`[。.]?$/, "$1")
        .replace(/[。.]$/, ""),
    )
    .filter((line) => pythonSourceLocation.test(line));
  const pythonExpected = takeProse(
    pythonFields.get("预期结果") ?? pythonFields.get("预期行为") ?? [],
    "acceptance",
    true,
  );
  const python = [
    ...[...new Set(pythonLocations)].map((location) => `用例位置：\`${location}\``),
    ...(pythonLocations.length ? [`预期结果：${paragraph(pythonExpected, "原报告未记录。")}`] : []),
  ];
  if (replayRequest) {
    python.push(
      "脚本按绑定的漏洞验证或复核请求生成，采集到的认证信息和请求正文保持原值。默认直连；设置 `BURP_PROXY=http://127.0.0.1:8080` 后经 Burp 发送。显式代理不可用时会报错且不会回退直连；HTTPS 可设置 `BURP_CA_CERT` 信任 Burp CA。",
      `\`\`\`python\n${renderPythonReplayScript(replayRequest)}\n\`\`\``,
    );
  } else if (!pythonLocations.length) {
    python.push(
      acceptance.length
        ? `本报告未附 Python 脚本。复测预期见「${repairVerificationTitle}」。`
        : "本报告未附 Python 脚本。",
    );
  }

  const issues: string[] = [];
  if (hasDetailedReport === false) issues.push("详细报告未保存");
  if (hasDetailedReport === undefined) issues.push("详细报告保存状态未知");
  if (!score) issues.push("缺少有效的 CVSS 4.0 评分");
  if (stale) {
    issues.push("测试记录有更新，交付前请核对报告");
  } else if (reportEvidenceVersion === undefined || currentEvidenceVersion === undefined) {
    issues.push("报告证据版本待核对");
  } else if (reportEvidenceVersion !== currentEvidenceVersion) {
    issues.push("测试记录有更新，交付前请核对报告");
  }
  if (burpPackageAvailable || replayRequest || httpRecorded || httpExample) {
    if (!replayRequest) issues.push("缺少完整原始 HTTP 请求报文");
    if (replayRequest?.bodyBase64) issues.push("留存请求正文为二进制，无法直接复制使用");
    if (!recordedVerification || recordedVerification.endsWith("待核对。")) issues.push("Burp 验证状态待核对");
  } else if (!nonHTTP) {
    issues.push("缺少 HTTP 证据或 Burp 不适用说明");
  }

  const markdown = [
    `# ${escapeMarkdownText(displayName)}`,
    rating,
    "## 漏洞描述",
    paragraph(description, "原报告的开发说明待整理。"),
    ...(descriptionFields
      ? [`已确认影响：${paragraph(takeProse(descriptionFields.get("已确认影响") ?? [], "description"), "待核实。")}`]
      : []),
    ...(descriptionFields?.has("测试范围")
      ? [`测试范围：${paragraph(takeProse(descriptionFields.get("测试范围") ?? [], "description"), "待核实。")}`]
      : []),
    `触发位置：${paragraph(location, "页面入口或接口归属待核实。")}`,
    "## 测试过程",
    testProcess,
    "### Burp 复现包",
    reproduction,
    ...[verification, evidenceVersions].filter(Boolean),
    "### 攻击链路",
    chain.length ? chain.map((line) => `- ${formatSentence(line)}`).join("\n") : "已观察到的影响见漏洞描述和测试过程。",
    "### 复现脚本（Python）",
    ...python,
    "## 修复建议",
    paragraph(remediation, "修复建议待补充，请写明要调整的行为和修复后的预期结果。"),
    ...(acceptance.length || remediationFields
      ? [
          repairVerificationLabel,
          (acceptance.length ? acceptance : ["待核实。"]).map((line) => `- ${escapeMarkdownText(line)}`).join("\n"),
        ]
      : []),
  ].join("\n\n");
  return { markdown, severity: score?.severity ?? "待评估", issues };
}

export function formatDeveloperDeliveryReport(content: string, options?: DeliveryReportOptions) {
  return prepareDeveloperDeliveryReport(content, options).markdown;
}
