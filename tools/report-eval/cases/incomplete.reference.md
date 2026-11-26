# 示例系统-附件下载 访问控制待核实：缺少响应正文，无法确认越权

CVSS 4.0：CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N  评分 0.0（无）

## 描述

离线合成场景，未测试真实目标。

评测场景设定请求方为用户 B、文件属于用户 A，但报文里的合成标记不能证明实际登录身份。响应头显示 HTTP 200；没有响应正文、A 的文件基线或账号权限证明，不能确认服务端返回了文件，也不能认定越权下载。
目前只有状态码，没有可确认的未授权读取影响；结论待补证。

## 攻击链路

```text
场景设定用户 B 请求用户 A 的文件编号
└─ GET /api/files/file-a/download
   └─ 只留存 HTTP 200 响应头，正文未取得
```

## 测试过程

测试时间：2026-11-01 10:00:00（北京时间）

场景记录为 B 请求 A 的文件编号，响应头为 HTTP 200。当前报文不能验证请求者的实际登录身份；没有响应正文或 A 的下载基线。

没有拒绝请求或完整下载结果的记录。文件是否可读取、账号权限和响应正文均未验证。

## Burp 复现

离线合成请求样例，不能直接发送到真实目标。以下请求包供渗透测试工程师在授权目标中导入 Burp Repeater 复现或复测；请求包本身不代表已通过 Burp 发送或验证。

```http
GET /api/files/file-a/download HTTP/1.1
Host: report-eval.invalid
X-Eval-Actor: user-b
Content-Length: 0
```


## 修复建议

目前不能据此给出代码修复结论。请分别用 A、B 的获授权账号正常登录，保存 A 下载本人文件的完整响应，再用 B 请求同一文件并保存完整响应；核对两次响应内容和文件归属。

<!-- artex:bound-traffic-evidence -->

### 固定样本原始材料

以下材料来自离线合成夹具，独立于报告正文保存。

**请求他人文件**

来源：离线合成报文，不对应真实网络请求

请求包：

```http
GET /api/files/file-a/download HTTP/1.1
Host: report-eval.invalid
X-Eval-Actor: user-b
Content-Length: 0


```

响应包：

```http
HTTP/1.1 200 OK
Content-Type: application/octet-stream
Content-Length: 48


```
