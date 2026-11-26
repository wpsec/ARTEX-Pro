# 示例系统-登录会话退出后仍有效：原会话继续读取用户信息

CVSS 4.0：CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N  评分 2.3（低危）

## 描述

离线合成场景，未测试真实目标。

用户 A 退出登录后，使用原会话请求 `/api/me`，仍能读取 A 的用户信息。不带会话的相同请求返回 401。攻击者须已持有该会话；会话如何取得、退出后有效多久，以及写操作和账号接管均未验证。
需先持有有效会话；样本显示退出后仍可读取当前账号资料。向量中的机密性影响按真实用户资料可被继续读取的情形评分；样本内容为合成数据，真实数据影响和评分前提需复核。

## 攻击链路

```text
测试人员持有用户 A 的有效会话
└─ 用户 A 退出登录
   └─ POST /api/logout
      └─ 重放原会话请求 GET /api/me，仍返回 A 的信息
```

## 测试过程

测试时间：2026-11-01 10:00:00（北京时间）

用原会话请求 `/api/me`，调用退出接口后重放同一请求，仍返回用户信息。不带会话的请求返回 401。

不带会话的请求被拒绝。会话有效期、改密、停用、跨设备和写操作未验证。

## Burp 复现

离线合成请求样例，不能直接发送到真实目标。以下请求包供渗透测试工程师在授权目标中导入 Burp Repeater 复现或复测；请求包本身不代表已通过 Burp 发送或验证。

```http
GET /api/me HTTP/1.1
Host: report-eval.invalid
Cookie: session=<SYNTHETIC_SESSION_A>
Content-Length: 0
```

## 修复建议

退出时由服务端撤销当前会话，并在后续请求中检查撤销状态。仅删除客户端 Cookie 不能阻止旧会话重放；当前会话实现和代码位置未核实。

<!-- artex:bound-traffic-evidence -->

### 固定样本原始材料

以下材料来自离线合成夹具，独立于报告正文保存。

**退出前查询**

来源：离线合成报文，不对应真实网络请求

请求包：

```http
GET /api/me HTTP/1.1
Host: report-eval.invalid
Cookie: session=<SYNTHETIC_SESSION_A>
Content-Length: 0


```

响应包：

```http
HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 31

{"id":"user-a","role":"member"}
```

**退出登录**

来源：离线合成报文，不对应真实网络请求

请求包：

```http
POST /api/logout HTTP/1.1
Host: report-eval.invalid
Cookie: session=<SYNTHETIC_SESSION_A>
Content-Length: 0


```

响应包：

```http
HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 11

{"ok":true}
```

**退出后重放原会话**

来源：离线合成报文，不对应真实网络请求

请求包：

```http
GET /api/me HTTP/1.1
Host: report-eval.invalid
Cookie: session=<SYNTHETIC_SESSION_A>
Content-Length: 0


```

响应包：

```http
HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 31

{"id":"user-a","role":"member"}
```

**不带会话查询**

来源：离线合成报文，不对应真实网络请求

请求包：

```http
GET /api/me HTTP/1.1
Host: report-eval.invalid
Content-Length: 0


```

响应包：

```http
HTTP/1.1 401 Unauthorized
Content-Type: application/json
Content-Length: 35

{"error":"authentication_required"}
```
