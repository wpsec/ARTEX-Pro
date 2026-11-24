# 示例系统-业务登记 重复提交：同一编号生成多条记录

CVSS 4.0：CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N  评分 2.3（低危）

## 描述

离线合成场景，未测试真实目标。

同一普通用户对业务编号 `EVAL-RACE` 提交三次，生成三条不同记录。提交前为零条，提交后为三条。现有材料没有服务端处理时间，不能据此说明请求在同一时刻执行。
需要已登录账号，已观察到的是重复登记和记录数增加；其他影响未验证。

## 攻击链路

```text
提交前基线
└─ GET /api/registrations?reference=EVAL-RACE
   └─ total=0
      ├─ 并发提交 3 次相同业务编号
      │  ├─ POST /api/registrations（第一次）
      │  │  └─ HTTP 201，id=reg-1
      │  ├─ POST /api/registrations（第二次）
      │  │  └─ HTTP 201，id=reg-2
      │  └─ POST /api/registrations（第三次）
      │     └─ HTTP 201，id=reg-3
      └─ 回读 GET /api/registrations?reference=EVAL-RACE
         └─ total=3，三条记录的 ID 不同
```

## 测试过程

测试时间：2026-11-01 10:00:00（北京时间）

2026-11-01 10:00:00（北京时间）使用 Python 3.12 并发驱动，以同一账号提交三次相同 POST。三次均返回 201，回读记录从 0 条增至 3 条，ID 不同。

缺少 `reference` 的提交返回 400。串行重复提交、其他账号和更大并发量未测；没有请求级时间，不能确认服务端同时处理。

## Burp 复现

离线合成请求样例，不能直接发送到真实目标。以下请求包供渗透测试工程师在授权目标中导入 Burp Repeater 复现或复测；请求包本身不代表已通过 Burp 发送或验证。

```http
POST /api/registrations HTTP/1.1
Host: report-eval.invalid
X-Eval-Actor: user-a
Content-Type: application/json
Content-Length: 25

{"reference":"EVAL-RACE"}
```

## 修复建议

在数据库中为业务编号建立唯一约束。重复提交返回冲突，不再生成新记录。源码位置未核实。

<!-- artex:bound-traffic-evidence -->

### 固定样本原始材料

以下材料来自离线合成夹具，独立于报告正文保存。

**提交前查询**

来源：离线合成报文，不对应真实网络请求

请求包：

```http
GET /api/registrations?reference=EVAL-RACE HTTP/1.1
Host: report-eval.invalid
X-Eval-Actor: user-a
Content-Length: 0


```

响应包：

```http
HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 22

{"total":0,"items":[]}
```

**第一次并发提交**

来源：离线合成报文，不对应真实网络请求

请求包：

```http
POST /api/registrations HTTP/1.1
Host: report-eval.invalid
X-Eval-Actor: user-a
Content-Type: application/json
Content-Length: 25

{"reference":"EVAL-RACE"}
```

响应包：

```http
HTTP/1.1 201 Created
Content-Type: application/json
Content-Length: 38

{"id":"reg-1","reference":"EVAL-RACE"}
```

**第二次并发提交**

来源：离线合成报文，不对应真实网络请求

请求包：

```http
POST /api/registrations HTTP/1.1
Host: report-eval.invalid
X-Eval-Actor: user-a
Content-Type: application/json
Content-Length: 25

{"reference":"EVAL-RACE"}
```

响应包：

```http
HTTP/1.1 201 Created
Content-Type: application/json
Content-Length: 38

{"id":"reg-2","reference":"EVAL-RACE"}
```

**第三次并发提交**

来源：离线合成报文，不对应真实网络请求

请求包：

```http
POST /api/registrations HTTP/1.1
Host: report-eval.invalid
X-Eval-Actor: user-a
Content-Type: application/json
Content-Length: 25

{"reference":"EVAL-RACE"}
```

响应包：

```http
HTTP/1.1 201 Created
Content-Type: application/json
Content-Length: 38

{"id":"reg-3","reference":"EVAL-RACE"}
```

**提交后查询**

来源：离线合成报文，不对应真实网络请求

请求包：

```http
GET /api/registrations?reference=EVAL-RACE HTTP/1.1
Host: report-eval.invalid
X-Eval-Actor: user-a
Content-Length: 0


```

响应包：

```http
HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 138

{"total":3,"items":[{"id":"reg-1","reference":"EVAL-RACE"},{"id":"reg-2","reference":"EVAL-RACE"},{"id":"reg-3","reference":"EVAL-RACE"}]}
```

**缺少业务编号的提交**

来源：离线合成报文，不对应真实网络请求

请求包：

```http
POST /api/registrations HTTP/1.1
Host: report-eval.invalid
X-Eval-Actor: user-a
Content-Type: application/json
Content-Length: 2

{}
```

响应包：

```http
HTTP/1.1 400 Bad Request
Content-Type: application/json
Content-Length: 30

{"error":"reference_required"}
```
