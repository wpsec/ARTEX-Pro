# 示例系统-备份文件权限过宽：其他本地用户可读取测试记录

CVSS 4.0：CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N  评分 4.8（中危）

## 描述

离线合成场景，未测试真实目标。

在同一主机上以普通用户权限执行命令时，可读取由 `eval-admin` 所有、权限为 644 的 `customer-notes.txt`，并读到一行合成记录。只检查了该文件；远程访问、写入和提权未验证。
需要在同一主机上执行命令；已观察到读取一份合成文件。向量中的机密性影响按同类真实备份可能含客户资料的情形评分；本次未取得真实内容，实际数据影响和评分前提需复核。

## 攻击链路

```text
终端当前用户为 eval-user
├─ stat customer-notes.txt
│  └─ 权限为 644，所有者为 eval-admin
├─ cat customer-notes.txt
│  └─ 读取到一行合成记录
└─ cat private-notes.txt
   └─ Permission denied
```

## 测试过程

测试时间：2026-11-01 10:00:00（北京时间）

在合成终端记录中，`id` 显示当前进程用户为 `eval-user`，`stat` 显示 `customer-notes.txt` 权限为 644，`cat` 读到一行合成记录。

读取相邻的 `private-notes.txt` 返回 `Permission denied`。远程访问、文件写入和提权未验证。

## Burp 复现

Burp 不适用：本次证据为本地命令或终端输出。

## 修复建议

将备份文件和目录权限收紧到实际需要的服务账号或用户组，并检查新生成的备份是否沿用该权限。服务代码和部署配置未检查。

<!-- artex:bound-traffic-evidence -->

### 固定样本原始材料

以下材料来自离线合成夹具，独立于报告正文保存。

**当前用户**

来源：离线合成终端记录

命令：

```sh
id
```

标准输出：

```text
uid=1002(eval-user) gid=1002(eval-user) groups=1002(eval-user)

```

**备份文件权限**

来源：离线合成终端记录

命令：

```sh
stat -c '%a %U %G %n' /tmp/report-eval/backups/customer-notes.txt
```

标准输出：

```text
644 eval-admin eval-admin /tmp/report-eval/backups/customer-notes.txt

```

**读取备份**

来源：离线合成终端记录

命令：

```sh
cat /tmp/report-eval/backups/customer-notes.txt
```

标准输出：

```text
EVAL_ONLY customer-a: synthetic test note

```

**读取相邻受限文件**

来源：离线合成终端记录

命令：

```sh
cat /tmp/report-eval/backups/private-notes.txt
```

标准错误：

```text
cat: /tmp/report-eval/backups/private-notes.txt: Permission denied

```
