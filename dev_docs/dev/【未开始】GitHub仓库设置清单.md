# 【未开始】GitHub 仓库设置清单

以下设置需在 GitHub 仓库设置中启用；本地文件无法替代远端分支规则。

2026-11-26 工作流与公开 Actions 复核：CI 的四个必需检查名与 workflow job 名称一致，push/PR 触发分支包含 `main` 和 `artex-dev`；CI 与 Release 共 26 个 Actions 引用均固定到完整 40 位 commit SHA。公开 API 确认 `52707a3` 的 CI 全绿，远端最新 `71777276` 的 Browser regression 失败；原始日志接口未经认证返回 403。此检查不代表 GitHub 远端保护规则已配置。

## 需要的用户配合

- 本地仓库沿用 `wpsec/ARTEX-local` 旧地址；GitHub 当前将其重定向到规范仓库 `wpsec/ARTEX-Pro`。远端规则核查和应用应定位到 `wpsec/ARTEX-Pro`。
- 2026-11-26 插件目录中的 GitHub connector 显示未安装，本机也没有 `gh` CLI。公开 API 可读 Actions 摘要，但完整失败日志与仓库规则设置仍不可见；核对规则需要已连接的 GitHub connector 或管理员提供设置截图。
- 如需实际应用设置，管理员权限必须覆盖分支规则、Actions 权限与 Dependabot。不要在聊天中粘贴 Personal Access Token；使用 GitHub 连接授权即可。
- 我会先核对当前规则和必需状态检查名称，再给出可审核的配置清单；只有你明确要求应用远端更改后才执行。

## `main`：ARTEX-Pro 正式主分支

- 将 `main` 设为仓库默认分支。
- `artex-dev` 的开发通过审查和 CI 后以 Pull Request 合入 `main`。
- 要求以下状态检查通过：`Go tests`、`Web checks`、`Browser regression`、`Go vulnerability scan`。这些名称与 `.github/workflows/ci.yml` 当前 `jobs.*.name` 一致（2026-11-24 核对）。
- 要求解决所有 Pull Request 对话线程；禁止强制推送和删除分支。
- 有其他维护者参与时要求至少一人批准；单人维护阶段不要设置会阻止本人合并的审查门槛。

## `artex-dev`：日常开发分支

- 按 `.github/workflows/ci.yml`，CI 在 push 到 `main`、`artex-dev`，以及目标为这两个分支的 Pull Request 时运行；也支持手动触发 `workflow_dispatch`。
- 开发完成后通过 Pull Request 合入 `main`；不要绕过审查直接更新正式分支。

## `artex-native-backup`：原生源码备份

- 保留原生 ARTEX 源码基线，不承接 ARTEX-Pro 的功能开发。
- 禁止强制推送和删除，避免丢失原始基线。

## 安全与 Actions

- 默认 `GITHUB_TOKEN` 权限设为只读；发布工作流按 job 单独授予写权限。
- 启用 Dependabot security updates、依赖图和私密漏洞报告。
- 首次通过 Release workflow 发布 GHCR 镜像后，如需匿名拉取，将 `wpsec/artex-pro` 包可见性设为 Public，并确认 Actions 可发布该包。
- 对 `v*` 发布 tag 配置规则，限制创建和更新权限。
- 检查 GitHub Actions 允许列表与第三方 Action 使用策略；工作流中的 Action 应固定到完整 commit SHA，并通过 Dependabot 定期更新。

## 启用后复核

分别确认 `artex-dev` 到 `main` 的 Pull Request 会触发必需状态检查。不要以跳过规则的方式测试保护设置。
