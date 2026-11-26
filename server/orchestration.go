package server

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
	"github.com/wpsec/ARTEX-local/agent"
	"github.com/wpsec/ARTEX-local/db"
)

// jsonResult marshals v to a JSON tool result.
func jsonResult(v any) (actool.Result, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return actool.Errorf(err.Error()), nil
	}
	return actool.Text(string(b)), nil
}

// 本文件实现 P2「跨任务编排工具集」(docs/跑分编排 §2 P2)。这些是 host 工具——需要
// 访问 Manager(任意任务的 Store)、Engine(暂停)、以及建任务流程,所以住在 server 层。
// 读类工具把「现有 per-task 工具」重定向到目标任务的 store 上跑(建一个临时 ToolSet
// 并 Call 其对应工具),从而复用完全相同的逻辑;控制类(spawn/pause)直接调 Manager/Engine。
// 它们像流量工具一样 seed 进 tools 表、按 agent 绑定(只绑给编排 agent 才可见)。

// hostTools is the runtime host-tool provider fed to ToolAugment: traffic tools
// (gated by capture) + cross-task orchestration tools + user-defined custom tools.
// The second return is the names of custom tools flagged `deferred` (schema
// withheld, routed via SearchExtraTools/ExecuteExtraTool). Per-agent binding still
// decides who actually sees any of them.
//
//nolint:unused // used as the hostTools provider in wireAgentAugment
func (s *Server) hostTools() ([]actool.CoreTool, map[string][]string) {
	tools := append(s.m.HostTools(), s.orchestrationTools()...)
	tools = append(tools, s.findingRetestTools()...)
	tools = append(tools, s.platformTools()...) // 平台操作工具(建改 skill/工具/MCP，给 Auto 用)
	custom, err := s.customTools()
	if err != nil {
		log.Printf("[custom-tool] 加载失败: %v", err)
		return tools, nil
	}
	tools = append(tools, custom...)
	// deferred custom tools → name -> its bound agent keys. ToolAugment turns a
	// name into a deferred entry only for agents it's actually bound to (so we don't
	// advertise a tool the per-agent binding will drop from the callable set).
	deferred := map[string][]string{}
	rows, _ := s.m.pg.ListCustomTools()
	for _, t := range rows {
		if t.Deferred && t.Enabled {
			deferred[t.Key] = t.Agents
		}
	}
	return tools, deferred
}

// orchestrationTools returns the cross-task tool set. Bound per-agent via the
// tools table (default: no binding — opt-in for orchestration agents).
func (s *Server) orchestrationTools() []actool.CoreTool {
	return []actool.CoreTool{
		s.toolListTasks(),
		s.toolListLLMProfiles(),
		s.toolSpawnTask(),
		s.toolPauseTask(),
		s.toolGetTaskGraph(),
		s.toolListTaskFindings(),
		s.toolAddHint(),
		s.toolGetWorkerTrace(),
		s.toolListWorkerTraces(),
		s.toolSearchWorkerTraces(),
		s.toolGetTaskNodeDetail(),
		s.toolUpdateFindingReport(),
		s.toolGetFindingTraffic(),
		s.toolBindFindingTraffic(),
	}
}

// --- schema helpers ---

func strParam(desc string) map[string]any {
	return map[string]any{"type": "string", "description": desc}
}

// parseProfileID reads an LLM profile id from a tool arg that may arrive as a JSON
// number (5) or a numeric string ("5"); returns 0 when absent/unparseable.
func parseProfileID(raw json.RawMessage) int64 {
	if len(raw) == 0 {
		return 0
	}
	var n int64
	if json.Unmarshal(raw, &n) == nil {
		return n
	}
	var str string
	if json.Unmarshal(raw, &str) == nil {
		v, _ := strconv.ParseInt(strings.TrimSpace(str), 10, 64)
		return v
	}
	return 0
}

func objSchema(props map[string]any, required ...string) map[string]any {
	m := map[string]any{"type": "object", "properties": props}
	if len(required) > 0 {
		req := make([]any, len(required))
		for i, r := range required {
			req[i] = r
		}
		m["required"] = req
	}
	return m
}

func roTool(name, desc string, schema map[string]any, run func(context.Context, json.RawMessage) (actool.Result, error)) actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: name, Description: desc, Schema: schema,
		ReadOnly:   func(json.RawMessage) bool { return true },
		Concurrent: func(json.RawMessage) bool { return true },
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Allowed()
		},
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			return run(ctx, in)
		},
	})
}

func wrTool(name, desc string, schema map[string]any, run func(context.Context, json.RawMessage) (actool.Result, error)) actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: name, Description: desc, Schema: schema,
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Allowed()
		},
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			return run(ctx, in)
		},
	})
}

// delegateToTask resolves the `task_id` in the input, builds a ToolSet bound to
// that task's store, strips task_id, and calls the chosen per-task tool — so the
// cross-task read reuses the exact in-task logic against another task.
func (s *Server) delegateToTask(ctx context.Context, in json.RawMessage, pick func(*agent.ToolSet) actool.CoreTool) (actool.Result, error) {
	var head struct {
		TaskID string `json:"task_id"`
	}
	_ = json.Unmarshal(in, &head)
	if strings.TrimSpace(head.TaskID) == "" {
		return actool.Errorf("task_id 为必填"), nil
	}
	t, ok := s.m.Task(head.TaskID)
	if !ok {
		return actool.Errorf("task 不存在: " + head.TaskID), nil
	}
	var m map[string]json.RawMessage
	_ = json.Unmarshal(in, &m)
	delete(m, "task_id")
	inner, _ := json.Marshal(m)
	tsx := agent.NewToolSet(t.Store, "orchestrator")
	if s.m.Assets() != nil {
		tsx.SetAssetStore(s.m.Assets(), s.m.Assets().Companies())
	}
	tsx.SetNotify(t.Notify)         // 通用唤醒（无专用回调的写操作走它；读工具为 no-op）
	tsx.SetNotifyHint(t.NotifyHint) // add_hint → 记一条「人新增了 N 条战略提示：…」触发并唤醒 planner
	return pick(tsx).Call(ctx, inner, nil)
}

// --- tools ---

func (s *Server) toolListTasks() actool.CoreTool {
	return roTool("list_tasks",
		"列出所有任务(id/描述/目标/状态/运行时长/父任务/LLM 配置)，编排 agent 用它掌握全局、看哪些任务卡太久、各自用哪个 LLM。运行时长：运行中=创建→现在，终态=创建→最后活动(秒)。llm_profile：任务 planner/worker 用的配置名，(激活配置)=跟随全局激活。",
		objSchema(map[string]any{}),
		func(context.Context, json.RawMessage) (actool.Result, error) {
			lastAct, _ := s.m.PG().LastActivityAll()
			// id -> name to resolve each task's pinned LLM profile.
			profName := map[int64]string{}
			if profs, err := s.m.pg.ListProfiles(); err == nil {
				for _, p := range profs {
					profName[p.ID] = p.Name
				}
			}
			out := make([]map[string]any, 0)
			for _, t := range s.m.List() {
				status := s.deriveTaskStatus(t)
				end := lastAct[t.ExpID]
				if live := s.engine.LastActivity(t.ID); live > end {
					end = live
				}
				dur := int64(0)
				if status == "running" {
					dur = time.Now().Unix() - t.CreatedAt
				} else if end > t.CreatedAt {
					dur = end - t.CreatedAt
				}
				row := map[string]any{"id": t.ID, "description": t.Description, "goal": t.Goal, "status": status, "run_seconds": dur}
				if t.ParentRef != "" {
					row["parent_ref"] = t.ParentRef
				}
				llmState := t.llmStateSnapshot()
				if llmState.ProfileID == nil {
					row["llm_profile"] = "(激活配置)"
				} else if n, ok := profName[*llmState.ProfileID]; ok {
					row["llm_profile"] = n
				} else {
					row["llm_profile"] = fmt.Sprintf("#%d(已删除)", *llmState.ProfileID)
				}
				out = append(out, row)
			}
			return jsonResult(out)
		})
}

// toolListLLMProfiles lists the available LLM profiles (name/model/active) so an
// orchestration agent can pick one for spawn_task's llm_profile. Never leaks keys.
func (s *Server) toolListLLMProfiles() actool.CoreTool {
	return roTool("list_llm_profiles",
		"列出可用的 LLM 配置(profile)：id、名称、模型、格式、是否为当前激活配置。用 id 给 spawn_task 的 llm_profile_id 参数指定子任务专属 LLM（如侦察用便宜模型、利用用强模型）。不含 API Key。",
		objSchema(map[string]any{}),
		func(context.Context, json.RawMessage) (actool.Result, error) {
			profs, err := s.m.pg.ListProfiles()
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			out := make([]map[string]any, 0, len(profs))
			for _, p := range profs {
				out = append(out, map[string]any{
					"id": p.ID, "name": p.Name, "model": p.Model, "format": p.Format, "is_active": p.IsDefault,
				})
			}
			return jsonResult(map[string]any{"profiles": out})
		})
}

func (s *Server) toolSpawnTask() actool.CoreTool {
	return wrTool("spawn_task",
		"新建一个子任务并启动探索引擎，返回 task_id。用于把一件事(如一道题/一个目标)派成独立任务。parent_ref 可选：填当前编排关联的父任务 id 做父子关联。",
		objSchema(map[string]any{
			"description":            strParam("任务描述(简短标题)"),
			"goal":                   strParam("任务目标(要达成什么)"),
			"parent_ref":             strParam("可选：父任务 id(做父子关联)"),
			"source_task_ids":        map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": fmt.Sprintf("可选：只读继承的来源任务 id 列表(最多 %d 个)。子任务可只读引用这些任务已探明的资产/结论作为起点；与 parent_ref 的纯父子指针不同，这是内容继承。", db.MaxTaskSourceCount)},
			"llm_profile_id":         map[string]any{"type": "integer", "description": "可选：指定本子任务 planner/worker 用的 LLM 配置 id(见 list_llm_profiles)；留空则继承父任务、再回退全局激活配置"},
			"timeout_seconds":        map[string]any{"type": "integer", "description": "可选：任务级超时(秒)。到点后触发优雅收尾并进入 timeout 终态；留空或 0 = 不限时"},
			"plan_heartbeat_seconds": map[string]any{"type": "integer", "description": "可选：planner 心跳触发间隔(秒)。距上轮规划结束/任务开始满该值且期间无触发 → 触发一轮规划(兜底死锁 + 唤醒去监督飞行中的 worker)。留空或 0 = 默认 600(10min)；"},
			"seed_first_intent":      map[string]any{"type": "boolean", "description": "可选：对于简单任务可开启，创建时直接下发一条种子意图(内容=描述+目标)让 worker 免等首轮 planner 直接开跑测试；默认 false(走标准先规划再执行)。"},
		}, "description", "goal"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Description          string          `json:"description"`
				Goal                 string          `json:"goal"`
				ParentRef            string          `json:"parent_ref"`
				SourceTaskIDs        []string        `json:"source_task_ids"`
				LLMProfileID         json.RawMessage `json:"llm_profile_id"`
				TimeoutSeconds       int             `json:"timeout_seconds"`
				PlanHeartbeatSeconds int             `json:"plan_heartbeat_seconds"`
				SeedFirstIntent      bool            `json:"seed_first_intent"`
			}
			_ = json.Unmarshal(in, &a)
			if strings.TrimSpace(a.Description) == "" {
				a.Description = "未命名任务"
			}
			if strings.TrimSpace(a.Goal) == "" {
				return actool.Errorf("goal 为必填"), nil
			}
			if a.TimeoutSeconds < 0 {
				a.TimeoutSeconds = 0
			}
			// 只读继承来源任务：数量上限 + 每个 id 有效/去重/存在，校验规则与 HTTP 建任务一致。
			if len(a.SourceTaskIDs) > db.MaxTaskSourceCount {
				return actool.Errorf(fmt.Sprintf("关联任务最多选择 %d 个", db.MaxTaskSourceCount)), nil
			}
			sourceIDs := make([]int64, 0, len(a.SourceTaskIDs))
			seenSources := map[int64]bool{}
			for _, raw := range a.SourceTaskIDs {
				id, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
				if err != nil || id <= 0 || seenSources[id] {
					return actool.Errorf("关联任务 id 无效或重复"), nil
				}
				if _, ok := s.m.Task(strconv.FormatInt(id, 10)); !ok {
					return actool.Errorf(fmt.Sprintf("关联任务 #%d 不存在", id)), nil
				}
				seenSources[id] = true
				sourceIDs = append(sourceIDs, id)
			}
			// LLM profile resolution: explicit id > inherit parent's pin > active(nil).
			var pin *int64
			if id := parseProfileID(a.LLMProfileID); id > 0 {
				if _, ok := s.loadProfileConfig(id); !ok {
					return actool.Errorf(fmt.Sprintf("LLM 配置 #%d 不存在或未设置 API Key", id)), nil
				}
				pin = &id
			} else if a.ParentRef != "" {
				if pt, ok := s.m.Task(a.ParentRef); ok {
					pin = pt.LLMProfileID
				}
			}
			var llmIDs []int64
			if pin != nil {
				llmIDs = []int64{*pin}
			}
			t, err := s.m.CreateTaskWithOptions(a.Description, a.Goal, db.TaskCreateOptions{
				SourceTaskIDs:        sourceIDs,
				LLMProfileIDs:        llmIDs,
				TimeoutSeconds:       a.TimeoutSeconds,
				PlanHeartbeatSeconds: a.PlanHeartbeatSeconds,
			})
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if a.ParentRef != "" {
				t.ParentRef = a.ParentRef
				if id, e := strconv.ParseInt(t.ID, 10, 64); e == nil {
					_ = s.m.PG().SetParentRef(id, a.ParentRef)
				}
			}
			// 共享的建后流程,与 HTTP 建任务(server.go createTask)复用同一段 launchTask:
			// seed + 后台可见地做目标分解(第0轮/LLM步骤/逐条goal) + engine.Run。
			// seed_first_intent 默认 false(标准先规划再执行);简单任务可开启直接下发一 work 测试。
			s.launchTask(t, a.Description+" "+a.Goal, a.SeedFirstIntent)
			return actool.Text(fmt.Sprintf("task created: %s", t.ID)), nil
		})
}

func (s *Server) toolPauseTask() actool.CoreTool {
	return wrTool("pause_task", "暂停指定任务(停止其 planner/worker 循环)。",
		objSchema(map[string]any{"task_id": strParam("要暂停的任务 id")}, "task_id"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				TaskID string `json:"task_id"`
			}
			_ = json.Unmarshal(in, &a)
			t, ok := s.m.Task(a.TaskID)
			if !ok {
				return actool.Errorf("task 不存在: " + a.TaskID), nil
			}
			if _, err := s.applyTaskControlWithCause(t, "pause", agent.AbortPausedByOrchestrator); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return actool.Text("task paused: " + a.TaskID), nil
		})
}

func (s *Server) toolGetTaskGraph() actool.CoreTool {
	return roTool("get_task_graph", "读指定任务的探索图总览(同 graph_overview：资产计数/frontier/发现/覆盖等)，用 task_id 指定任务。",
		objSchema(map[string]any{"task_id": strParam("任务 id")}, "task_id"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			return s.delegateToTask(ctx, in, (*agent.ToolSet).GraphOverviewTool)
		})
}

func (s *Server) toolListTaskFindings() actool.CoreTool {
	return roTool("list_task_findings", "读指定任务的确认漏洞(含 flag/PoC；每条带 id/task_id/intent_id/vulnclass/severity/摘要/状态)，用 task_id 指定任务。",
		objSchema(map[string]any{"task_id": strParam("任务 id")}, "task_id"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			return s.delegateToTask(ctx, in, (*agent.ToolSet).ListFindingsTool)
		})
}

func (s *Server) toolAddHint() actool.CoreTool {
	return wrTool("add_task_hint", "给指定任务注入战略提示(该任务的 planner 下轮生成意图时会读到)。\n"+
		"★优先批量：多条提示放进 hints 数组一次提交（返回 ids 数组，与 hints 等长同序，失败项 id=0）；单条则省略 hints 直接给顶层 text。",
		objSchema(map[string]any{
			"task_id":      strParam("任务 id"),
			"hints":        map[string]any{"type": "array", "description": "【优先用这个】提示数组，每个元素字段同顶层（text/asset_ids/traffic_refs）。", "items": objSchema(map[string]any{"text": strParam("提示内容"), "asset_ids": map[string]any{"type": "array", "items": map[string]any{"type": "integer"}}, "traffic_refs": agent.HintTrafficSchema()})},
			"text":         strParam("[单条] 提示内容"),
			"traffic_refs": agent.HintTrafficSchema(),
			"asset_ids":    map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "锚定的资产 id（可选，0/1/多个；该任务内的资产 id）"},
		}, "task_id"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			return s.delegateToTask(ctx, in, (*agent.ToolSet).AddHintTool)
		})
}

func (s *Server) toolGetWorkerTrace() actool.CoreTool {
	return roTool("get_task_worker_trace",
		"看指定任务里某个 work(意图)的执行过程：get_task_worker_trace(task_id, intent_id) 看步骤摘要；再带 step_ids=[...] 取那几步完整内容(一次最多 5 个,多传只返回前 5 个)。",
		objSchema(map[string]any{
			"task_id":   strParam("任务 id"),
			"intent_id": map[string]any{"type": "integer", "description": "意图 id(该任务里的 work)"},
			"step_ids":  map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "可选：要取完整内容的步骤 id(一次最多 5 个,多传只返回前 5 个,其余在 omitted_step_ids 里列出)"},
		}, "task_id", "intent_id"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			return s.delegateToTask(ctx, in, (*agent.ToolSet).GetWorkerTraceTool)
		})
}

func (s *Server) toolListWorkerTraces() actool.CoreTool {
	return roTool("list_task_worker_traces", "列出指定任务里跑过哪些 work(意图) + 各自步数，用于发现哪些 work 值得翻看(再用 get_task_worker_trace)。",
		objSchema(map[string]any{"task_id": strParam("任务 id")}, "task_id"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			return s.delegateToTask(ctx, in, (*agent.ToolSet).ListWorkerTracesTool)
		})
}

func (s *Server) toolSearchWorkerTraces() actool.CoreTool {
	return roTool("search_task_worker_traces", "在指定任务里按关键字搜索所有 work 的执行过程(返回命中步骤摘要 + intent_id)。",
		objSchema(map[string]any{"task_id": strParam("任务 id"), "q": strParam("搜索关键字")}, "task_id", "q"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			return s.delegateToTask(ctx, in, (*agent.ToolSet).SearchWorkerTracesTool)
		})
}

func (s *Server) toolGetTaskNodeDetail() actool.CoreTool {
	return roTool("get_task_node_detail",
		"读指定任务里某个探索图节点的完整内容(发现/事实/意图/目标：摘要 + 详情/证据/PoC)。id 为探索节点 id(如 report_finding 返回、或 list_task_findings 里的 id)。写漏洞报告前用它取该漏洞的完整证据。",
		objSchema(map[string]any{
			"task_id": strParam("任务 id"),
			"id":      map[string]any{"type": "integer", "description": "探索图节点 id(非资产 id)"},
		}, "task_id", "id"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			return s.delegateToTask(ctx, in, (*agent.ToolSet).NodeDetailTool)
		})
}

const previousFindingReportToolDescription = "为已登记的漏洞一次写入/更新【详细报告】和【交付报告】(均为 Markdown,整段覆盖旧内容)。finding_id 传 report_finding 返回的那个 id(\"finding recorded: <id>\" 里的数字)。交付报告面向开发修复，按必要性和证据给出简洁、可复测的内容；保存时 ARTEX 会自动附加本漏洞全部已绑定 HTTP 流量的完整原始请求和响应，不要在正文重复粘贴这些报文。cvss_vector 提供完整 CVSS 4.0 Base 向量。"

const previousFindingReportToolDescriptionTemplateV1 = "为已登记的漏洞一次写入/更新【详细报告】和【交付报告】(Markdown 全文，整段覆盖)。finding_id 传 finding_node_id（report_finding 第一行的数字）。交付报告必须包含一级标题、漏洞名称和单行 CVSS 4.0 报告头，二级标题按顺序固定为：描述、修复、测试过程、攻击链路、证据说明；各节非空。描述内必须有三级标题“定级依据”；测试过程内必须有“发现过程与攻击思路”“失败尝试与未验证项”；证据说明内必须有“Burp 复现”“复测标准”。测试记录写清工具参数、判据和时间。缺少证据写“未验证”，不得补造；格式错误时按工具反馈补齐后重新保存。保存时 ARTEX 会在证据说明内成对附加全部已绑定 HTTP 请求和响应，正文指明对应证据编号与用途，不要重复抄写绑定报文。cvss_vector 提供完整 CVSS 4.0 Base 向量。"

const previousFindingReportToolDescriptionTemplateV2 = "为已登记的漏洞一次写入/更新【详细报告】和【交付报告】(Markdown 全文，整段覆盖)。finding_id 传 finding_node_id（report_finding 第一行的数字）。交付报告必须包含一个一级标题和一行 CVSS 4.0 信息。一级标题就是漏洞名称，不再另写“漏洞名称”字段；CVSS 向量、分数和等级只写一次。二级标题按顺序固定为：描述、修复、测试过程、攻击链路、证据说明；各节非空。描述内必须有三级标题“定级依据”；测试过程内必须有“发现过程与攻击思路”“失败尝试与未验证项”；证据说明内必须有“Burp 复现”“复测标准”。攻击链路必须包含 text 代码块树形图，写清起点和至少一条带内容的分支，并说明功能来源、接口或工具和实际结果。测试记录写清工具参数、判据和时间。缺少证据写“未验证”，不得补造；格式错误时按工具反馈补齐后重新保存。保存时 ARTEX 会在证据说明内成对附加全部已绑定 HTTP 请求和响应，正文指明对应证据编号与用途，不要重复抄写绑定报文。cvss_vector 提供完整 CVSS 4.0 Base 向量。"

const previousFindingReportToolDescriptionTemplateV3 = "为已登记的漏洞一次写入/更新【详细报告】和【交付报告】(Markdown 全文，整段覆盖)。finding_id 传 finding_node_id（report_finding 第一行的数字）。交付报告头只写一个漏洞名称和一行 CVSS 4.0 信息。二级标题必须逐字依次写为：漏洞描述、测试过程、攻击链路、修复建议、证据说明；不能缩写或换成近义标题。正文短句，优先写复现和修复；完整绑定报文由 ARTEX 自动附加，不要重抄。HTTP 测试过程写 Burp Repeater 的请求、账号会话、修改项、顺序和判据；并发测试先发基线查询，再将相同请求放入标签组选择 Send group in parallel，最后发回读查询；不编造线程控件。失败尝试和未验证边界简短说明，不得补造。保存时 ARTEX 会在证据说明内成对附加全部已绑定 HTTP 请求和响应。正文按材料用途称呼，不抄写内部证据 ID 或重复报文。cvss_vector 提供完整 CVSS 4.0 Base 向量。"

const previousFindingReportToolDescriptionTemplateV4 = "为已登记的漏洞一次写入/更新【详细报告】和【交付报告】(Markdown 全文，整段覆盖)。finding_id 传 finding_node_id（report_finding 第一行的数字）。交付报告须包含一个漏洞名称一级标题、一行 CVSS 4.0 信息，并按顺序使用二级标题：描述、修复、测试过程、攻击链路、证据说明。须包含三级标题“定级依据”“发现过程与攻击思路”“失败尝试与未验证项”“Burp 复现”“复测标准”。材料不足时在对应位置说明未验证或缺少什么。正文用具体操作、结果和修复办法说明问题。绑定的原始材料由 ARTEX 完整附加，不能改写或重复粘贴。HTTP 报告须提供 Burp Repeater 复现说明；实际未用 Burp 时要标明复测未验证。攻击链用 text 代码块展示有证据支持的步骤。CVSS 信息与风险等级只在报告头出现一次；不得使用“判决项”“阴性结果”“属主”“W07”等内部或实验记录词。保存时 ARTEX 会在证据说明内成对附加全部已绑定 HTTP 请求和响应。正文按材料用途称呼，不抄写内部证据 ID 或重复报文。cvss_vector 提供完整 CVSS 4.0 Base 向量。"

const previousDeliveryReportSaveGuidance = "交付报告须包含一个漏洞名称一级标题和一行 CVSS 4.0 信息，并按顺序使用二级标题：描述、修复、测试过程、攻击链路、证据说明。须包含三级标题“定级依据”“发现过程与攻击思路”“失败尝试与未验证项”“Burp 复现”“复测标准”。材料不足时说明缺少什么或尚未验证。用简短中文写清问题、复现和修复。绑定的原始材料由 ARTEX 完整附加，保持原文，不要重复粘贴。HTTP 报告说明 Burp Repeater 复现步骤，并区分实际测试与建议复测。攻击链用 text 代码块展示证据支持的步骤。"
const previousFindingReportToolDescriptionTemplateV5 = "为已登记的漏洞一次写入/更新【详细报告】和【交付报告】(Markdown 全文，整段覆盖)。finding_id 传 finding_node_id（report_finding 第一行的数字）。" + previousDeliveryReportSaveGuidance + "保存时 ARTEX 会在证据说明内成对附加全部已绑定 HTTP 请求和响应。正文按材料用途称呼，不抄写内部证据 ID 或重复报文。cvss_vector 提供完整 CVSS 4.0 Base 向量。"

const previousDeliveryReportSaveGuidanceV6 = "交付报告须包含一个漏洞名称一级标题、一行 CVSS 4.0 信息，并按顺序使用二级标题：描述、修复建议、测试过程、攻击链路、证据说明。不要添加三级标题或重复栏目。测试过程须说明工具、参数、实际结果、判据、失败尝试与未验证项；HTTP 问题须写明 Burp Repeater 的实际使用状态和复现步骤，非 HTTP 问题说明 Burp 不适用。绑定的请求和响应由 ARTEX 原文附加，不要重复粘贴。用简短中文写清问题、影响和修复。"
const previousFindingReportToolDescriptionTemplateV6 = "为已登记的漏洞一次写入/更新【详细报告】和【交付报告】(Markdown 全文，整段覆盖)。finding_id 传 finding_node_id（report_finding 第一行的数字）。" + previousDeliveryReportSaveGuidanceV6 + "保存时 ARTEX 会在证据说明内成对附加全部已绑定 HTTP 请求和响应。正文按材料用途称呼，不抄写内部证据 ID 或重复报文。cvss_vector 提供完整 CVSS 4.0 Base 向量。"

const previousDeliveryReportSaveGuidanceV7 = "交付报告须包含一个漏洞名称一级标题、一行 CVSS 4.0 信息，并按顺序使用二级标题：描述、修复建议、测试过程、攻击链路、证据说明。不要添加三级标题或重复栏目。测试过程须说明时间、实际工具与参数、结果、判据、失败尝试与未验证项；缺少时间或工具记录时分别写“测试时间：未记录”或“执行工具：未记录”。HTTP 问题须写明 Burp Repeater 的实际使用状态和复现步骤，非 HTTP 问题说明 Burp 不适用。已绑定 HTTP 请求和响应由 ARTEX 原文附加，不要重复粘贴。用简短中文写清问题、影响和修复。"
const previousFindingReportToolDescriptionTemplateV7 = "为已登记的漏洞一次写入/更新【详细报告】和【交付报告】(Markdown 全文，整段覆盖)。finding_id 传 finding_node_id（report_finding 第一行的数字）。" + previousDeliveryReportSaveGuidanceV7 + "保存时 ARTEX 会在证据说明内成对附加全部已绑定 HTTP 请求和响应。正文按材料用途称呼，不抄写内部证据 ID 或重复报文。cvss_vector 提供完整 CVSS 4.0 Base 向量。"

const previousDeliveryReportSaveGuidanceV8 = "交付报告须包含一个漏洞名称一级标题、一行 CVSS 4.0 信息，并按顺序使用二级标题：描述、修复建议、测试过程、攻击链路、证据说明。不要添加三级标题或重复栏目。测试过程必须各有一行“测试时间：”和“执行工具：”；没有记录时分别写“未记录”。还须说明参数、结果、判据、失败尝试与未验证项。HTTP 问题须写明 Burp Repeater 的实际使用状态；非 HTTP 问题只说明 Burp 不适用；协议未确认时写“协议未确认，Burp Repeater 复测未验证”，不猜协议也不写复现步骤。合成身份标记不是凭证，不要抄写或建议替换。已绑定 HTTP 请求和响应由 ARTEX 原文附加，不要重复粘贴。用简短中文写清问题、影响和修复。"
const previousFindingReportToolDescriptionTemplateV8 = "为已登记的漏洞一次写入/更新【详细报告】和【交付报告】(Markdown 全文，整段覆盖)。finding_id 传 finding_node_id（report_finding 第一行的数字）。" + previousDeliveryReportSaveGuidanceV8 + "保存时 ARTEX 会在证据说明内成对附加全部已绑定 HTTP 请求和响应。正文按材料用途称呼，不抄写内部证据 ID 或重复报文。cvss_vector 提供完整 CVSS 4.0 Base 向量。"

const previousDeliveryReportSaveGuidanceV9 = "以下结构和写作要求只适用于交付报告字段；详细报告仍保留原有章节和完整台账。交付报告须包含一个漏洞名称标题、一行 CVSS 4.0 信息，并按顺序使用二级标题：描述、修复建议、测试过程、攻击链路、证据说明。描述含“定级依据”；测试过程含“发现过程与攻击思路”“失败尝试与未验证项”“Burp 复现”；证据说明含“复测标准”。正文尽量简短，通常不超过 800 字；复杂案例可超过，不得删掉关键证据来凑长度。测试时间按记录换算为北京时间，缺失时写“未记录”。HTTP 问题说明 Burp Repeater 的实际使用情况或复测步骤。ARTEX 会附加完整原始请求和响应，不要在正文重复转述。"
const previousFindingReportToolDescriptionTemplateV9 = "为已登记的漏洞一次写入/更新【详细报告】和【交付报告】(Markdown 全文，整段覆盖)。finding_id 传 finding_node_id（report_finding 第一行的数字）。" + previousDeliveryReportSaveGuidanceV9 + "保存时 ARTEX 会在证据说明内成对附加全部已绑定 HTTP 请求和响应。正文按材料用途称呼，不抄写内部证据 ID 或重复报文。cvss_vector 提供完整 CVSS 4.0 Base 向量。"

const previousDeliveryReportSaveGuidanceV10 = `以下结构和写作要求只适用于交付报告字段；详细报告仍保留原有章节和完整台账。交付报告须包含一个漏洞名称标题、一行 CVSS 4.0 信息，并按顺序使用二级标题：描述、修复建议、测试过程、攻击链路、证据说明。描述含“定级依据”；测试过程含“发现过程与攻击思路”“失败尝试与未验证项”“Burp 复现”；证据说明含“复测标准”。正文尽量简短，通常不超过 800 字；复杂案例可超过，不得删掉关键证据来凑长度。测试时间按记录换算为北京时间，缺失时写“未记录”。HTTP 问题说明 Burp Repeater 的实际使用情况或复测步骤。ARTEX 会附加完整原始请求和响应，不要在正文重复转述。

逐项区分观察到的行为、已确认的安全影响和已确认的根因。状态码、响应头、字段变化或 CVSS 向量只能证明其显示的信息，不能单独证明跨账号访问成功、文件正文已返回或真实数据已泄露。缺少响应正文、身份/权限证明或前后状态时，明确写“未验证”；安全缺陷尚未确认时，修复建议只列需要补齐的证据，不给代码改动结论。
材料标记为合成、演示或占位时，相关身份、结果和内容只能称为样本观察，并明确未测试真实目标；不得称为真实用户资料、敏感数据或实际泄露。CVSS 涉及未观察到的影响时，说明评分前提待复核。
根因只在源码、配置或服务端日志直接支持时填写。行为已确认而根因未知时，只建议一项针对已确认行为的可观察修复结果，不推断具体实现、不列备选方案；行为尚未确认时只列补证步骤。
复现步骤和攻击链只使用记录中的身份条件、工具、命令、请求行、次数与结果；未记录时明确写未记录，不添加命令、工具、认证动作或测试结果。`
const previousFindingReportToolDescriptionTemplateV10 = "为已登记的漏洞一次写入/更新【详细报告】和【交付报告】(Markdown 全文，整段覆盖)。finding_id 传 finding_node_id（report_finding 第一行的数字）。" + previousDeliveryReportSaveGuidanceV10 + "保存时 ARTEX 会在证据说明内成对附加全部已绑定 HTTP 请求和响应。正文按材料用途称呼，不抄写内部证据 ID 或重复报文。cvss_vector 提供完整 CVSS 4.0 Base 向量。"

const findingReportToolDescription = "为已登记的漏洞一次写入/更新【详细报告】和【交付报告】(Markdown 全文，整段覆盖)。finding_id 传 finding_node_id（report_finding 第一行的数字）。" + agent.DeliveryReportSaveGuidance + "保存时 ARTEX 会在证据说明内成对附加全部已绑定 HTTP 请求和响应。正文按材料用途称呼，不抄写内部证据 ID 或重复报文。cvss_vector 提供完整 CVSS 4.0 Base 向量。"

func previousFindingReportToolDescriptions() []string {
	return []string{
		previousFindingReportToolDescription,
		previousFindingReportToolDescriptionTemplateV1,
		previousFindingReportToolDescriptionTemplateV2,
		previousFindingReportToolDescriptionTemplateV3,
		previousFindingReportToolDescriptionTemplateV4,
		previousFindingReportToolDescriptionTemplateV5,
		previousFindingReportToolDescriptionTemplateV6,
		previousFindingReportToolDescriptionTemplateV7,
		previousFindingReportToolDescriptionTemplateV8,
		previousFindingReportToolDescriptionTemplateV9,
		previousFindingReportToolDescriptionTemplateV10,
	}
}

func reporterToolDescriptionNeedsTemplateUpgrade(description string) bool {
	for _, previous := range previousFindingReportToolDescriptions() {
		if description == previous {
			return true
		}
	}
	return false
}

// finding_id remains the finding node ID used by native report callers. The
// existing evidence-version transaction still writes both reports together.
func (s *Server) toolUpdateFindingReport() actool.CoreTool {
	evidenceQuotes := agent.EvidenceQuotesSchema()
	evidenceQuotes["description"] = "可选的逐字原文引用；traffic_id 必须是已绑定到该漏洞的真实流量 ID。只核对 proof/verification 的 HTTP 请求或响应正文，不代表漏洞已确认。"
	return wrTool("update_finding_report",
		findingReportToolDescription,
		objSchema(map[string]any{
			"finding_id":       map[string]any{"type": "integer", "description": "目标漏洞 id(report_finding 返回的 id)"},
			"report":           strParam("详细报告全文,Markdown 格式"),
			"delivery_report":  strParam("与详细报告同次撰写的开发交付报告全文，Markdown 格式；固定二级标题依次为：" + agent.DeliveryReportSectionOrder),
			"cvss_vector":      strParam("AI 根据证据给出的完整 CVSS 4.0 Base 向量，按 AV/AC/AT/PR/UI/VC/VI/VA/SC/SI/SA 顺序"),
			"evidence_version": map[string]any{"type": "integer", "description": "get_finding_traffic 返回的证据 version；用于防止报告覆盖新的证据变更"},
			"evidence_quotes":  evidenceQuotes,
			"counterevidence":  map[string]any{"type": "string", "description": "可选：尝试过但未成立的路径、反例或与结论冲突的观察"},
		}, "finding_id", "report", "delivery_report", "cvss_vector", "evidence_version"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				EvidenceVersion *int64                     `json:"evidence_version"`
				FindingID       json.RawMessage            `json:"finding_id"`
				Report          string                     `json:"report"`
				DeliveryReport  string                     `json:"delivery_report"`
				CVSSVector      string                     `json:"cvss_vector"`
				EvidenceQuotes  *[]db.FindingEvidenceQuote `json:"evidence_quotes"`
				Counterevidence *string                    `json:"counterevidence"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("报告参数不是有效 JSON：" + err.Error()), nil
			}
			if !agent.IsFindingTrafficBindingEnabled() {
				a.EvidenceQuotes = nil
			}
			nodeID := parseProfileID(a.FindingID) // 复用「数字或数字字符串」解析
			if nodeID <= 0 {
				return actool.Errorf("finding_id 无效"), nil
			}
			var n int64
			var err error
			if a.DeliveryReport != "" || a.CVSSVector != "" {
				if strings.TrimSpace(a.DeliveryReport) == "" || a.EvidenceVersion == nil {
					return actool.Errorf("交付报告和 evidence_version 必填"), nil
				}
				vector, ok := normalizeCVSS4BaseVector(a.CVSSVector)
				if !ok {
					return actool.Errorf("CVSS 4.0 Base 向量无效"), nil
				}
				if err := validateDeliveryReportTemplate(a.DeliveryReport, vector); err != nil {
					return actool.Errorf(err.Error()), nil
				}
				findingID, lookupErr := s.m.pg.FindingIDByNodeID(nodeID)
				if lookupErr != nil {
					return actool.Errorf(lookupErr.Error()), nil
				}
				narrative := normalizeDeliveryNarrative(a.DeliveryReport, false)
				deliveryReport, appendErr := s.appendDeliveryTrafficEvidence(ctx, findingID, *a.EvidenceVersion, narrative)
				if appendErr != nil {
					return actool.Errorf("附加完整 HTTP 流量证据失败：" + appendErr.Error()), nil
				}
				n, err = s.m.pg.SetFindingReportsByNodeID(ctx, nodeID, a.Report, deliveryReport, vector, *a.EvidenceVersion)
			} else {
				n, err = s.m.pg.SetFindingReportVersionByNodeID(ctx, nodeID, a.Report, a.EvidenceVersion)
			}
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if n == 0 {
				return actool.Errorf(fmt.Sprintf("未找到 finding_id=%d 对应的漏洞记录(先用 report_finding 登记)", nodeID)), nil
			}
			if a.EvidenceQuotes != nil || a.Counterevidence != nil {
				findingID, findErr := s.m.pg.FindingIDByNodeID(nodeID)
				if findErr != nil {
					return actool.Errorf(findErr.Error()), nil
				}
				if err := s.evidenceStore().UpdateFindingEvidence(ctx, findingID, a.EvidenceQuotes, a.Counterevidence); err != nil {
					return actool.Errorf(err.Error()), nil
				}
			}
			if a.DeliveryReport != "" {
				return actool.Text(fmt.Sprintf("finding %d reports updated (detailed %d chars, delivery %d chars including original traffic)", nodeID, len(a.Report), len(a.DeliveryReport))), nil
			}
			return actool.Text(fmt.Sprintf("finding %d report updated (%d chars)", nodeID, len(a.Report))), nil
		})
}

// deriveTaskStatus mirrors listTasks' status derivation for the list_tasks tool.
func (s *Server) deriveTaskStatus(t *Task) string {
	lifecycle := t.lifecycleSnapshot()
	switch {
	case isTerminalStatus(lifecycle.Status):
		return lifecycle.Status
	case lifecycle.Paused || s.engine.IsPaused(t.ID):
		return "paused"
	case s.engine.ReadyFor(t) && s.engine.Started(t.ID):
		return "running"
	}
	return "created"
}

// orchestrationToolSeeds seeds the cross-task tools into the tools table so they
// are bindable per-agent (default: bound to nobody — opt-in for orchestration
// agents). First-insert only, like the traffic seeds.
func (s *Server) seedOrchestrationTools() {
	// task-op + platform tools default-bind to the built-in Auto agent (它天生用来
	// 操作平台)。SeedTool 首插入生效;老库已 seed 的行由 seedAutoDefaultBindings 补绑。
	autoAgents, _ := json.Marshal([]string{"auto"})
	for _, t := range s.orchestrationTools() {
		schema, _ := json.Marshal(t.InputSchema())
		bindings := autoAgents
		if t.Name() == "bind_finding_traffic" {
			bindings = json.RawMessage(`["reporter"]`)
		}
		_ = s.m.PG().SeedTool(t.Name(), t.Description(), schema, bindings)
	}
	s.upgradeFindingReportToolSchema()
	for _, t := range s.platformTools() {
		schema, _ := json.Marshal(t.InputSchema())
		_ = s.m.PG().SeedTool(t.Name(), t.Description(), schema, autoAgents)
	}
	s.refreshBuiltinToolSchemas()
	s.seedAutoDefaultBindings()
	s.seedPlannerDefaultBindings()
	s.seedPlannerListAssetsBinding()
	s.seedCompanyScopeRebind()
	s.seedWorkerReadToolsUnbind() // list_facts/list_companies/list_worker_traces 从 worker 默认解绑(一次性)
	s.seedWorkerReadbackRebind()  // 修复旧迁移误删：把 search_all_worker_traces/get_worker_trace/node_detail 补绑回 worker(一次性)
	s.seedAutoReportFindingBinding()
	s.unbindGoalMetDefault()
	s.reseedGoalsPrompt()                  // goals 提示词加入「抽操作约束」步 → 旧库追加一版新默认(一次性)
	s.reseedMainAgentPrompt()              // mainagent 提示词加入「目标达成后 add_intent 反问是否建目标」(一次性)
	s.upgradeVerificationPrompts()         // 仅替换仍为旧默认值的提示词
	s.seedReporterAgent()                  // 预置「报告撰写」agent + 工具绑定 + finding 触发器(一次性)
	s.upgradeReporterDefaultPrompt()       // 老库默认 prompt 增加交付报告，保留用户自定义版本
	s.upgradeReporterDefaultPromptV3()     // 默认报告使用真人可读内容并自动附加原始报文
	s.upgradeReporterDeliveryTemplate()    // 默认交付报告升级为真人可读标题和链路图规范
	s.upgradeReporterDeliveryTemplateV17() // 分离 Markdown 报告与 JSON 草稿规则，避免格式指令冲突
	s.upgradeReporterDeliveryTemplateV18() // 统一事实整理、影响边界和攻击链顺序要求
	s.upgradeReporterDeliveryTemplateV19() // 明确接口路径、字数检查和单一修复实现
	s.upgradeReporterDeliveryTemplateV20() // 更新共享攻击链规范，避免旧默认提示词重复叠加
	s.upgradeReporterDeliveryTemplateV21() // 收紧合成样本、根因和未验证影响的表述
	s.upgradeReporterDeliveryTemplateV22() // 明确独立对照分支、原样命令和潜在影响边界
	s.upgradeReporterDeliveryTemplateV23() // 改善 Burp 请求包、报告术语和攻击链可读性
	s.upgradeReporterDeliveryTemplateV24() // 要求所有 HTTP 报告附 Burp 请求包
	s.upgradeReporterDeliveryTemplateV25() // 为交付报告增加字段篇幅预算与去重要求
	s.upgradeReporterDeliveryTemplateV26() // 区分根因证据与有依据的行为修复建议
	s.upgradeReporterDeliveryTemplateV27() // 禁止合成内容误报泄露并收敛为单一修复措施
	s.upgradeReporterDeliveryTemplateV28() // 禁止非 HTTP 请求包与未经确认的条件式修复结论
	s.upgradeReporterDeliveryTemplateV29() // 收敛常见修复措施并核对每次请求结果
	s.upgradeReporterDeliveryTemplateV30() // 固定常见单项修复并补齐发现过程标题
	s.upgradeReporterDeliveryTemplateV31() // 明确合成数据的潜在机密性影响表述
	s.upgradeReporterDeliveryTemplateV32() // 确保 HTTP 报告含 Burp 请求并收敛修复措施
	s.upgradeReporterDeliveryTemplateV33() // 禁止把合成材料写成已发生的机密性影响
	s.upgradeReporterDeliveryTemplateV34() // 明确合成范围并整理 Burp 请求与攻击链
	s.upgradeReporterDeliveryTemplateV35() // 固定攻击链分组节点，避免出现第二个根
	s.upgradeReporterDeliveryTemplateV36() // 避免把合成文件称为真实敏感资产
	s.upgradeReporterDeliveryTemplateV37() // 固定交付报告六项结构并提供 Burp 复现请求包
	s.upgradeReporterTriggerMessage()      // 老库触发消息同步报告版式与链路图规范
	s.upgradeReporterTriggerMessageV11()   // 移除触发消息中重复的报告写作规则
	s.seedFindingTrafficTools()            // 增加可选证据参数及只读证据工具，保留用户配置
	s.seedFindingWorkflowTools()
	// 注：pentest 的默认工具绑定无需迁移——BuiltinToolSeeds 在全新初始化时就把
	// list_assets/insert_assets/report_finding/list_findings/list_companies 连同
	// pentest 一起 seed 好了（项目尚无旧库，不做迁移）。
}

// refreshBuiltinToolSchemas propagates code schema/description changes on the
// orchestration + platform tools into already-seeded rows ONCE per version flag —
// SeedTool is first-insert-only, so a new param (e.g. spawn_task 的 llm_profile) never
// reaches an old DB otherwise. Preserves each tool's agent binding + enabled flag.
// Bump the flag whenever these tools' schemas/descriptions change in code.
func (s *Server) refreshBuiltinToolSchemas() {
	const flag = "tool_schema_refresh_v7_list_facts_paging"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	tools := append(s.orchestrationTools(), s.platformTools()...)
	for _, t := range tools {
		schema, _ := json.Marshal(t.InputSchema())
		if err := s.m.pg.RefreshToolDefaults(t.Name(), t.Description(), schema); err != nil {
			log.Printf("[tools] refresh %s schema failed: %v", t.Name(), err)
		}
	}
	// 同时把部分内置 agent 工具刷成代码默认：
	//   - goal_met：旧库 seed 的描述带“结束本轮规划”的误导，会让 planner 把它当成
	//     “结束空轮”的手段、刚开跑就误判整个任务完成。
	//   - insert_assets：新增 related 入参(标记资产是否与当前任务相关、决定是否入覆盖度)，
	//     SeedTool 首插入only，旧库已 seed 的 schema 否则收不到这个新参数。
	//   - list_facts：改为分页，新增 limit/before/q 入参；旧库已 seed 的空 schema 否则
	//     在工具管理页显示「无参数」，模型也拿不到这几个参数说明。
	refreshBuiltin := map[string]bool{"goal_met": true, "insert_assets": true, "list_facts": true}
	for _, sd := range agent.BuiltinToolSeeds() {
		if !refreshBuiltin[sd.Key] {
			continue
		}
		schema, _ := json.Marshal(sd.Schema)
		if err := s.m.pg.RefreshToolDefaults(sd.Key, sd.Desc, schema); err != nil {
			log.Printf("[tools] refresh %s desc failed: %v", sd.Key, err)
		}
	}
	_ = s.m.pg.SetSetting(flag, "true")
	log.Printf("[tools] 已刷新 orchestration/platform 工具 schema 到代码默认(一次性)")
}

func (s *Server) upgradeFindingReportToolSchema() {
	const flag = "reporter_report_tool_schema_delivery_v2"
	if value, _, _ := s.m.pg.GetSetting(flag); value == "true" {
		return
	}
	tool := s.toolUpdateFindingReport()
	current, err := s.m.pg.GetTool(tool.Name())
	if err != nil {
		log.Printf("[reporter] 读取报告工具配置失败: %v", err)
		return
	}
	if current == nil || !current.System {
		return
	}
	description := current.Description
	const oldDescription = "为已登记的漏洞写入/更新【详细报告】(Markdown 全文,整段覆盖旧内容)。finding_id 传 report_finding 返回的那个 id(\"finding recorded: <id>\" 里的数字)。报告建议包含:漏洞概述、影响与危害、复现步骤、证据/PoC、修复建议。"
	if description == oldDescription || description == previousFindingReportToolDescription || description == previousFindingReportToolDescriptionTemplateV1 || description == previousFindingReportToolDescriptionTemplateV2 {
		description = tool.Description()
	}
	schema, err := json.Marshal(tool.InputSchema())
	if err != nil {
		log.Printf("[reporter] 编码报告工具 schema 失败: %v", err)
		return
	}
	if err := s.m.pg.RefreshToolDefaults(tool.Name(), description, schema); err != nil {
		log.Printf("[reporter] 刷新报告工具 schema 失败: %v", err)
		return
	}
	if err := s.m.pg.SetSetting(flag, "true"); err != nil {
		log.Printf("[reporter] 保存报告工具 schema 迁移标记失败: %v", err)
		return
	}
	log.Printf("[reporter] 已更新报告工具参数 schema")
}

func (s *Server) upgradeReporterDefaultPrompt() {
	const flag = "reporter_prompt_delivery_report_v1"
	if value, _, _ := s.m.pg.GetSetting(flag); value == "true" {
		return
	}
	agentRow, err := s.m.pg.GetAgentByKey("reporter")
	if err != nil {
		log.Printf("[reporter] 读取 agent 失败: %v", err)
		return
	}
	if agentRow == nil {
		return
	}
	current, err := s.m.pg.CurrentPrompt(agentRow.ID)
	if err != nil {
		log.Printf("[reporter] 读取 prompt 失败: %v", err)
		return
	}
	const legacyDefaultHash = "8ba98208f6c5f2ccb103c88ef13239c4264733400c0e3dfec96d3a3572d78d39"
	if fmt.Sprintf("%x", sha256.Sum256([]byte(current))) == legacyDefaultHash {
		if _, err := s.m.pg.ResetPromptToDefault(agentRow.ID, agent.ReporterDefaultPrompt); err != nil {
			log.Printf("[reporter] 升级默认 prompt 失败: %v", err)
			return
		}
		log.Printf("[reporter] 默认 prompt 已升级为同时撰写详细报告和交付报告")
	}
	if err := s.m.pg.SetSetting(flag, "true"); err != nil {
		log.Printf("[reporter] 保存默认 prompt 迁移标记失败: %v", err)
	}
}

func (s *Server) upgradeReporterDefaultPromptV3() {
	const flag = "reporter_prompt_delivery_report_v3"
	if value, _, _ := s.m.pg.GetSetting(flag); value == "true" {
		return
	}
	agentRow, err := s.m.pg.GetAgentByKey("reporter")
	if err != nil {
		log.Printf("[reporter] 读取 agent 失败: %v", err)
		return
	}
	if agentRow == nil {
		return
	}
	current, err := s.m.pg.CurrentPrompt(agentRow.ID)
	if err != nil {
		log.Printf("[reporter] 读取 prompt 失败: %v", err)
		return
	}
	currentHash := fmt.Sprintf("%x", sha256.Sum256([]byte(current)))
	const previousDefaultHash = "4c0afdd38b38d7fece3ee18e644a0e829b113a00a86bbb798be47457e6489949"
	const previousWorktreeDefaultHash = "5525dc3abf6563ccb4d07c6f8d40b9f417901ed61370c1175bacffb0e220c56a"
	if currentHash == previousDefaultHash || currentHash == previousWorktreeDefaultHash {
		if _, err := s.m.pg.ResetPromptToDefault(agentRow.ID, agent.ReporterDefaultPrompt); err != nil {
			log.Printf("[reporter] 升级默认 prompt 失败: %v", err)
			return
		}
		log.Printf("[reporter] 默认 prompt 已升级为由 ARTEX 附加授权测试原始报文的交付报告规范")
	}
	if err := s.m.pg.SetSetting(flag, "true"); err != nil {
		log.Printf("[reporter] 保存默认 prompt 迁移标记失败: %v", err)
	}
}

func reporterPromptNeedsTemplateUpgrade(prompt string) bool {
	return reporterPromptHashNeedsTemplateUpgrade(fmt.Sprintf("%x", sha256.Sum256([]byte(prompt))))
}

func reporterPromptHashNeedsTemplateUpgrade(hash string) bool {
	switch hash {
	case "b1ab0800d8137a0476f02d6e2b7e5380133b62f060096ad52dc412769af152c9", // 旧版默认交付规范
		"8b3000d01b7f8bdee0a4b1f4fcee3beb8350744d10144c5c2669090acffd83ed", // 补回攻击链章节的默认值
		"8f8e5a14828823f4b3ca6f255ed0a8775787bb31d08c5cb2c5576222ad2a81bd", // 旧版固定五节模板
		"169a228581af77e71037a37fb350013c6e5d9d7e3ffa80fd5ff1d2cbec2618c4", // 精简标题与树形攻击链默认值
		"66b2c31047b3b2ad974673d5cbf4462e4be4f0274b455876b5f51a5131bd151d", // 已知旧版改写标题与限制规则
		"3f39e940b17ac4ac44ce9149863c0714d9ea7c84c3f3fa7c0fd65034f07629de", // 上一版内置 Reporter 默认提示词
		"dde76414b475c7d51011383357e2b4709bcfa1a1454fa39c926f0812becf2256", // 固定五节默认提示词
		"fa49ee7b606d0bdc5d12c4432b522fb07e7a4d7599286bd2acdffe32ff462a73", // 上一版固定模板默认提示词
		"3103d7d553a88859aa582e8c9841cfbcd151caa03684d0746b9b0e2a3c0ffd6d", // 上一版五节简版默认提示词
		"c5fdbe6a4069cafda38f2c26b560c11faea0186f7554cfe472c26330950fc43f", // v10 固定报告默认提示词
		"5d1f0391ca434e3d7f3649bea87f934c639ef8f80eb9b77d26858174519e5944", // v10 加入事实边界后的默认提示词
		"8e639fbad0e554fe409bc34dc1c329992d7fb38e5f4fe8d61614a1e2c8f75138", // v11 精简事实边界提示词
		"c6c12f63c6c24062529222027333d59f49ff34e0e18ab464589d31f7b955e813", // v13 默认交付报告提示词
		"1b97167790b635b784598e7ff380ded5d798843156d9f299fd2db572a2ac53bd", // v14 默认交付报告提示词
		"5a4985c0a7839ed1a9602d2bfa26342fbce264c0608a46d081ea467904ccbf3e", // v15 默认交付报告提示词
		"92150e16f0ec293e597f4b5b0631ac1793a5515d93fb614c1449f2c79cae53df", // 当前版重复说明提示词
		"786d3a6b59b52c4d998398d297f41091d2db0187d2f47f21c3f531e9ec5489c2", // v17 事实整理提示词
		"17aa6f65e6d88922dc086b17730357c00b3ef9d55535a85d513eb3cc795ede4e", // v18 事实整理默认提示词
		"2e629b3e35fcab552a9a901419af419dfb721ebf15a654e9f8443f1c44d2d3ee", // v19 旧版 Reporter 默认提示词
		"29a290fbc2d42bce7cf282b8c4da46605ee4deac38b9cf7df2500dad13d8171f", // v20 旧版 Reporter 默认提示词
		"cf8c3a66a8230ab9bf7095d32e7025e56135010936d1f86765acc413ba441023", // v21 证据边界默认提示词
		"0b3a0eec07ad86b6302a9072399ad5cecf46cf3d21dabd0192ee5277b5191834", // v22 原样命令与证据边界默认提示词
		"54343d87df0ffdff1aeec0d3e58dd3bd23b7fb138884bc8719cc01ca5e85fe63": // v23 Burp 请求包与可读性默认提示词
		return true
	case "506d290c34bc78e4d52d1665b5e740466a379fe803b4cff2e3dc2efca090e371": // v24 必需请求包默认提示词
		return true
	case "f1850be22e070adce5879d7e6cf58e0afb6509fdc5892617751b97f700353ba9": // v25 篇幅预算与修复边界默认提示词
		return true
	case "b444692a343f054ea0685828b3c1df90e3735d279972786fa87c053134a6502e": // v26 根因与行为修复边界默认提示词
		return true
	case "26491cebbf5006c3a8d28bf29943b84bd395e3f3d55f60cffae114716be78867": // v27 合成影响与修复措施约束默认提示词
		return true
	case "c9a7020f8405687afaaca33e30f5ed968ba68b9b2fa69b340685b85ead2e467b": // v28 非 HTTP 与证据不足边界默认提示词
		return true
	case "16cc0718092b4ab57a5fd320ea70ef746da25d214e2e9ba048e13bcffca7266e": // v29 单项修复与请求覆盖默认提示词
		return true
	case "6922a24c94dcc6b2e4b1021163107aea7d3d87480fff40a79bee27a5211b5afd": // v30 合成数据机密性表述默认提示词
		return true
	case "1f5f062a02161d370dbfa89f260b2d1318941747ebc3d320a376bae4256ac086": // v31 修复措施与合成影响默认提示词
		return true
	case "b5aa7ef16999d95655823f686c42d1eeec2e8782b0f3364209cb98fffe27e716": // v32 Burp 请求与单项修复默认提示词
		return true
	case "cbb9cdfde209d33d5aee3a52581d3dbb7612b4fc0be99c0dc4076acbb10e0c52": // v33 合成范围和报告结构默认提示词
		return true
	case "487018396adc75c029f8864b55ca8d17a6b612376ea75eace5dd88a31ae15016": // v34 合成范围与攻击链默认提示词
		return true
	case "9d700f4f89005e55b28d163ce5eda116b5a0c81eb5d64c3563997a02ede09ae4": // v35 合成数据敏感资产边界默认提示词
		return true
	case "b283bbd9f8f2a3ff6c94711491b0c20ca84391ee1610cab43f749e09e6b4949b": // v36 六项交付报告结构升级前的默认提示词
		return true
	default:
		return false
	}
}

func (s *Server) upgradeReporterDeliveryTemplateV17() {
	const flag = "reporter_prompt_delivery_template_v17"
	if value, _, err := s.m.pg.GetSetting(flag); err != nil {
		log.Printf("[reporter] 读取精简提示词迁移标记失败: %v", err)
		return
	} else if value == "true" {
		return
	}
	agentRow, err := s.m.pg.GetAgentByKey("reporter")
	if err != nil {
		log.Printf("[reporter] 读取 agent 失败: %v", err)
		return
	}
	if agentRow == nil {
		return
	}
	current, err := s.m.pg.CurrentPrompt(agentRow.ID)
	if err != nil {
		log.Printf("[reporter] 读取 prompt 失败: %v", err)
		return
	}
	if reporterPromptNeedsTemplateUpgrade(current) {
		if _, err := s.m.pg.ResetPromptToDefault(agentRow.ID, agent.ReporterDefaultPrompt); err != nil {
			log.Printf("[reporter] 精简默认交付报告提示词失败: %v", err)
			return
		}
		log.Printf("[reporter] 默认提示词已移除重复的交付报告规则")
	}
	if err := s.m.pg.SetSetting(flag, "true"); err != nil {
		log.Printf("[reporter] 保存精简提示词迁移标记失败: %v", err)
	}
}

func (s *Server) upgradeReporterDeliveryTemplateV18() {
	const flag = "reporter_prompt_delivery_template_v18"
	if value, _, err := s.m.pg.GetSetting(flag); err != nil {
		log.Printf("[reporter] 读取事实整理提示词迁移标记失败: %v", err)
		return
	} else if value == "true" {
		return
	}
	agentRow, err := s.m.pg.GetAgentByKey("reporter")
	if err != nil {
		log.Printf("[reporter] 读取 agent 失败: %v", err)
		return
	}
	if agentRow == nil {
		return
	}
	current, err := s.m.pg.CurrentPrompt(agentRow.ID)
	if err != nil {
		log.Printf("[reporter] 读取 prompt 失败: %v", err)
		return
	}
	if reporterPromptNeedsTemplateUpgrade(current) {
		if _, err := s.m.pg.ResetPromptToDefault(agentRow.ID, agent.ReporterDefaultPrompt); err != nil {
			log.Printf("[reporter] 更新事实整理交付报告提示词失败: %v", err)
			return
		}
		log.Printf("[reporter] 默认提示词已同步事实整理与证据边界规范")
	}
	if err := s.m.pg.SetSetting(flag, "true"); err != nil {
		log.Printf("[reporter] 保存事实整理提示词迁移标记失败: %v", err)
	}
}

func (s *Server) upgradeReporterDeliveryTemplateV19() {
	const flag = "reporter_prompt_delivery_template_v19"
	if value, _, err := s.m.pg.GetSetting(flag); err != nil {
		log.Printf("[reporter] 读取报告篇幅与接口路径迁移标记失败: %v", err)
		return
	} else if value == "true" {
		return
	}
	agentRow, err := s.m.pg.GetAgentByKey("reporter")
	if err != nil {
		log.Printf("[reporter] 读取 agent 失败: %v", err)
		return
	}
	if agentRow == nil {
		return
	}
	current, err := s.m.pg.CurrentPrompt(agentRow.ID)
	if err != nil {
		log.Printf("[reporter] 读取 prompt 失败: %v", err)
		return
	}
	if reporterPromptNeedsTemplateUpgrade(current) {
		if _, err := s.m.pg.ResetPromptToDefault(agentRow.ID, agent.ReporterDefaultPrompt); err != nil {
			log.Printf("[reporter] 更新交付报告篇幅与接口路径要求失败: %v", err)
			return
		}
		log.Printf("[reporter] 默认提示词已同步接口路径和正文篇幅要求")
	}
	if err := s.m.pg.SetSetting(flag, "true"); err != nil {
		log.Printf("[reporter] 保存报告篇幅与接口路径迁移标记失败: %v", err)
	}
}

func (s *Server) upgradeReporterDeliveryTemplateV20() {
	const flag = "reporter_prompt_delivery_template_v20"
	if value, _, err := s.m.pg.GetSetting(flag); err != nil {
		log.Printf("[reporter] 读取共享链路提示词迁移标记失败: %v", err)
		return
	} else if value == "true" {
		return
	}
	agentRow, err := s.m.pg.GetAgentByKey("reporter")
	if err != nil {
		log.Printf("[reporter] 读取 agent 失败: %v", err)
		return
	}
	if agentRow == nil {
		return
	}
	current, err := s.m.pg.CurrentPrompt(agentRow.ID)
	if err != nil {
		log.Printf("[reporter] 读取 prompt 失败: %v", err)
		return
	}
	if reporterPromptNeedsTemplateUpgrade(current) {
		if _, err := s.m.pg.ResetPromptToDefault(agentRow.ID, agent.ReporterDefaultPrompt); err != nil {
			log.Printf("[reporter] 同步共享攻击链规范失败: %v", err)
			return
		}
		log.Printf("[reporter] 默认提示词已同步共享攻击链规范")
	}
	if err := s.m.pg.SetSetting(flag, "true"); err != nil {
		log.Printf("[reporter] 保存共享链路提示词迁移标记失败: %v", err)
	}
}

func (s *Server) upgradeReporterDeliveryTemplateV21() {
	const flag = "reporter_prompt_delivery_template_v21"
	if value, _, err := s.m.pg.GetSetting(flag); err != nil {
		log.Printf("[reporter] 读取证据边界提示词迁移标记失败: %v", err)
		return
	} else if value == "true" {
		return
	}
	previousDescriptions := previousFindingReportToolDescriptions()
	placeholders := make([]string, len(previousDescriptions))
	args := make([]any, 1, len(previousDescriptions)+1)
	args[0] = findingReportToolDescription
	for index, description := range previousDescriptions {
		placeholders[index] = fmt.Sprintf("$%d", index+2)
		args = append(args, description)
	}
	query := fmt.Sprintf(`UPDATE tools SET description=$1,updated_at=now()
		WHERE key='update_finding_report' AND system AND description IN (%s)`, strings.Join(placeholders, ","))
	if _, err := s.m.pg.Exec(query, args...); err != nil {
		log.Printf("[reporter] 更新报告工具证据边界说明失败: %v", err)
		return
	}
	agentRow, err := s.m.pg.GetAgentByKey("reporter")
	if err != nil {
		log.Printf("[reporter] 读取 agent 失败: %v", err)
		return
	}
	if agentRow == nil {
		return
	}
	current, err := s.m.pg.CurrentPrompt(agentRow.ID)
	if err != nil {
		log.Printf("[reporter] 读取 prompt 失败: %v", err)
		return
	}
	if reporterPromptNeedsTemplateUpgrade(current) {
		if _, err := s.m.pg.ResetPromptToDefault(agentRow.ID, agent.ReporterDefaultPrompt); err != nil {
			log.Printf("[reporter] 更新报告证据边界要求失败: %v", err)
			return
		}
		log.Printf("[reporter] 默认提示词已同步证据、根因和样本影响边界")
	}
	if err := s.m.pg.SetSetting(flag, "true"); err != nil {
		log.Printf("[reporter] 保存证据边界提示词迁移标记失败: %v", err)
	}
}

func (s *Server) upgradeReporterDeliveryTemplateV22() {
	const flag = "reporter_prompt_delivery_template_v22"
	if value, _, err := s.m.pg.GetSetting(flag); err != nil {
		log.Printf("[reporter] 读取独立对照提示词迁移标记失败: %v", err)
		return
	} else if value == "true" {
		return
	}
	previousDescriptions := previousFindingReportToolDescriptions()
	placeholders := make([]string, len(previousDescriptions))
	args := make([]any, 1, len(previousDescriptions)+1)
	args[0] = findingReportToolDescription
	for index, description := range previousDescriptions {
		placeholders[index] = fmt.Sprintf("$%d", index+2)
		args = append(args, description)
	}
	query := fmt.Sprintf(`UPDATE tools SET description=$1,updated_at=now()
		WHERE key='update_finding_report' AND system AND description IN (%s)`, strings.Join(placeholders, ","))
	if _, err := s.m.pg.Exec(query, args...); err != nil {
		log.Printf("[reporter] 更新报告工具独立对照说明失败: %v", err)
		return
	}
	agentRow, err := s.m.pg.GetAgentByKey("reporter")
	if err != nil {
		log.Printf("[reporter] 读取 agent 失败: %v", err)
		return
	}
	if agentRow == nil {
		return
	}
	current, err := s.m.pg.CurrentPrompt(agentRow.ID)
	if err != nil {
		log.Printf("[reporter] 读取 prompt 失败: %v", err)
		return
	}
	if reporterPromptNeedsTemplateUpgrade(current) {
		if _, err := s.m.pg.ResetPromptToDefault(agentRow.ID, agent.ReporterDefaultPrompt); err != nil {
			log.Printf("[reporter] 更新报告独立对照提示词失败: %v", err)
			return
		}
		log.Printf("[reporter] 默认提示词已同步独立对照、原样命令和潜在影响边界")
	}
	if err := s.m.pg.SetSetting(flag, "true"); err != nil {
		log.Printf("[reporter] 保存独立对照提示词迁移标记失败: %v", err)
	}
}

func (s *Server) upgradeReporterDeliveryTemplateV23() {
	const flag = "reporter_prompt_delivery_template_v23"
	if value, _, err := s.m.pg.GetSetting(flag); err != nil {
		log.Printf("[reporter] 读取可复现请求包提示词迁移标记失败: %v", err)
		return
	} else if value == "true" {
		return
	}
	agentRow, err := s.m.pg.GetAgentByKey("reporter")
	if err != nil {
		log.Printf("[reporter] 读取 agent 失败: %v", err)
		return
	}
	if agentRow == nil {
		return
	}
	current, err := s.m.pg.CurrentPrompt(agentRow.ID)
	if err != nil {
		log.Printf("[reporter] 读取 prompt 失败: %v", err)
		return
	}
	if reporterPromptNeedsTemplateUpgrade(current) {
		if _, err := s.m.pg.ResetPromptToDefault(agentRow.ID, agent.ReporterDefaultPrompt); err != nil {
			log.Printf("[reporter] 更新 Burp 请求包与可读性规则失败: %v", err)
			return
		}
		log.Printf("[reporter] 默认提示词已同步 Burp 请求包、通俗表达和攻击链结果规则")
	}
	if err := s.m.pg.SetSetting(flag, "true"); err != nil {
		log.Printf("[reporter] 保存可复现请求包提示词迁移标记失败: %v", err)
	}
}

func (s *Server) upgradeReporterDeliveryTemplateV24() {
	const flag = "reporter_prompt_delivery_template_v24"
	if value, _, err := s.m.pg.GetSetting(flag); err != nil {
		log.Printf("[reporter] 读取必需 Burp 请求包迁移标记失败: %v", err)
		return
	} else if value == "true" {
		return
	}
	agentRow, err := s.m.pg.GetAgentByKey("reporter")
	if err != nil {
		log.Printf("[reporter] 读取 agent 失败: %v", err)
		return
	}
	if agentRow == nil {
		return
	}
	current, err := s.m.pg.CurrentPrompt(agentRow.ID)
	if err != nil {
		log.Printf("[reporter] 读取 prompt 失败: %v", err)
		return
	}
	if reporterPromptNeedsTemplateUpgrade(current) {
		if _, err := s.m.pg.ResetPromptToDefault(agentRow.ID, agent.ReporterDefaultPrompt); err != nil {
			log.Printf("[reporter] 更新必需 Burp 请求包规则失败: %v", err)
			return
		}
		log.Printf("[reporter] 默认提示词已要求所有 HTTP 报告附 Burp 请求包")
	}
	if err := s.m.pg.SetSetting(flag, "true"); err != nil {
		log.Printf("[reporter] 保存必需 Burp 请求包迁移标记失败: %v", err)
	}
}

func (s *Server) upgradeReporterDeliveryTemplateV25() {
	const flag = "reporter_prompt_delivery_template_v25"
	if value, _, err := s.m.pg.GetSetting(flag); err != nil {
		log.Printf("[reporter] 读取正文篇幅预算迁移标记失败: %v", err)
		return
	} else if value == "true" {
		return
	}
	agentRow, err := s.m.pg.GetAgentByKey("reporter")
	if err != nil {
		log.Printf("[reporter] 读取 agent 失败: %v", err)
		return
	}
	if agentRow == nil {
		return
	}
	current, err := s.m.pg.CurrentPrompt(agentRow.ID)
	if err != nil {
		log.Printf("[reporter] 读取 prompt 失败: %v", err)
		return
	}
	if reporterPromptNeedsTemplateUpgrade(current) {
		if _, err := s.m.pg.ResetPromptToDefault(agentRow.ID, agent.ReporterDefaultPrompt); err != nil {
			log.Printf("[reporter] 更新正文篇幅预算提示词失败: %v", err)
			return
		}
		log.Printf("[reporter] 默认提示词已同步字段篇幅预算与事实去重规则")
	}
	if err := s.m.pg.SetSetting(flag, "true"); err != nil {
		log.Printf("[reporter] 保存正文篇幅预算迁移标记失败: %v", err)
	}
}

func (s *Server) upgradeReporterDeliveryTemplateV26() {
	const flag = "reporter_prompt_delivery_template_v26"
	if value, _, err := s.m.pg.GetSetting(flag); err != nil {
		log.Printf("[reporter] 读取行为修复建议迁移标记失败: %v", err)
		return
	} else if value == "true" {
		return
	}
	agentRow, err := s.m.pg.GetAgentByKey("reporter")
	if err != nil {
		log.Printf("[reporter] 读取 agent 失败: %v", err)
		return
	}
	if agentRow == nil {
		return
	}
	current, err := s.m.pg.CurrentPrompt(agentRow.ID)
	if err != nil {
		log.Printf("[reporter] 读取 prompt 失败: %v", err)
		return
	}
	if reporterPromptNeedsTemplateUpgrade(current) {
		if _, err := s.m.pg.ResetPromptToDefault(agentRow.ID, agent.ReporterDefaultPrompt); err != nil {
			log.Printf("[reporter] 更新行为修复建议提示词失败: %v", err)
			return
		}
		log.Printf("[reporter] 默认提示词已同步根因与行为修复边界")
	}
	if err := s.m.pg.SetSetting(flag, "true"); err != nil {
		log.Printf("[reporter] 保存行为修复建议迁移标记失败: %v", err)
	}
}

func (s *Server) upgradeReporterDeliveryTemplateV27() {
	const flag = "reporter_prompt_delivery_template_v27"
	if value, _, err := s.m.pg.GetSetting(flag); err != nil {
		log.Printf("[reporter] 读取合成材料与单一修复措施迁移标记失败: %v", err)
		return
	} else if value == "true" {
		return
	}
	agentRow, err := s.m.pg.GetAgentByKey("reporter")
	if err != nil {
		log.Printf("[reporter] 读取 agent 失败: %v", err)
		return
	}
	if agentRow == nil {
		return
	}
	current, err := s.m.pg.CurrentPrompt(agentRow.ID)
	if err != nil {
		log.Printf("[reporter] 读取 prompt 失败: %v", err)
		return
	}
	if reporterPromptNeedsTemplateUpgrade(current) {
		if _, err := s.m.pg.ResetPromptToDefault(agentRow.ID, agent.ReporterDefaultPrompt); err != nil {
			log.Printf("[reporter] 更新合成材料与单一修复措施提示词失败: %v", err)
			return
		}
		log.Printf("[reporter] 默认提示词已禁止将合成样本描述为真实泄露，并要求单一修复措施")
	}
	if err := s.m.pg.SetSetting(flag, "true"); err != nil {
		log.Printf("[reporter] 保存合成材料与单一修复措施迁移标记失败: %v", err)
	}
}

func (s *Server) upgradeReporterDeliveryTemplateV28() {
	const flag = "reporter_prompt_delivery_template_v28"
	if value, _, err := s.m.pg.GetSetting(flag); err != nil {
		log.Printf("[reporter] 读取非 HTTP 与证据不足迁移标记失败: %v", err)
		return
	} else if value == "true" {
		return
	}
	agentRow, err := s.m.pg.GetAgentByKey("reporter")
	if err != nil {
		log.Printf("[reporter] 读取 agent 失败: %v", err)
		return
	}
	if agentRow == nil {
		return
	}
	current, err := s.m.pg.CurrentPrompt(agentRow.ID)
	if err != nil {
		log.Printf("[reporter] 读取 prompt 失败: %v", err)
		return
	}
	if reporterPromptNeedsTemplateUpgrade(current) {
		if _, err := s.m.pg.ResetPromptToDefault(agentRow.ID, agent.ReporterDefaultPrompt); err != nil {
			log.Printf("[reporter] 更新非 HTTP 与证据不足提示词失败: %v", err)
			return
		}
		log.Printf("[reporter] 默认提示词已禁止非 HTTP 场景虚构请求，并收紧证据不足时的修复建议")
	}
	if err := s.m.pg.SetSetting(flag, "true"); err != nil {
		log.Printf("[reporter] 保存非 HTTP 与证据不足迁移标记失败: %v", err)
	}
}

func (s *Server) upgradeReporterDeliveryTemplateV29() {
	const flag = "reporter_prompt_delivery_template_v29"
	if value, _, err := s.m.pg.GetSetting(flag); err != nil {
		log.Printf("[reporter] 读取修复措施与请求覆盖迁移标记失败: %v", err)
		return
	} else if value == "true" {
		return
	}
	agentRow, err := s.m.pg.GetAgentByKey("reporter")
	if err != nil {
		log.Printf("[reporter] 读取 agent 失败: %v", err)
		return
	}
	if agentRow == nil {
		return
	}
	current, err := s.m.pg.CurrentPrompt(agentRow.ID)
	if err != nil {
		log.Printf("[reporter] 读取 prompt 失败: %v", err)
		return
	}
	if reporterPromptNeedsTemplateUpgrade(current) {
		if _, err := s.m.pg.ResetPromptToDefault(agentRow.ID, agent.ReporterDefaultPrompt); err != nil {
			log.Printf("[reporter] 更新修复措施与请求覆盖提示词失败: %v", err)
			return
		}
		log.Printf("[reporter] 默认提示词已明确单一修复措施并要求逐条核对重复请求")
	}
	if err := s.m.pg.SetSetting(flag, "true"); err != nil {
		log.Printf("[reporter] 保存修复措施与请求覆盖迁移标记失败: %v", err)
	}
}

func (s *Server) upgradeReporterDeliveryTemplateV30() {
	const flag = "reporter_prompt_delivery_template_v30"
	if value, _, err := s.m.pg.GetSetting(flag); err != nil {
		log.Printf("[reporter] 读取单项修复建议迁移标记失败: %v", err)
		return
	} else if value == "true" {
		return
	}
	agentRow, err := s.m.pg.GetAgentByKey("reporter")
	if err != nil {
		log.Printf("[reporter] 读取 agent 失败: %v", err)
		return
	}
	if agentRow == nil {
		return
	}
	current, err := s.m.pg.CurrentPrompt(agentRow.ID)
	if err != nil {
		log.Printf("[reporter] 读取 prompt 失败: %v", err)
		return
	}
	if reporterPromptNeedsTemplateUpgrade(current) {
		if _, err := s.m.pg.ResetPromptToDefault(agentRow.ID, agent.ReporterDefaultPrompt); err != nil {
			log.Printf("[reporter] 更新单项修复建议提示词失败: %v", err)
			return
		}
		log.Printf("[reporter] 默认提示词已固定常见修复措施并强化报告结构检查")
	}
	if err := s.m.pg.SetSetting(flag, "true"); err != nil {
		log.Printf("[reporter] 保存单项修复建议迁移标记失败: %v", err)
	}
}

func (s *Server) upgradeReporterDeliveryTemplateV31() {
	const flag = "reporter_prompt_delivery_template_v31"
	if value, _, err := s.m.pg.GetSetting(flag); err != nil {
		log.Printf("[reporter] 读取合成数据影响表述迁移标记失败: %v", err)
		return
	} else if value == "true" {
		return
	}
	agentRow, err := s.m.pg.GetAgentByKey("reporter")
	if err != nil {
		log.Printf("[reporter] 读取 agent 失败: %v", err)
		return
	}
	if agentRow == nil {
		return
	}
	current, err := s.m.pg.CurrentPrompt(agentRow.ID)
	if err != nil {
		log.Printf("[reporter] 读取 prompt 失败: %v", err)
		return
	}
	if reporterPromptNeedsTemplateUpgrade(current) {
		if _, err := s.m.pg.ResetPromptToDefault(agentRow.ID, agent.ReporterDefaultPrompt); err != nil {
			log.Printf("[reporter] 更新合成数据影响表述提示词失败: %v", err)
			return
		}
		log.Printf("[reporter] 默认提示词已区分合成数据与潜在机密性影响")
	}
	if err := s.m.pg.SetSetting(flag, "true"); err != nil {
		log.Printf("[reporter] 保存合成数据影响表述迁移标记失败: %v", err)
	}
}

func (s *Server) upgradeReporterDeliveryTemplateV32() {
	const flag = "reporter_prompt_delivery_template_v32"
	if value, _, err := s.m.pg.GetSetting(flag); err != nil {
		log.Printf("[reporter] 读取 Burp 请求与修复措施迁移标记失败: %v", err)
		return
	} else if value == "true" {
		return
	}
	agentRow, err := s.m.pg.GetAgentByKey("reporter")
	if err != nil {
		log.Printf("[reporter] 读取 agent 失败: %v", err)
		return
	}
	if agentRow == nil {
		return
	}
	current, err := s.m.pg.CurrentPrompt(agentRow.ID)
	if err != nil {
		log.Printf("[reporter] 读取 prompt 失败: %v", err)
		return
	}
	if reporterPromptNeedsTemplateUpgrade(current) {
		if _, err := s.m.pg.ResetPromptToDefault(agentRow.ID, agent.ReporterDefaultPrompt); err != nil {
			log.Printf("[reporter] 更新 Burp 请求与单项修复提示词失败: %v", err)
			return
		}
		log.Printf("[reporter] 默认提示词已补齐 Burp 请求并收敛修复措施")
	}
	if err := s.m.pg.SetSetting(flag, "true"); err != nil {
		log.Printf("[reporter] 保存 Burp 请求与修复措施迁移标记失败: %v", err)
	}
}

func (s *Server) upgradeReporterDeliveryTemplateV33() {
	const flag = "reporter_prompt_delivery_template_v33"
	if value, _, err := s.m.pg.GetSetting(flag); err != nil {
		log.Printf("[reporter] 读取合成机密性边界迁移标记失败: %v", err)
		return
	} else if value == "true" {
		return
	}
	agentRow, err := s.m.pg.GetAgentByKey("reporter")
	if err != nil {
		log.Printf("[reporter] 读取 agent 失败: %v", err)
		return
	}
	if agentRow == nil {
		return
	}
	current, err := s.m.pg.CurrentPrompt(agentRow.ID)
	if err != nil {
		log.Printf("[reporter] 读取 prompt 失败: %v", err)
		return
	}
	if reporterPromptNeedsTemplateUpgrade(current) {
		if _, err := s.m.pg.ResetPromptToDefault(agentRow.ID, agent.ReporterDefaultPrompt); err != nil {
			log.Printf("[reporter] 更新合成机密性边界提示词失败: %v", err)
			return
		}
		log.Printf("[reporter] 默认提示词已限定合成材料的机密性结论")
	}
	if err := s.m.pg.SetSetting(flag, "true"); err != nil {
		log.Printf("[reporter] 保存合成机密性边界迁移标记失败: %v", err)
	}
}

func (s *Server) upgradeReporterDeliveryTemplateV34() {
	const flag = "reporter_prompt_delivery_template_v34"
	if value, _, err := s.m.pg.GetSetting(flag); err != nil {
		log.Printf("[reporter] 读取合成范围与请求规范迁移标记失败: %v", err)
		return
	} else if value == "true" {
		return
	}
	agentRow, err := s.m.pg.GetAgentByKey("reporter")
	if err != nil {
		log.Printf("[reporter] 读取 agent 失败: %v", err)
		return
	}
	if agentRow == nil {
		return
	}
	current, err := s.m.pg.CurrentPrompt(agentRow.ID)
	if err != nil {
		log.Printf("[reporter] 读取 prompt 失败: %v", err)
		return
	}
	if reporterPromptNeedsTemplateUpgrade(current) {
		if _, err := s.m.pg.ResetPromptToDefault(agentRow.ID, agent.ReporterDefaultPrompt); err != nil {
			log.Printf("[reporter] 更新合成范围与请求规范提示词失败: %v", err)
			return
		}
		log.Printf("[reporter] 默认提示词已明确合成样本范围并要求规范化 Burp 请求和攻击链")
	}
	if err := s.m.pg.SetSetting(flag, "true"); err != nil {
		log.Printf("[reporter] 保存合成范围与请求规范迁移标记失败: %v", err)
	}
}

func (s *Server) upgradeReporterDeliveryTemplateV35() {
	const flag = "reporter_prompt_delivery_template_v35"
	if value, _, err := s.m.pg.GetSetting(flag); err != nil {
		log.Printf("[reporter] 读取攻击链分组迁移标记失败: %v", err)
		return
	} else if value == "true" {
		return
	}
	agentRow, err := s.m.pg.GetAgentByKey("reporter")
	if err != nil {
		log.Printf("[reporter] 读取 agent 失败: %v", err)
		return
	}
	if agentRow == nil {
		return
	}
	current, err := s.m.pg.CurrentPrompt(agentRow.ID)
	if err != nil {
		log.Printf("[reporter] 读取 prompt 失败: %v", err)
		return
	}
	if reporterPromptNeedsTemplateUpgrade(current) {
		if _, err := s.m.pg.ResetPromptToDefault(agentRow.ID, agent.ReporterDefaultPrompt); err != nil {
			log.Printf("[reporter] 更新攻击链分组提示词失败: %v", err)
			return
		}
		log.Printf("[reporter] 默认提示词已要求攻击链分组使用树枝标记")
	}
	if err := s.m.pg.SetSetting(flag, "true"); err != nil {
		log.Printf("[reporter] 保存攻击链分组迁移标记失败: %v", err)
	}
}

func (s *Server) upgradeReporterDeliveryTemplateV36() {
	const flag = "reporter_prompt_delivery_template_v36"
	if value, _, err := s.m.pg.GetSetting(flag); err != nil {
		log.Printf("[reporter] 读取合成文件敏感资产边界迁移标记失败: %v", err)
		return
	} else if value == "true" {
		return
	}
	agentRow, err := s.m.pg.GetAgentByKey("reporter")
	if err != nil {
		log.Printf("[reporter] 读取 agent 失败: %v", err)
		return
	}
	if agentRow == nil {
		return
	}
	current, err := s.m.pg.CurrentPrompt(agentRow.ID)
	if err != nil {
		log.Printf("[reporter] 读取 prompt 失败: %v", err)
		return
	}
	if reporterPromptNeedsTemplateUpgrade(current) {
		if _, err := s.m.pg.ResetPromptToDefault(agentRow.ID, agent.ReporterDefaultPrompt); err != nil {
			log.Printf("[reporter] 更新合成文件敏感资产边界提示词失败: %v", err)
			return
		}
		log.Printf("[reporter] 默认提示词已区分合成文件与真实敏感资产")
	}
	if err := s.m.pg.SetSetting(flag, "true"); err != nil {
		log.Printf("[reporter] 保存合成文件敏感资产边界迁移标记失败: %v", err)
	}
}

func (s *Server) upgradeReporterDeliveryTemplateV37() {
	const flag = "reporter_prompt_delivery_template_v37"
	if value, _, err := s.m.pg.GetSetting(flag); err != nil {
		log.Printf("[reporter] 读取六项交付报告模板迁移标记失败: %v", err)
		return
	} else if value == "true" {
		return
	}
	agentRow, err := s.m.pg.GetAgentByKey("reporter")
	if err != nil {
		log.Printf("[reporter] 读取 agent 失败: %v", err)
		return
	}
	if agentRow == nil {
		return
	}
	current, err := s.m.pg.CurrentPrompt(agentRow.ID)
	if err != nil {
		log.Printf("[reporter] 读取 prompt 失败: %v", err)
		return
	}
	if reporterPromptNeedsTemplateUpgrade(current) {
		if _, err := s.m.pg.ResetPromptToDefault(agentRow.ID, agent.ReporterDefaultPrompt); err != nil {
			log.Printf("[reporter] 更新六项交付报告模板失败: %v", err)
			return
		}
		log.Printf("[reporter] 默认提示词已更新为六项交付报告结构")
	}
	if err := s.m.pg.SetSetting(flag, "true"); err != nil {
		log.Printf("[reporter] 保存六项交付报告模板迁移标记失败: %v", err)
	}
}

func (s *Server) upgradeReporterDeliveryTemplate() {
	const flag = "reporter_prompt_delivery_template_v16"
	value, _, err := s.m.pg.GetSetting(flag)
	if err != nil {
		log.Printf("[reporter] 读取固定模板迁移标记失败: %v", err)
		return
	}
	if value == "true" {
		return
	}
	// Only refresh the known stock description; edited schema and bindings stay
	// authoritative, while runtime guidance still explains the save contract.
	previousDescriptions := previousFindingReportToolDescriptions()
	placeholders := make([]string, len(previousDescriptions))
	args := make([]any, 1, len(previousDescriptions)+1)
	args[0] = findingReportToolDescription
	for index, description := range previousDescriptions {
		placeholders[index] = fmt.Sprintf("$%d", index+2)
		args = append(args, description)
	}
	query := fmt.Sprintf(`UPDATE tools SET description=$1,updated_at=now()
	WHERE key='update_finding_report' AND system AND description IN (%s)`, strings.Join(placeholders, ","))
	if _, err := s.m.pg.Exec(query, args...); err != nil {
		log.Printf("[reporter] 更新固定模板工具说明失败: %v", err)
		return
	}
	agentRow, err := s.m.pg.GetAgentByKey("reporter")
	if err != nil {
		log.Printf("[reporter] 读取 agent 失败: %v", err)
		return
	}
	if agentRow == nil {
		return
	}
	current, err := s.m.pg.CurrentPrompt(agentRow.ID)
	if err != nil {
		log.Printf("[reporter] 读取 prompt 失败: %v", err)
		return
	}
	if reporterPromptNeedsTemplateUpgrade(current) {
		if _, err := s.m.pg.ResetPromptToDefault(agentRow.ID, agent.ReporterDefaultPrompt); err != nil {
			log.Printf("[reporter] 升级固定交付模板失败: %v", err)
			return
		}
		log.Printf("[reporter] 默认 prompt 已升级为明确证据来源和简明交付规范")
	}
	if err := s.m.pg.SetSetting(flag, "true"); err != nil {
		log.Printf("[reporter] 保存固定模板 prompt 迁移标记失败: %v", err)
	}
}

// unbindGoalMetDefault removes goal_met's default "planner" binding ONCE (guarded by
// a settings flag), so existing DBs match the new default of NO agent. goal_met bypasses
// per-goal prove_goal to declare the whole task done — powerful/risky and redundant with
// the prove_goal→auto-complete path — so it ships unbound; users can re-bind it per agent
// in the UI. A user's own binding to another agent is untouched (we only strip planner).
func (s *Server) unbindGoalMetDefault() {
	const flag = "goal_met_unbind_default_v1"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	if err := s.m.pg.RemoveAgentFromTool("planner", "goal_met"); err != nil {
		log.Printf("[tools] goal_met 解绑 planner 失败: %v", err)
		return
	}
	_ = s.m.pg.SetSetting(flag, "true")
}

// reseedGoalsPrompt 把 goals 目标拆解器的提示词刷成【当前代码默认】——因为默认正文新增了
// 「先抽操作约束(set_constraints)再拆目标」这一步,而 SeedPromptIfEmpty 首插入only,旧库
// 已有的 version 1 收不到这步。这里用版本管理【追加一个新版本】并切过去(ResetPromptToDefault),
// 旧的版本仍保留在历史里,用户若自定义过可从版本记录找回。settings flag 守卫 → 只做一次;
// 以后默认再变就 bump 这个 flag。全新库无需处理(SeedPromptIfEmpty 已 seed 最新默认)。
func (s *Server) reseedGoalsPrompt() {
	const flag = "goals_prompt_constraint_step_v1"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	defer func() { _ = s.m.pg.SetSetting(flag, "true") }() // 无论成功与否只尝试一次
	a, err := s.m.pg.GetAgentByKey("goals")
	if err != nil || a == nil {
		return // 全新库尚未建 agent 行时,seedPrompts 会直接 seed 最新默认,无需此迁移
	}
	tmpl := agent.BuiltinPromptSeeds()["goals"]
	if tmpl == "" {
		return
	}
	// 全新库 seedPrompts 已 seed 最新默认 → 当前版本已等于代码默认,不必再追加重复版本。
	if cur, err := s.m.pg.CurrentPrompt(a.ID); err == nil && cur == tmpl {
		return
	}
	if _, err := s.m.pg.ResetPromptToDefault(a.ID, tmpl); err != nil {
		log.Printf("[prompts] goals 提示词重刷为新默认失败: %v", err)
		return
	}
	log.Printf("[prompts] goals 提示词已追加新默认版本(加入抽操作约束步,一次性)")
}

// reseedMainAgentPrompt 把 mainagent 提示词刷成【当前代码默认】——默认正文新增了「目标全部
// 达成后 add_intent 直投意图时,反问人是否登记为正式目标」这段引导,而 SeedPromptIfEmpty 首插入
// only,旧库已有版本收不到。用版本管理【追加一个新版本】并切过去(ResetPromptToDefault),旧版本仍
// 保留在历史里,用户若自定义过可从版本记录找回。settings flag 守卫 → 只做一次。全新库无需处理
// (SeedPromptIfEmpty 已 seed 最新默认)。与 reseedGoalsPrompt 完全同构。
func (s *Server) reseedMainAgentPrompt() {
	const flag = "mainagent_prompt_goalless_intent_v1"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	defer func() { _ = s.m.pg.SetSetting(flag, "true") }() // 无论成功与否只尝试一次
	a, err := s.m.pg.GetAgentByKey("mainagent")
	if err != nil || a == nil {
		return // 全新库尚未建 agent 行时,seedPrompts 会直接 seed 最新默认,无需此迁移
	}
	tmpl := agent.BuiltinPromptSeeds()["mainagent"]
	if tmpl == "" {
		return
	}
	// 全新库 seedPrompts 已 seed 最新默认 → 当前版本已等于代码默认,不必再追加重复版本。
	if cur, err := s.m.pg.CurrentPrompt(a.ID); err == nil && cur == tmpl {
		return
	}
	if _, err := s.m.pg.ResetPromptToDefault(a.ID, tmpl); err != nil {
		log.Printf("[prompts] mainagent 提示词重刷为新默认失败: %v", err)
		return
	}
	log.Printf("[prompts] mainagent 提示词已追加新默认版本(加入目标达成后反问建目标,一次性)")
}

// upgradeVerificationPrompts leaves edited prompts and their history untouched.
func (s *Server) upgradeVerificationPrompts() {
	defaults := agent.BuiltinPromptSeeds()
	for key, previous := range agent.PreviousVerificationPromptSeeds() {
		a, err := s.m.pg.GetAgentByKey(key)
		if err != nil || a == nil {
			log.Printf("[prompts] %s 复核提示词升级跳过: %v", key, err)
			continue
		}
		updated, err := s.m.pg.UpgradePromptIfCurrent(a.ID, previous, defaults[key])
		if err != nil {
			log.Printf("[prompts] %s 复核提示词升级失败: %v", key, err)
		} else if updated {
			log.Printf("[prompts] %s 复核提示词已升级", key)
		}
	}
}

// reporterToolCallMessage 必须无条件要求先读一次 get_finding_traffic 再写报告。
// 该工具是只读的、「不依赖捕获开关」,自动绑定关不关都能读到人工绑定的证据。若这里
// 写成「启用自动绑定才读」,默认关闭配置下 reporter 就不会传 evidence_version,
// SetFindingReportVersionByNodeID 便按 legacy 语义写 -1,漏洞详情与 Markdown 导出
// 从此常驻「证据已变更，报告待更新」,而 UI 上没有任何入口能把它清掉。
const reporterToolCallMessageV2 = "上面刚有一个漏洞被 report_finding 登记。请读取返回 JSON 的 finding_id（独立漏洞记录 ID）与 finding_node_id（探索节点 ID），" +
	"先用 get_finding_traffic(finding_id) 读取当前证据清单及其 version（空清单是正常情况，照常写报告）；" +
	"若运行指引启用自动绑定，在读取前先核实并关联本次漏洞的流量。节点详情使用 finding_node_id。" +
	"最后调用 update_finding_report(finding_id=finding_node_id, report, evidence_version=实际读取版本) 保存，" +
	"evidence_version 必须传，否则报告会被永久标记为待更新。不要混用两种编号。"

const reporterToolCallMessageV3 = "上面刚有一个漏洞被 report_finding 登记。请读取返回 JSON 的 finding_id（独立漏洞记录 ID）与 finding_node_id（探索节点 ID），" +
	"先用 get_finding_traffic(finding_id) 读取当前证据清单及其 version（空清单是正常情况，照常写报告）；" +
	"若运行指引启用自动绑定，在读取前先核实并关联本次漏洞的流量。节点详情使用 finding_node_id。" +
	"基于同一组证据一次写出详细报告和面向开发修复的交付报告，并给出完整 CVSS 4.0 Base 向量；交付报告修复建议只写证据支持的必要改动，不估算无依据的工期或成本。" +
	"交付报告按漏洞名称、CVSS 4.0 Base 向量/评分/等级、漏洞描述、修复建议、测试过程、攻击过程和证据来源组织。CVSS 三行须使用固定格式：- **CVSS 4.0 Base 向量（CVSS-B）**：...；- **CVSS 4.0 评分**：...；- **漏洞等级**：...。" +
	"不要在正文复制已绑定的 HTTP 报文；ARTEX 会在保存报告时附加完整原始请求和响应。任务证据或执行记录中若有未绑定的原始报文，可按原文引用并注明来源，不做脱敏，不得编造。" +
	"最后调用 update_finding_report(finding_id=finding_node_id, report, delivery_report, cvss_vector, evidence_version=实际读取版本) 一次保存两份报告；" +
	"evidence_version 必须传，否则报告会被永久标记为待更新。不要混用两种编号。"

const reporterToolCallMessageV4 = "上面刚有一个漏洞被 report_finding 登记。请读取返回 JSON 的 finding_id（独立漏洞记录 ID）与 finding_node_id（探索节点 ID），" +
	"先用 get_finding_traffic(finding_id) 读取当前证据清单及其 version（空清单是正常情况，照常写报告）；" +
	"若运行指引启用自动绑定，在读取前先核实并关联本次漏洞的流量。节点详情使用 finding_node_id。" +
	"基于同一组证据一次写出详细报告和面向开发修复的交付报告，并给出完整 CVSS 4.0 Base 向量；交付报告修复建议只写证据支持的必要改动，不估算无依据的工期或成本。" +
	"交付报告必须单独使用 Markdown 二级标题“攻击链路”，按实际发生顺序说明利用前提、每一步请求或操作、系统响应和最终已证实影响，并对应证据；缺失或未验证的步骤明确标出，不使用箭头缩写，不把推测写成事实。" +
	"交付报告按漏洞名称、CVSS 4.0 Base 向量/评分/等级、漏洞描述、修复建议、测试过程、攻击链路、发现路径和证据来源组织。CVSS 三行须使用固定格式：- **CVSS 4.0 Base 向量（CVSS-B）**：...；- **CVSS 4.0 评分**：...；- **漏洞等级**：...。" +
	"不要在正文复制已绑定的 HTTP 报文；ARTEX 会在保存报告时附加完整原始请求和响应。任务证据或执行记录中若有未绑定的原始报文，可按原文引用并注明来源，不做脱敏，不得编造。" +
	"最后调用 update_finding_report(finding_id=finding_node_id, report, delivery_report, cvss_vector, evidence_version=实际读取版本) 一次保存两份报告；" +
	"evidence_version 必须传，否则报告会被永久标记为待更新。不要混用两种编号。"

const reporterToolCallMessageV2Legacy = "上面刚有一个漏洞被 report_finding 登记。请读取返回 JSON 的 finding_id（独立漏洞记录 ID）与 finding_node_id（探索节点 ID），" +
	"先用 get_finding_traffic(finding_id) 读取当前证据清单及其 version（空清单是正常情况，照常写报告）；" +
	"若运行指引启用自动绑定，在读取前先核实并关联本次漏洞的流量。节点详情使用 finding_node_id。" +
	"基于同一组证据一次写出详细报告和面向开发修复的交付报告，并给出完整 CVSS 4.0 Base 向量；交付报告修复建议只写证据支持的必要改动，不估算无依据的工期或成本。" +
	"交付报告按漏洞名称、CVSS 4.0 Base 向量/评分/等级、漏洞描述、修复建议、测试过程、攻击链路、发现路径、Burp 复测请求和返回包组织。CVSS 三行须使用固定格式：- **CVSS 4.0 Base 向量（CVSS-B）**：...；- **CVSS 4.0 评分**：...；- **漏洞等级**：...。" +
	"只在已绑定真实 HTTP 流量时填写 Burp 请求/响应，保留证据原文，不编造报文。" +
	"最后调用 update_finding_report(finding_id=finding_node_id, report, delivery_report, cvss_vector, evidence_version=实际读取版本) 一次保存两份报告；" +
	"evidence_version 必须传，否则报告会被永久标记为待更新。不要混用两种编号。"

// Keep legacy text independent of current rules so saved stock triggers remain recognizable.
const reporterLegacySaveGuidanceV5 = "交付报告必须包含一个一级标题和一行 CVSS 4.0 信息。一级标题就是漏洞名称，不再另写“漏洞名称”字段；CVSS 向量、分数和等级只写一次。二级标题按顺序固定为：描述、修复、测试过程、攻击链路、证据说明；各节非空。描述内必须有三级标题“定级依据”；测试过程内必须有“发现过程与攻击思路”“失败尝试与未验证项”；证据说明内必须有“Burp 复现”“复测标准”。攻击链路必须包含 text 代码块树形图，写清起点和至少一条带内容的分支，并说明功能来源、接口或工具和实际结果。测试记录写清工具参数、判据和时间。缺少证据写“未验证”，不得补造；格式错误时按工具反馈补齐后重新保存。"

const reporterToolCallMessageV5 = "上面刚有一个漏洞被 report_finding 登记。请读取返回 JSON 的 finding_id（独立漏洞记录 ID）与 finding_node_id（探索节点 ID），" +
	"用 get_task_node_detail 和执行记录取全本次漏洞的发现线索、攻击思路、测试项、工具参数、判据、时间、失败尝试及未验证项；" +
	"先按运行指引核实并关联已有流量，再用 get_finding_traffic(finding_id) 读取当前证据清单及 version（空清单可正常写报告，不猜测流量编号）。" +
	"基于同组证据一次写出详细报告和面向开发修复的交付报告。" + reporterLegacySaveGuidanceV5 +
	"攻击链路用简短树形逐步写出身份条件、操作、响应和影响，并对应测试记录；提供可在 Burp Repeater 复现的完整请求及会话、发送方式和判据，未实际在 Burp 验证要说明。" +
	"ARTEX 会在证据说明内成对附加绑定报文；未绑定原始包按真实来源引用，不虚构、不把其他账号记录贴作本次证据。" +
	"最后调用 update_finding_report(finding_id=finding_node_id, report, delivery_report, cvss_vector, evidence_version=实际读取版本) 一次保存两份报告；格式不符合工具反馈时补齐后重试。"

const reporterToolCallMessageV6 = "上面刚有一个漏洞被 report_finding 登记。请读取返回 JSON 的 finding_id（独立漏洞记录 ID）与 finding_node_id（探索节点 ID），" +
	"用 get_task_node_detail 和执行记录还原漏洞发现路径、测试项、工具参数、判据、时间、失败尝试及未验证项；先按运行指引核实并关联已有流量，再用 get_finding_traffic(finding_id) 读取证据清单及 version。" +
	"基于同组证据一次写出详细报告和开发交付报告。交付报告标题就是漏洞名称，不要重复写“漏洞名称”字段；CVSS 向量、评分和等级合并为一行。" +
	"攻击链路必须用简短树形图，按页面或功能来源、用户操作、前端请求、HTTP 接口方法与路径、服务端实际处理、业务结果说明过程。接口路径单独成行，不要在描述或路径后加括号解释；非 HTTP 漏洞写执行入口和命令，不编接口。每一步对应实际证据，缺失部分写“未验证”。" +
	"按固定五节模板撰写，中文短句，避免内部术语，避免重复标题、接口清单、CVSS 信息和完整报文。已绑定报文由 ARTEX 自动附加；未绑定原始报文按实际来源完整引用，不编造。" +
	"最后调用 update_finding_report(finding_id=finding_node_id, report, delivery_report, cvss_vector, evidence_version=实际读取版本) 一次保存两份报告；格式不符合工具反馈时补齐后重试。"

const reporterToolCallMessageV7 = "上面刚有一个漏洞被 report_finding 登记。请从返回 JSON 取得 finding_id（独立漏洞记录 ID）和 finding_node_id（探索节点 ID）。" +
	"读取本漏洞节点、相关执行记录和已有材料，核对实际观察、成立条件、未验证影响及证据位置。按运行指引关联已有流量，并用 get_finding_traffic(finding_id) 取得证据清单及 version。" +
	"按当前交付规范写详细报告和交付报告；正文用具体用途称呼材料，不抄写内部证据 ID。已绑定报文由 ARTEX 自动附加，其他材料按真实来源引用，不编造或为补证据重新探测目标。" +
	"最后调用 update_finding_report(finding_id=finding_node_id, report, delivery_report, cvss_vector, evidence_version=实际读取的 version) 一次保存两份报告，按明确的保存错误修正后重试。"

const reporterToolCallMessageV8 = "上面刚有一个漏洞被 report_finding 登记。请从返回 JSON 取得 finding_id（独立漏洞记录 ID）和 finding_node_id（探索节点 ID）。" +
	"读取本漏洞节点、执行记录和原始材料，核对发现思路、成立条件、实际操作、结果、失败尝试、未验证影响及证据位置；旧报告和执行摘要只作线索。按运行指引核对已有流量，并用 get_finding_traffic(finding_id) 取得证据清单及 version。" +
	"一次写出详细报告和交付报告。交付报告按固定顺序使用“描述、修复、测试过程、攻击链路、证据说明”五节，并保留“定级依据”“发现过程与攻击思路”“失败尝试与未验证项”“Burp 复现”“复测标准”子标题。详细报告保留完整工具参数、时间和逐项结果；交付正文只写复现必需的账号或会话、关键参数、操作顺序和判据，其他细节不重复。原始报文由 ARTEX 完整附加。" +
	"最后调用 update_finding_report(finding_id=finding_node_id, report, delivery_report, cvss_vector, evidence_version=实际读取的 version) 一次保存两份报告。"

const reporterToolCallMessageV9 = "上面刚有一个漏洞被 report_finding 登记。请从返回 JSON 取得 finding_id（独立漏洞记录 ID）和 finding_node_id（探索节点 ID）。" +
	"读取本漏洞节点、对应执行记录和原始材料，核对实际操作、工具参数、时间、结果、失败尝试和未验证事项；摘要与旧报告只作线索。按运行指引核对已有流量，并用 get_finding_traffic(finding_id) 取得证据版本。" +
	"一次写出详细报告和交付报告。详细报告保留完整测试台账；交付报告只用固定的五节二级标题，不增加子标题，用短句说明问题、复现和修复。HTTP 测试在“测试过程”写明 Burp Repeater 实际使用状态和步骤；未实际使用时明确标为建议复测。ARTEX 会附加完整绑定报文，正文不重复粘贴。" +
	"最后调用 update_finding_report(finding_id=finding_node_id, report, delivery_report, cvss_vector, evidence_version=实际读取的 version) 一次保存两份报告。"

const reporterToolCallMessageV10 = "上面刚有一个漏洞被 report_finding 登记。请从返回 JSON 取得 finding_id（独立漏洞记录 ID）和 finding_node_id（探索节点 ID）。" +
	"读取本漏洞节点、相关执行记录和原始证据。执行记录和报文优先于漏洞摘要、旧报告和 worker 总结；先整理成立条件、实际操作、观察结果、未验证影响和证据位置。" +
	"一次写出详细报告和交付报告。详细报告保留完整工具参数、时间、失败记录、哈希和证据索引；交付报告按固定五节及其必需子标题撰写，只保留开发理解问题、复现和修复所需内容，不重复执行台账。时间用北京时间；仅在先后顺序或时间条件影响结论时保留准确时间。HTTP 测试在测试过程中写明 Burp Repeater 实际使用情况，未使用时给建议步骤并标记未验证。ARTEX 会在末尾附加已绑定的原始请求和响应，正文不重复粘贴。" +
	"保存前由当前 Reporter 自查事实、复现条件、影响边界、攻击链和证据引用；不要补造缺失事实。只根据明确的格式错误作必要修正，不无限重试。" +
	"最后调用 update_finding_report(finding_id=finding_node_id, report, delivery_report, cvss_vector, evidence_version=实际读取的 version) 一次保存两份报告。"

const reporterToolCallMessageV11 = "漏洞登记后，读取漏洞节点、对应执行记录和原始证据，核对实际操作、结果、失败和未验证事项。按 Reporter 提示词中的固定结构写详细报告与交付报告；不要补造缺失事实。最后一次调用 update_finding_report 保存两份报告，使用实际读取的证据版本。"

const reporterToolCallMessage = reporterToolCallMessageV11

// 旧版触发消息(0.3.8 及更早)。只有仍与它逐字相同的记录才会被迁移覆盖，用户改过的保持原样。
const reporterToolCallMessageV1 = "上面刚有一个漏洞被 report_finding 登记。请从触发上下文里取出 finding_id" +
	"（工具返回 \"finding recorded: <id>\" 里的数字）与任务 id，按你的职责撰写该漏洞的详细报告，" +
	"最后调用 update_finding_report(finding_id, report) 保存。"

func reporterTriggerMessageNeedsUpgrade(message string) bool {
	switch message {
	case reporterToolCallMessageV1, reporterToolCallMessageV2, reporterToolCallMessageV2Legacy,
		reporterToolCallMessageV3, reporterToolCallMessageV4, reporterToolCallMessageV5, reporterToolCallMessageV6, reporterToolCallMessageV7, reporterToolCallMessageV8, reporterToolCallMessageV9, reporterToolCallMessageV10:
		return true
	default:
		return false
	}
}

func (s *Server) upgradeReporterTriggerMessageV11() {
	const flag = "reporter_trigger_delivery_report_v11"
	if value, _, err := s.m.pg.GetSetting(flag); err != nil {
		log.Printf("[reporter] 读取精简触发消息迁移标记失败: %v", err)
		return
	} else if value == "true" {
		return
	}
	triggers, err := s.m.pg.ListTriggersFor("reporter")
	if err != nil {
		log.Printf("[reporter] 读取触发器失败: %v", err)
		return
	}
	for _, trigger := range triggers {
		if !trigger.OnToolCall || trigger.ToolCallMessage != reporterToolCallMessageV10 {
			continue
		}
		trigger.ToolCallMessage = reporterToolCallMessage
		if err := s.m.pg.UpdateTrigger(trigger); err != nil {
			log.Printf("[reporter] 精简触发消息失败: %v", err)
			return
		}
	}
	if err := s.m.pg.SetSetting(flag, "true"); err != nil {
		log.Printf("[reporter] 保存精简触发消息迁移标记失败: %v", err)
	}
}

// Existing installations keep editable triggers, so only known stock messages
// can receive new guidance without overwriting the user's workflow.
func (s *Server) upgradeReporterTriggerMessage() {
	const flag = "reporter_trigger_delivery_report_v10"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	triggers, err := s.m.pg.ListTriggersFor("reporter")
	if err != nil {
		log.Printf("[reporter] 读取触发器失败: %v", err)
		return
	}
	for _, t := range triggers {
		if !t.OnToolCall || !reporterTriggerMessageNeedsUpgrade(t.ToolCallMessage) {
			continue // 用户改过或不是 finding 触发器，不动。
		}
		t.ToolCallMessage = reporterToolCallMessage
		if err := s.m.pg.UpdateTrigger(t); err != nil {
			log.Printf("[reporter] 升级触发消息失败: %v", err)
			return
		}
		log.Printf("[reporter] 触发消息已升级为固定五节交付报告规范")
	}
	if err := s.m.pg.SetSetting(flag, "true"); err != nil {
		log.Printf("[reporter] 保存触发消息迁移标记失败: %v", err)
	}
}

// seedReporterAgent 预置一个「报告撰写」自定义 agent(builtin=false，可在 UI 编辑/删除)：
// 绑定 update_finding_report + 任务查询工具，并挂一个「report_finding 被调用即触发」的
// 触发器 —— 每登记一个漏洞就唤起它写详细报告和交付报告。一次性(settings flag 守卫)：用户删掉后不再重建。
// 依赖：orchestration 工具已在本函数上方 SeedTool 入库，故绑定得上。
func (s *Server) seedReporterAgent() {
	const flag = "reporter_agent_seed_v1"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	defer func() { _ = s.m.pg.SetSetting(flag, "true") }() // 无论成功与否只尝试一次

	if exist, _ := s.m.pg.GetAgentByKey("reporter"); exist != nil {
		return // key 已被占用(用户手建过)——不覆盖
	}
	a, err := s.m.pg.CreateAgent("reporter", "报告撰写",
		"漏洞报告撰写：发现漏洞时自动触发，查取证据与执行过程后一次生成详细报告和开发交付报告。")
	if err != nil {
		log.Printf("[reporter] 创建 agent 失败: %v", err)
		return
	}
	if err := s.m.pg.SeedPromptIfEmpty(a.ID, agent.ReporterDefaultPrompt); err != nil {
		log.Printf("[reporter] seed prompt 失败: %v", err)
	}
	// 触发运行策略：parallel + none —— 一漏洞一报告、多个 finding 并发各写各的。
	// merge 必须为 none：否则(默认 all)一波 finding 会被合并成一次运行，并行就没意义。
	// maxParallel=5：同时最多 5 个报告会话，避免瞬时太多 LLM 调用。
	if err := s.m.pg.SetAgentTriggerBehavior("reporter", "parallel", "none", 5); err != nil {
		log.Printf("[reporter] 设置触发运行策略失败: %v", err)
	}
	// 绑定它需要的工具：写报告 + 读证据/执行过程/态势。
	if err := s.m.pg.AddAgentToToolBinding("reporter", []string{
		"update_finding_report", "get_task_node_detail", "list_task_findings",
		"get_task_worker_trace", "list_task_worker_traces", "search_task_worker_traces",
		"get_task_graph",
	}); err != nil {
		log.Printf("[reporter] 绑定工具失败: %v", err)
	}
	// 触发器：report_finding 被调用即触发（工具返回 "finding recorded: <id>" 带上 finding_id，
	// 任务 id 也在触发消息里）。
	if _, err := s.m.pg.CreateTrigger(&db.AgentTrigger{
		AgentKey:        "reporter",
		Enabled:         true,
		OnToolCall:      true,
		ToolNames:       []string{"report_finding"},
		ToolCallMessage: reporterToolCallMessage,
	}); err != nil {
		log.Printf("[reporter] 创建触发器失败: %v", err)
	}
	log.Printf("[reporter] 已预置「报告撰写」agent + finding 触发器")
}

// seedAutoReportFindingBinding adds "auto" to report_finding's binding ONCE so
// conversation-context agents can call it without requiring an intent_id.
func (s *Server) seedAutoReportFindingBinding() {
	const flag = "auto_report_finding_v1"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	if err := s.m.pg.AddAgentToToolBinding("auto", []string{"report_finding"}); err != nil {
		log.Printf("[auto] report_finding 默认绑定失败: %v", err)
		return
	}
	_ = s.m.pg.SetSetting(flag, "true")
}

// seedPlannerDefaultBindings adds "planner" to report_finding's binding ONCE
// (guarded by a settings flag), so existing DBs — whose report_finding row was
// seeded as worker-only — also let the planner record findings. Fresh DBs already
// get it via PlannerTools(); this only backfills without overriding a user unbind.
func (s *Server) seedPlannerDefaultBindings() {
	const flag = "planner_report_finding_v1"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	if err := s.m.pg.AddAgentToToolBinding("planner", []string{"report_finding"}); err != nil {
		log.Printf("[planner] report_finding 默认绑定失败: %v", err)
		return
	}
	_ = s.m.pg.SetSetting(flag, "true")
}

// seedPlannerListAssetsBinding adds "planner" to list_assets's binding ONCE
// (guarded by a settings flag), so existing DBs — whose list_assets row was seeded
// as auto/pentest-only — also let the planner query the asset store by DSL. Fresh
// DBs already get it via PlannerTools(); this only backfills without overriding a
// user unbind.
func (s *Server) seedPlannerListAssetsBinding() {
	const flag = "planner_list_assets_v1"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	if err := s.m.pg.AddAgentToToolBinding("planner", []string{"list_assets"}); err != nil {
		log.Printf("[planner] list_assets 默认绑定失败: %v", err)
		return
	}
	_ = s.m.pg.SetSetting(flag, "true")
}

// seedCompanyScopeRebind changes add_company_scope's default binding ONCE on
// existing DBs (guarded by a settings flag): the tool moves off worker and onto
// planner — defining a company's asset scope is a planning/main/auto concern, not
// something a worker does mid-exploration. Fresh DBs already get planner via
// PlannerTools() and lack worker via WorkerTools(); this only backfills old rows.
// One-shot + flag-guarded so a user who later re-binds worker isn't overridden.
func (s *Server) seedCompanyScopeRebind() {
	const flag = "company_scope_rebind_v1" // worker→planner 默认绑定切换
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	if err := s.m.pg.AddAgentToToolBinding("planner", []string{"add_company_scope"}); err != nil {
		log.Printf("[planner] add_company_scope 默认绑定失败: %v", err)
		return
	}
	if err := s.m.pg.RemoveAgentFromTool("worker", "add_company_scope"); err != nil {
		log.Printf("[worker] add_company_scope 解绑失败: %v", err)
		return
	}
	_ = s.m.pg.SetSetting(flag, "true")
}

// seedWorkerReadToolsUnbind strips the read-context tools off worker's default
// binding ONCE on existing DBs (guarded by a settings flag): a worker executes one
// intent and writes back — reading facts/companies and listing all workers' traces is
// a planning/main concern, not the executor's. Fresh DBs already lack these via
// WorkerTools(); this only backfills old rows without overriding a user who
// deliberately re-binds worker. Each RemoveAgentFromTool is per-tool +
// membership-guarded, so planner/mainagent bindings of the same tool are untouched.
//
// NOTE: search_all_worker_traces / get_worker_trace / node_detail are intentionally NOT
// unbound — worker owns them for cross-work look-back + node drill-down (see WorkerTools).
// They used to be in this list back when worker lacked them; seedWorkerReadbackRebind
// repairs DBs whose old run stripped them.
func (s *Server) seedWorkerReadToolsUnbind() {
	const flag = "worker_readtools_unbind_v1"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	for _, k := range []string{
		"list_facts", "list_companies", "list_worker_traces",
	} {
		if err := s.m.pg.RemoveAgentFromTool("worker", k); err != nil {
			log.Printf("[worker] %s 从 worker 解绑失败: %v", k, err)
			return // 出错则不落 flag，下次启动重试
		}
	}
	_ = s.m.pg.SetSetting(flag, "true")
}

// seedWorkerReadbackRebind re-binds the cross-work look-back / drill-down tools onto
// worker ONCE (guarded by a settings flag): an earlier seedWorkerReadToolsUnbind wrongly
// stripped search_all_worker_traces / get_worker_trace / node_detail from worker after
// they had been added to WorkerTools(), so any DB that ran that migration lost them.
// Fresh DBs already have them via WorkerTools() and this is a harmless no-op there.
// One-shot + flag-guarded so a user who later deliberately unbinds them isn't overridden.
func (s *Server) seedWorkerReadbackRebind() {
	const flag = "worker_readback_rebind_v2" // v2: 追加 node_detail
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	if err := s.m.pg.AddAgentToToolBinding("worker", []string{
		"search_all_worker_traces", "get_worker_trace", "node_detail",
	}); err != nil {
		log.Printf("[worker] 回看/详情工具补绑失败: %v", err)
		return // 出错则不落 flag，下次启动重试
	}
	_ = s.m.pg.SetSetting(flag, "true")
}

// seedAutoDefaultBindings adds "auto" to the task-op + platform tools' bindings
// ONCE (guarded by a settings flag), so existing DBs whose tool rows were seeded
// before Auto existed still give Auto its default toolset — without re-adding it
// after a user deliberately unbinds.
func (s *Server) seedAutoDefaultBindings() {
	const flag = "auto_default_bindings_v3" // v3: 替换旧资产工具名，加入 insert_assets/add_company_scope
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	keys := make([]string, 0, len(platformToolKeys)+12)
	for _, t := range s.orchestrationTools() {
		keys = append(keys, t.Name())
	}
	keys = append(keys, platformToolKeys...)
	// 资产工具：Auto 操作平台常要看/登记资产、管理公司范围。
	keys = append(keys, "insert_assets", "add_company_scope", "list_assets")
	if err := s.m.pg.AddAgentToToolBinding("auto", keys); err != nil {
		log.Printf("[auto] 默认绑定失败: %v", err)
		return
	}
	_ = s.m.pg.SetSetting(flag, "true")
}
