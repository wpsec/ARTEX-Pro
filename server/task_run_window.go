package server

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/wpsec/ARTEX-local/agent"
	"github.com/wpsec/ARTEX-local/db"
)

var (
	errRunWindowClosed  = agent.Causef("run_window_closed", "渗透测试暂停时间已到", "渗透测试已暂停。修改暂停时间后任务会继续执行")
	errRunWindowChanged = agent.Causef("run_window_changed", "渗透测试暂停时间已调整", "当前规划或执行轮次已取消，任务将按新配置继续运行")
)

type taskRunWindowState struct {
	policy   *db.TaskRunWindow
	revision int64
	stopsAt  time.Time
}

func newTaskRunWindowState(policy *db.TaskRunWindow, revision int64) taskRunWindowState {
	state := taskRunWindowState{policy: policy, revision: revision}
	if policy != nil {
		state.stopsAt = policy.NextStop(time.Now())
	}
	return state
}

func (t *Task) windowSnapshot() taskRunWindowState {
	t.runWindowMu.RLock()
	defer t.runWindowMu.RUnlock()
	return t.runWindow
}

// A daily pause stays in effect until the user resumes; rebase its next occurrence only on that explicit action.
func (t *Task) rollExpiredRunWindowForward(at time.Time) taskRunWindowState {
	t.runWindowMu.Lock()
	defer t.runWindowMu.Unlock()
	if t.runWindow.policy == nil || t.runWindow.stopsAt.IsZero() || at.Before(t.runWindow.stopsAt) {
		return t.runWindow
	}
	if next := t.runWindow.policy.NextStop(at.Add(time.Second)); !next.IsZero() {
		t.runWindow.stopsAt = next
	}
	return t.runWindow
}

func (t *Task) replaceWindowPolicy(policy *db.TaskRunWindow, revision int64) {
	t.runWindowMu.Lock()
	defer t.runWindowMu.Unlock()
	t.runWindow = newTaskRunWindowState(policy, revision)
	if t.cancelFinalPlanner != nil {
		t.cancelFinalPlanner(errRunWindowChanged)
	}
}

func (t *Task) finalPlannerWindowContext(parent context.Context, revision int64) (context.Context, context.CancelFunc) {
	t.runWindowMu.Lock()
	defer t.runWindowMu.Unlock()
	ctx, cancel := context.WithCancelCause(parent)
	if t.runWindow.revision != revision {
		cancel(errRunWindowChanged)
		return ctx, func() { cancel(nil) }
	}
	// The deadline coordinator runs one final planner round per task run.
	t.cancelFinalPlanner = cancel
	return ctx, func() {
		cancel(nil)
		t.runWindowMu.Lock()
		t.cancelFinalPlanner = nil
		t.runWindowMu.Unlock()
	}
}

func (w taskRunWindowState) allowed(at time.Time) bool {
	return w.policy == nil || w.stopsAt.IsZero() || at.Before(w.stopsAt)
}

func (w taskRunWindowState) blocksAdmission(lifecycle taskLifecycleState, at time.Time) bool {
	return w.policy != nil && (isTerminalStatus(lifecycle.Status) || !w.allowed(at))
}

func (w taskRunWindowState) context(parent context.Context) (context.Context, context.CancelFunc) {
	if w.policy == nil {
		return parent, func() {}
	}
	return context.WithDeadlineCause(parent, w.stopsAt, errRunWindowClosed)
}

func (s *Server) updateTaskRunWindow(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	var req struct {
		Revision *int64          `json:"revision"`
		Window   json.RawMessage `json:"window"`
	}
	if err := decode(r, &req); err != nil || req.Revision == nil || len(req.Window) == 0 {
		writeErr(w, http.StatusBadRequest, "需要当前窗口版本和有效配置")
		return
	}
	var input *db.TaskRunWindow
	if err := json.Unmarshal(req.Window, &input); err != nil {
		writeErr(w, http.StatusBadRequest, "运行窗口配置无效")
		return
	}
	policy, err := db.ValidateTaskRunWindow(input)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	id := r.PathValue("id")
	s.concMu.Lock()
	task, ok := s.m.Task(id)
	if !ok || s.engine.IsDeleting(id) {
		s.concMu.Unlock()
		writeErr(w, http.StatusNotFound, "任务不存在或不可编辑")
		return
	}
	taskID, err := strconv.ParseInt(task.ID, 10, 64)
	if err != nil {
		s.concMu.Unlock()
		writeErr(w, http.StatusNotFound, "无效任务")
		return
	}
	s.m.taskStateMu.Lock()
	revision, err := pg.ReplaceTaskRunWindow(taskID, *req.Revision, policy)
	if err == nil {
		s.engine.Pause(id, errRunWindowChanged)
		task.updateLifecycle(func(state *taskLifecycleState) {
			state.Paused = true
			state.Queued = false
			state.QueuedAt = 0
		})
		task.replaceWindowPolicy(policy, revision)
	}
	s.m.taskStateMu.Unlock()
	s.concMu.Unlock()
	if errors.Is(err, db.ErrTaskRunWindowConflict) {
		writeErr(w, http.StatusConflict, "运行窗口已被修改或任务已结束，请刷新后重试")
		return
	}
	if err != nil {
		log.Printf("[run-window] task %s 保存失败: %v", id, err)
		writeErr(w, http.StatusInternalServerError, "保存运行窗口失败")
		return
	}
	s.cancelTaskChat(id, agent.AbortChatPausedWithTask)
	if _, err := s.admitPausedTask(task); err != nil {
		log.Printf("[run-window] task %s 更新暂停时间后继续失败: %v", id, err)
		writeErr(w, http.StatusInternalServerError, "暂停时间已保存，但任务未能继续："+err.Error())
		return
	}
	dto := taskDTO(task, s.resolvedTaskStatus(task))
	s.fillWindowDrainState(&dto, task)
	writeJSON(w, http.StatusOK, dto)
}

func (s *Server) pauseOutsideRunWindows() bool {
	s.concMu.Lock()
	defer s.concMu.Unlock()
	now := time.Now()
	var candidates []*Task
	s.m.mu.RLock()
	for _, task := range s.m.tasks {
		if !task.windowSnapshot().allowed(now) {
			candidates = append(candidates, task)
		}
	}
	s.m.mu.RUnlock()
	changed := false
	for _, task := range candidates {
		lifecycle := task.lifecycleSnapshot()
		if lifecycle.Paused || isTerminalStatus(lifecycle.Status) || s.engine.IsDeleting(task.ID) {
			continue
		}
		// Reporter runs in independent trigger conversations; stopping exploration must not cancel report work for findings already recorded.
		s.engine.Pause(task.ID, errRunWindowClosed)
		s.cancelTaskChat(task.ID, agent.AbortChatPausedWithTask)
		if err := s.m.ApplyTaskPause(task.ID); err != nil {
			log.Printf("[run-window] task %s 暂停状态保存失败: %v", task.ID, err)
			continue
		}
		changed = true
	}
	return changed
}

func (s *Server) runWindowGuard(ctx context.Context) {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if s.pauseOutsideRunWindows() {
				s.reconcileConcurrency()
			}
		}
	}
}

func (s *Server) fillWindowDrainState(dto *TaskDTO, task *Task) {
	if dto.RunWindowStatus != "closed" {
		return
	}
	if s.hasTaskWorkInFlight(task.ID, 0) {
		dto.RunWindowStatus = "pausing"
	}
}

func (s *Server) hasTaskWorkInFlight(taskID string, ownOperations int64) bool {
	s.chatMu.Lock()
	chatBusy := s.chatBusy[taskID]
	s.chatMu.Unlock()
	return chatBusy || s.engine.inflightCount(taskID) > ownOperations
}
