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
	errRunWindowPending = agent.Causef("run_window_not_started", "任务尚未到自动启动时间", "任务将在设定的自动启动时间开始")
)

type taskRunWindowState struct {
	policy   *db.TaskRunWindow
	revision int64
	startsAt time.Time
	stopsAt  time.Time
}

func newTaskRunWindowState(policy *db.TaskRunWindow, revision int64) taskRunWindowState {
	state := taskRunWindowState{policy: policy, revision: revision}
	if policy != nil {
		state.startsAt = policy.StartTime()
		state.stopsAt = policy.PauseTime(time.Now())
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
	if w.policy == nil {
		return true
	}
	if !w.startsAt.IsZero() && at.Before(w.startsAt) {
		return false
	}
	return w.stopsAt.IsZero() || at.Before(w.stopsAt)
}

func (w taskRunWindowState) waitingToStart(at time.Time) bool {
	return !w.startsAt.IsZero() && at.Before(w.startsAt)
}

func (w taskRunWindowState) startDue(at time.Time) bool {
	return !w.startsAt.IsZero() && !at.Before(w.startsAt) && (w.stopsAt.IsZero() || at.Before(w.stopsAt))
}

func (w taskRunWindowState) nextEvent(at time.Time) time.Time {
	if w.waitingToStart(at) {
		return w.startsAt
	}
	return w.stopsAt
}

func (w taskRunWindowState) blockedCause(at time.Time) error {
	if w.waitingToStart(at) {
		return errRunWindowPending
	}
	return errRunWindowClosed
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
	now := time.Now()
	scheduled := policy != nil && !policy.StartTime().IsZero() && policy.StartTime().After(now)
	if policy != nil && !policy.IsDailyPause() && !policy.PauseTime(now).After(now) {
		writeErr(w, http.StatusBadRequest, "自动暂停时间必须晚于当前时间")
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
	lifecycle := task.lifecycleSnapshot()
	if policy != nil && !policy.StartTime().IsZero() && policy.StartTime().After(now) &&
		(lifecycle.Status != "created" || lifecycle.FirstRunAt > 0) {
		s.concMu.Unlock()
		writeErr(w, http.StatusBadRequest, "已开始的任务不能改为未来启动，请只调整自动暂停时间")
		return
	}
	previousWindow := task.windowSnapshot()
	if lifecycle.FirstRunAt > 0 && policy != nil && !previousWindow.startsAt.IsZero() &&
		!policy.StartTime().Equal(previousWindow.startsAt) {
		s.concMu.Unlock()
		writeErr(w, http.StatusBadRequest, "任务已启动，不能修改自动启动时间，请只调整自动暂停时间")
		return
	}
	s.m.taskStateMu.Lock()
	revision, err := pg.ReplaceTaskRunWindow(taskID, *req.Revision, policy, !scheduled)
	if err == nil {
		if !scheduled {
			s.engine.Pause(id, errRunWindowChanged)
		}
		task.updateLifecycle(func(state *taskLifecycleState) {
			state.Paused = !scheduled
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
	if scheduled {
		dto := taskDTO(task, s.resolvedTaskStatus(task))
		writeJSON(w, http.StatusOK, dto)
		return
	}
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
		window := task.windowSnapshot()
		if lifecycle.Paused || window.waitingToStart(now) || isTerminalStatus(lifecycle.Status) || s.engine.IsDeleting(task.ID) {
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
			changed := s.startScheduledTasks(time.Now())
			if s.pauseOutsideRunWindows() {
				changed = true
			}
			if changed {
				s.reconcileConcurrency()
			}
		}
	}
}

func (s *Server) startScheduledTasks(at time.Time) bool {
	started := false
	for _, task := range s.m.List() {
		lifecycle := task.lifecycleSnapshot()
		window := task.windowSnapshot()
		if lifecycle.Status != "created" || lifecycle.Paused || lifecycle.Queued || isTerminalStatus(lifecycle.Status) ||
			!window.startDue(at) || s.engine.IsDeleting(task.ID) || s.engine.inflightCount(task.ID) > 0 {
			continue
		}
		if _, err := s.admitTask(task, "bootstrap"); err != nil {
			if !errors.Is(err, errRunWindowClosed) {
				log.Printf("[run-window] task %s 自动启动失败: %v", task.ID, err)
			}
			continue
		}
		started = true
	}
	return started
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
