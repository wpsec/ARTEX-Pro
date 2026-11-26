package server

import (
	"context"
	"log"
	"time"

	"github.com/wpsec/ARTEX-local/agent"
	"github.com/wpsec/ARTEX-local/db"
)

var errRunWindowClosed = agent.Causef("run_window_closed", "任务停止时间已到", "本次执行已停止。")

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

func (t *Task) replaceWindowPolicy(policy *db.TaskRunWindow, revision int64) {
	t.runWindowMu.Lock()
	defer t.runWindowMu.Unlock()
	t.runWindow = newTaskRunWindowState(policy, revision)
	if t.cancelFinalPlanner != nil {
		t.cancelFinalPlanner(errRunWindowClosed)
	}
}

func (t *Task) finalPlannerWindowContext(parent context.Context, revision int64) (context.Context, context.CancelFunc) {
	t.runWindowMu.Lock()
	defer t.runWindowMu.Unlock()
	ctx, cancel := context.WithCancelCause(parent)
	if t.runWindow.revision != revision {
		cancel(errRunWindowClosed)
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
			s.pauseOutsideRunWindows()
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
