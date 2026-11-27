package server

import (
	"context"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/wpsec/ARTEX-local/agent"
	"github.com/wpsec/ARTEX-local/db"
)

func TestTaskRunWindowStopsWithoutConfirmation(t *testing.T) {
	policy, err := db.ValidateTaskRunWindow(&db.TaskRunWindow{End: "08:00", TimeZone: "UTC"})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	stopsAt := now.Add(time.Minute)
	state := taskRunWindowState{policy: policy, revision: 2, stopsAt: stopsAt}
	if !state.allowed(now) || state.allowed(stopsAt) {
		t.Fatal("task was not admitted exactly until its stop time")
	}
	ctx, cancel := state.context(context.Background())
	defer cancel()
	if deadline, ok := ctx.Deadline(); !ok || !deadline.Equal(stopsAt) {
		t.Fatalf("deadline = %v, want %v", deadline, stopsAt)
	}
	expired := state
	expired.stopsAt = now.Add(-time.Second)
	expiredCtx, expiredCancel := expired.context(context.Background())
	defer expiredCancel()
	<-expiredCtx.Done()
	if !errors.Is(context.Cause(expiredCtx), errRunWindowClosed) {
		t.Fatalf("context cause = %v", context.Cause(expiredCtx))
	}
	task := &Task{ID: "fixture", runWindow: expired}
	if NewEngine(nil).runFinalPlannerRound(context.Background(), task) {
		t.Fatal("expired stop time allowed the final planner")
	}
}

func TestTaskRunWindowRejectsRerunAfterStop(t *testing.T) {
	policy, err := db.ValidateTaskRunWindow(&db.TaskRunWindow{End: "10:00", TimeZone: "UTC"})
	if err != nil {
		t.Fatal(err)
	}
	task := &Task{ID: "1", runWindow: taskRunWindowState{policy: policy, stopsAt: time.Now().Add(-time.Second)}}
	s := newAdmissionTestServer(&Manager{tasks: map[string]*Task{task.ID: task}}, nil)
	for _, route := range []struct {
		name    string
		handler http.HandlerFunc
	}{
		{"single", s.rerunIntent},
		{"batch", s.rerunBlocked},
	} {
		t.Run(route.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", nil)
			req.SetPathValue("id", task.ID)
			req.SetPathValue("iid", "1")
			rec := httptest.NewRecorder()
			route.handler(rec, req)
			if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), errRunWindowClosed.Error()) {
				t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestTaskRunWindowEditCancelsUnrestrictedFinalPlanner(t *testing.T) {
	task := &Task{ID: "fixture"}
	engine := NewEngine(nil)
	started := make(chan struct{}, 1)
	engine.resolve = func(*Task) (*agent.Planner, *agent.Worker) {
		started <- struct{}{}
		return nil, nil
	}
	engine.resolveAuthoritative = true
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan bool, 1)
	go func() { done <- engine.runFinalPlannerRound(ctx, task) }()
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("final round never started")
	}
	policy, err := db.ValidateTaskRunWindow(&db.TaskRunWindow{End: "10:00", TimeZone: "UTC"})
	if err != nil {
		t.Fatal(err)
	}
	task.replaceWindowPolicy(policy, 1)
	select {
	case met := <-done:
		if met {
			t.Fatal("cancelled final round reported success")
		}
	case <-time.After(time.Second):
		t.Fatal("final round continued after the stop time was edited")
	}
}

func TestTaskRunWindowReportsDrainAfterStop(t *testing.T) {
	const taskID = "1"
	task := &Task{
		ID:     taskID,
		Status: "running",
		runWindow: taskRunWindowState{
			policy:   mustRunWindow(t, "08:00"),
			revision: 2,
			stopsAt:  time.Now().Add(-time.Second),
		},
	}
	s := newAdmissionTestServer(&Manager{tasks: map[string]*Task{taskID: task}}, nil)
	s.chatBusy[taskID] = true
	dto := taskDTO(task, s.resolvedTaskStatus(task))
	s.fillWindowDrainState(&dto, task)
	if dto.RunWindowStatus != "pausing" {
		t.Fatalf("expected pausing after stop time, got %q", dto.RunWindowStatus)
	}
	delete(s.chatBusy, taskID)
	dto = taskDTO(task, s.resolvedTaskStatus(task))
	s.fillWindowDrainState(&dto, task)
	if dto.RunWindowStatus != "closed" {
		t.Fatalf("drained task status = %q, want closed", dto.RunWindowStatus)
	}
}

func TestTaskRunWindowGuardPausesExpiredTaskAndCancelsInFlight(t *testing.T) {
	if _, _, err := db.DSN(); err != nil {
		t.Skip("requires a PostgreSQL fixture")
	}
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	now := time.Now().UTC()
	task, err := m.CreateTaskWithOptions("window fixture", "check expired stop time", db.TaskCreateOptions{
		RunWindow: &db.TaskRunWindow{End: now.Add(time.Hour).Format("15:04"), TimeZone: "UTC"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = m.DeleteTask(task.ID, DeleteTaskOptions{}) }()
	s := newAdmissionTestServer(m, nil)
	taskID, err := strconv.ParseInt(task.ID, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.ApplyTaskAdmission(task.ID, task.lifecycleSnapshot().Status, "running", true, "bootstrap", false); err != nil {
		t.Fatal(err)
	}
	task.runWindowMu.Lock()
	task.runWindow.stopsAt = now.Add(-time.Second)
	task.runWindowMu.Unlock()
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	s.chatBusy[task.ID] = true
	s.chatCancel[task.ID] = cancel
	s.pauseOutsideRunWindows()
	if ctx.Err() == nil {
		t.Fatal("task chat survived expired stop time")
	}
	stored, err := m.pg.GetTask(taskID)
	if err != nil || stored == nil || !stored.Paused || stored.Queued || stored.QueuedAt != nil || task.windowSnapshot().allowed(time.Now()) {
		t.Fatalf("expired task state = %+v, err = %v", stored, err)
	}
	dto := taskDTO(task, s.resolvedTaskStatus(task))
	s.fillWindowDrainState(&dto, task)
	if dto.RunWindowStatus != "pausing" {
		t.Fatalf("in-flight work should report pausing, got %s", dto.RunWindowStatus)
	}
	s.finishTaskChat(task.ID, cancel)
	dto = taskDTO(task, s.resolvedTaskStatus(task))
	s.fillWindowDrainState(&dto, task)
	if dto.RunWindowStatus != "closed" {
		t.Fatalf("drained task status = %s, want closed", dto.RunWindowStatus)
	}
}

func TestTaskRunWindowHTTPDoesNotApplyStaleEdit(t *testing.T) {
	if _, _, err := db.DSN(); err != nil {
		t.Skip("requires a PostgreSQL fixture")
	}
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	task, err := m.CreateTask("window edit fixture", "verify edition conflicts", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = m.DeleteTask(task.ID, DeleteTaskOptions{}) }()
	s := newAdmissionTestServer(m, nil)
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	token, err := signJWT(key)
	if err != nil {
		t.Fatal(err)
	}
	s.jwtKey = key
	handler := s.Handler()
	edit := func(payload string, authorized bool) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPut, "/api/tasks/"+task.ID+"/run-window", strings.NewReader(payload))
		if authorized {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		return w
	}
	if response := edit(`{"revision":0,"window":null}`, false); response.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated write: %d %s", response.Code, response.Body)
	}
	if response := edit(`{"revision":0,"window":{"end":"08:00","time_zone":"UTC"}}`, true); response.Code != http.StatusOK {
		t.Fatalf("set window: %d %s", response.Code, response.Body)
	}
	if response := edit(`{"revision":0,"window":null}`, true); response.Code != http.StatusConflict {
		t.Fatalf("stale edit: %d %s", response.Code, response.Body)
	}
	if window := task.windowSnapshot(); window.revision != 1 || window.policy == nil || task.lifecycleSnapshot().Paused {
		t.Fatalf("stale edit changed runtime: %+v", window)
	}
}

func mustRunWindow(t *testing.T, end string) *db.TaskRunWindow {
	t.Helper()
	policy, err := db.ValidateTaskRunWindow(&db.TaskRunWindow{End: end, TimeZone: "UTC"})
	if err != nil {
		t.Fatal(err)
	}
	return policy
}
