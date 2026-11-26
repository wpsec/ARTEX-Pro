package db

import (
	"errors"
	"testing"
	"time"
)

func TestTaskRunWindowNextStop(t *testing.T) {
	for _, tc := range []struct {
		name       string
		window     TaskRunWindow
		at, stopAt string
	}{
		{"上海当天停止", TaskRunWindow{End: "22:00", TimeZone: "Asia/Shanghai"}, "2026-11-26T13:59:59Z", "2026-11-26T14:00:00Z"},
		{"停止时刻正好到达", TaskRunWindow{End: "22:00", TimeZone: "Asia/Shanghai"}, "2026-11-26T14:00:00Z", "2026-11-26T14:00:00Z"},
		{"UTC 当天停止", TaskRunWindow{End: "17:00", TimeZone: "UTC"}, "2026-11-27T12:30:00Z", "2026-11-27T17:00:00Z"},
		{"夏令时当天停止", TaskRunWindow{End: "03:30", TimeZone: "America/New_York"}, "2026-03-08T06:45:00Z", "2026-03-08T07:30:00Z"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			at, err := time.Parse(time.RFC3339, tc.at)
			if err != nil {
				t.Fatal(err)
			}
			window, err := ValidateTaskRunWindow(&tc.window)
			if err != nil {
				t.Fatal(err)
			}
			if got := window.NextStop(at).UTC().Format(time.RFC3339); got != tc.stopAt {
				t.Fatalf("next stop = %v, want %v", got, tc.stopAt)
			}
		})
	}
}

func TestTaskRunWindowValidation(t *testing.T) {
	for _, input := range []TaskRunWindow{
		{End: "", TimeZone: "UTC"},
		{End: "9:00", TimeZone: "UTC"},
		{End: "24:00", TimeZone: "UTC"},
		{End: "18:00", TimeZone: "Local"},
		{End: "18:00", TimeZone: "Test/Unknown"},
	} {
		if _, err := ValidateTaskRunWindow(&input); err == nil {
			t.Errorf("accepted invalid input: %+v", input)
		}
	}
}

func TestTaskRunWindowPersistence(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	window := &TaskRunWindow{End: "08:00", TimeZone: "Asia/Shanghai"}
	task, err := d.CreateTaskWithOptions("window fixture", "verify persisted configuration", TaskCreateOptions{RunWindow: window})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := d.Exec("DELETE FROM tasks WHERE id=$1", task.ID); err != nil {
			t.Error(err)
		}
		if _, err := d.Exec("DELETE FROM explorations WHERE id=$1", task.ExplorationID); err != nil {
			t.Error(err)
		}
	}()
	stored, err := d.GetTask(task.ID)
	if err != nil || stored == nil || stored.Paused || stored.Queued || stored.RunWindowRevision != 1 ||
		stored.RunWindow == nil || stored.RunWindow.End != "08:00" {
		t.Fatalf("initial stored state = %+v, err = %v", stored, err)
	}
	next := &TaskRunWindow{End: "07:00", TimeZone: "Asia/Shanghai"}
	results := make(chan error, 2)
	for range 2 {
		go func() {
			_, err := d.ReplaceTaskRunWindow(task.ID, 1, next)
			results <- err
		}()
	}
	first, second := <-results, <-results
	if !((first == nil && errors.Is(second, ErrTaskRunWindowConflict)) ||
		(second == nil && errors.Is(first, ErrTaskRunWindowConflict))) {
		t.Fatalf("concurrent edit = %v, %v", first, second)
	}
	if revision, err := d.ReplaceTaskRunWindow(task.ID, 2, nil); err != nil || revision != 3 {
		t.Fatalf("remove revision = %d, err = %v", revision, err)
	}
	stored, err = d.GetTask(task.ID)
	if err != nil || stored == nil || !stored.Paused || stored.Queued || stored.RunWindowRevision != 3 || stored.RunWindow != nil {
		t.Fatalf("stored after removal = %+v, err = %v", stored, err)
	}
	var audit, correct int
	if err := d.QueryRow(`SELECT count(*), count(*) FILTER (WHERE
		(revision=1 AND previous_window IS NULL AND next_window->>'end'='08:00')
		OR (revision=2 AND previous_window->>'end'='08:00' AND next_window->>'end'='07:00')
		OR (revision=3 AND previous_window->>'end'='07:00' AND next_window IS NULL))
		FROM task_run_window_audit WHERE task_id=$1 AND actor='ARTEX' AND effective_at IS NOT NULL`, task.ID).Scan(&audit, &correct); err != nil || audit != 3 || correct != 3 {
		t.Fatalf("audit entries = %d, correct = %d, err = %v", audit, correct, err)
	}
}
