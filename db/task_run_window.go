package db

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
	_ "time/tzdata"
)

var ErrTaskRunWindowConflict = errors.New("task run window changed or task is unavailable")

// TaskRunWindow defines the local wall-clock time at which the current task run stops.
type TaskRunWindow struct {
	End      string `json:"end"`
	TimeZone string `json:"time_zone"`

	location  *time.Location
	endMinute int
}

func ValidateTaskRunWindow(window *TaskRunWindow) (*TaskRunWindow, error) {
	if window == nil {
		return nil, nil
	}
	end, err := time.Parse("15:04", window.End)
	if err != nil || end.Format("15:04") != window.End {
		return nil, errors.New("渗透测试暂停时间必须为 HH:MM")
	}
	if window.TimeZone == "" || window.TimeZone == "Local" || len(window.TimeZone) > 100 {
		return nil, errors.New("请选择明确的 IANA 时区")
	}
	location, err := time.LoadLocation(window.TimeZone)
	if err != nil {
		return nil, errors.New("无效的 IANA 时区")
	}
	normalized := *window
	normalized.location = location
	normalized.endMinute = end.Hour()*60 + end.Minute()
	return &normalized, nil
}

// NextStop returns the first local occurrence of the configured stop time that
// has not passed yet. A run stays stopped after that instant until its stop time
// is changed, so callers retain this value instead of recalculating it later.
func (w *TaskRunWindow) NextStop(at time.Time) time.Time {
	if w == nil || w.location == nil {
		return time.Time{}
	}
	first := at.Truncate(time.Minute)
	if first.Before(at) {
		first = first.Add(time.Minute)
	}
	for next, limit := first, at.Add(48*time.Hour); !next.After(limit); next = next.Add(time.Minute) {
		local := next.In(w.location)
		if local.Hour()*60+local.Minute() == w.endMinute {
			return next
		}
	}
	return time.Time{}
}

func decodeTaskRunWindow(raw []byte) (*TaskRunWindow, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var window *TaskRunWindow
	if err := json.Unmarshal(raw, &window); err != nil {
		return nil, fmt.Errorf("decode task run window: %w", err)
	}
	return ValidateTaskRunWindow(window)
}

func (d *DB) ReplaceTaskRunWindow(taskID, revision int64, next *TaskRunWindow) (int64, error) {
	normalized, err := ValidateTaskRunWindow(next)
	if err != nil {
		return 0, err
	}
	data, err := json.Marshal(normalized)
	if err != nil {
		return 0, err
	}
	tx, err := d.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var previous []byte
	var current int64
	if err := tx.QueryRow(`
SELECT run_window, run_window_revision FROM tasks
WHERE id=$1 AND deleted_at IS NULL AND status NOT IN ('done','failed','timeout')
FOR UPDATE`, taskID).Scan(&previous, &current); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, ErrTaskRunWindowConflict
		}
		return 0, err
	}
	if revision != current {
		return 0, ErrTaskRunWindowConflict
	}
	revision++
	if _, err := tx.Exec(`
UPDATE tasks SET run_window=NULLIF($2::jsonb,'null'::jsonb), run_window_revision=$3,
paused=true, queued=false, queued_at=NULL WHERE id=$1`, taskID, string(data), revision); err != nil {
		return 0, err
	}
	var oldValue any
	if previous != nil {
		oldValue = string(previous)
	}
	if _, err := tx.Exec(`
INSERT INTO task_run_window_audit(task_id, revision, actor, previous_window, next_window)
VALUES ($1,$2,'ARTEX',$3::jsonb,NULLIF($4::jsonb,'null'::jsonb))`, taskID, revision, oldValue, string(data)); err != nil {
		return 0, err
	}
	return revision, tx.Commit()
}
