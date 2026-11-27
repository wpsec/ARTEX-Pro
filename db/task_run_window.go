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

// TaskRunWindow stores a one-time start/pause schedule. End remains readable for
// tasks created by the older daily-pause configuration.
type TaskRunWindow struct {
	StartAt  string `json:"start_at,omitempty"`
	PauseAt  string `json:"pause_at,omitempty"`
	End      string `json:"end,omitempty"`
	TimeZone string `json:"time_zone"`

	location   *time.Location
	startAt    time.Time
	pauseAt    time.Time
	endMinute  int
	dailyPause bool
}

func ValidateTaskRunWindow(window *TaskRunWindow) (*TaskRunWindow, error) {
	if window == nil {
		return nil, nil
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
	if window.End != "" && window.StartAt == "" && window.PauseAt == "" {
		end, err := time.Parse("15:04", window.End)
		if err != nil || end.Format("15:04") != window.End {
			return nil, errors.New("每日暂停时间必须为 HH:MM")
		}
		normalized.dailyPause = true
		normalized.endMinute = end.Hour()*60 + end.Minute()
		return &normalized, nil
	}
	if window.End != "" || window.StartAt == "" || window.PauseAt == "" {
		return nil, errors.New("自动启动时间和自动暂停时间必须同时设置")
	}
	const layout = "2006-01-02T15:04"
	startAt, err := time.ParseInLocation(layout, window.StartAt, location)
	if err != nil || startAt.Format(layout) != window.StartAt {
		return nil, errors.New("自动启动时间格式必须为 YYYY-MM-DDTHH:MM")
	}
	pauseAt, err := time.ParseInLocation(layout, window.PauseAt, location)
	if err != nil || pauseAt.Format(layout) != window.PauseAt {
		return nil, errors.New("自动暂停时间格式必须为 YYYY-MM-DDTHH:MM")
	}
	if !pauseAt.After(startAt) {
		return nil, errors.New("自动暂停时间必须晚于自动启动时间")
	}
	normalized.startAt = startAt
	normalized.pauseAt = pauseAt
	return &normalized, nil
}

// StartTime returns the configured one-time start instant, or zero for legacy
// daily schedules.
func (w *TaskRunWindow) StartTime() time.Time {
	if w == nil {
		return time.Time{}
	}
	return w.startAt
}

// PauseTime returns the configured one-time pause instant, or the next legacy
// daily pause for the supplied time.
func (w *TaskRunWindow) PauseTime(at time.Time) time.Time {
	if w == nil {
		return time.Time{}
	}
	if !w.pauseAt.IsZero() {
		return w.pauseAt
	}
	return w.NextStop(at)
}

func (w *TaskRunWindow) IsDailyPause() bool { return w != nil && w.dailyPause }

// NextStop returns the one-time pause instant, or the first local occurrence of
// a legacy daily pause time that has not passed yet.
func (w *TaskRunWindow) NextStop(at time.Time) time.Time {
	if w == nil || w.location == nil {
		return time.Time{}
	}
	if !w.pauseAt.IsZero() {
		return w.pauseAt
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

func (d *DB) ReplaceTaskRunWindow(taskID, revision int64, next *TaskRunWindow, pausedState ...bool) (int64, error) {
	normalized, err := ValidateTaskRunWindow(next)
	if err != nil {
		return 0, err
	}
	data, err := json.Marshal(normalized)
	if err != nil {
		return 0, err
	}
	paused := normalized == nil || normalized.StartTime().IsZero() || !normalized.StartTime().After(time.Now())
	if len(pausedState) > 0 {
		paused = pausedState[0]
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
paused=$4, queued=false, queued_at=NULL WHERE id=$1`, taskID, string(data), revision, paused); err != nil {
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
