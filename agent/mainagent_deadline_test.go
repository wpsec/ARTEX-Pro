package agent

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestMainAgentSystemIncludesExecutionDeadline(t *testing.T) {
	deadline := time.Now().Add(time.Hour).In(time.FixedZone("UTC+8", 8*60*60))
	ctx, cancel := context.WithDeadline(t.Context(), deadline)
	defer cancel()

	const label = "当前会话的执行截止时间为 "
	if system := mainAgentSystem(ctx, "", "", ""); !strings.Contains(system, label+deadline.Format(time.RFC3339)) {
		t.Fatal("main agent prompt is missing the execution deadline with its time zone")
	}
	if system := mainAgentSystem(context.Background(), "", "", ""); strings.Contains(system, label) {
		t.Fatal("main agent prompt shows an execution deadline for an unbounded context")
	}
}

func TestMainAgentChatSkipsSetupAfterDeadline(t *testing.T) {
	windowClosed := errors.New("run window closed")
	ctx, cancel := context.WithDeadlineCause(t.Context(), time.Now().Add(-time.Second), windowClosed)
	defer cancel()

	var main MainAgent
	_, err := main.Chat(ctx, 0, 0, nil, nil, "", "", nil, nil, nil, nil, nil)
	if !errors.Is(err, windowClosed) {
		t.Fatalf("Chat error = %v, want %v", err, windowClosed)
	}
}
