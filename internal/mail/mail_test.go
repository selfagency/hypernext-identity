package mail

import (
	"context"
	"log/slog"
	"strings"
	"testing"
)

// TestBuildMessage verifies the RFC 5322 message shape.
func TestBuildMessage(t *testing.T) {
	msg := buildMessage("no-reply@example.com", Message{
		To:      "alice@example.com",
		Subject: "Your invite",
		Body:    "Click the link",
	})
	s := string(msg)
	for _, want := range []string{
		"From: no-reply@example.com",
		"To: alice@example.com",
		"Subject: Your invite",
		"Content-Type: text/plain; charset=utf-8",
		"Click the link",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("message missing %q:\n%s", want, s)
		}
	}
}

// TestSMTPEnabled verifies the Enabled gate.
func TestSMTPEnabled(t *testing.T) {
	var empty SMTPConfig
	if empty.Enabled() {
		t.Fatal("empty config should be disabled")
	}
	cfg := SMTPConfig{Host: "smtp.example.com", Port: 587}
	if !cfg.Enabled() {
		t.Fatal("host+port should be enabled")
	}
}

// TestLogSender verifies the dev fallback logs without error.
func TestLogSender(t *testing.T) {
	var buf strings.Builder
	log := slog.New(slog.NewTextHandler(&buf, nil))
	s := NewLogSender(log)
	if err := s.Send(context.Background(), Message{To: "a@example.com", Subject: "hi", Body: "body"}); err != nil {
		t.Fatalf("LogSender.Send: %v", err)
	}
	if !strings.Contains(buf.String(), "a@example.com") {
		t.Fatalf("log output missing recipient: %s", buf.String())
	}
	// Nil logger must not panic.
	if err := NewLogSender(nil).Send(context.Background(), Message{}); err != nil {
		t.Fatalf("nil-logger Send: %v", err)
	}
}
