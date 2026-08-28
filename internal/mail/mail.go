// Package mail sends outbound email (invite magic links, notifications) via
// stdlib net/smtp. It exposes a small Sender interface so callers can inject a
// fake in tests, and provides an SMTP implementation plus a logging fallback
// for development when SMTP is not configured.
package mail

import (
	"context"
	"fmt"
	"log/slog"
	"net/smtp"
	"strings"
)

// Message is a single outbound email.
type Message struct {
	To      string
	Subject string
	Body    string // plain text
}

// Sender delivers a Message. Implementations must be safe for concurrent use.
type Sender interface {
	Send(ctx context.Context, m Message) error
}

// SMTPConfig mirrors the server SMTP config block.
type SMTPConfig struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
	TLS      bool // STARTTLS
}

// Enabled reports whether SMTP is configured for sending.
func (c SMTPConfig) Enabled() bool {
	return c.Host != "" && c.Port != 0
}

// SMTP is a Sender backed by stdlib net/smtp.
type SMTP struct {
	cfg SMTPConfig
}

// NewSMTP builds an SMTP sender.
func NewSMTP(cfg SMTPConfig) *SMTP {
	return &SMTP{cfg: cfg}
}

// Send delivers a message via SMTP. It uses the plain auth mechanism when
// credentials are present, and STARTTLS when configured.
func (s *SMTP) Send(ctx context.Context, m Message) error {
	addr := fmt.Sprintf("%s:%d", s.cfg.Host, s.cfg.Port)
	from := s.cfg.From
	if from == "" {
		from = "no-reply@" + s.cfg.Host
	}

	var auth smtp.Auth
	if s.cfg.Username != "" {
		auth = smtp.PlainAuth("", s.cfg.Username, s.cfg.Password, s.cfg.Host)
	}

	msg := buildMessage(from, m)
	if s.cfg.TLS {
		return smtp.SendMail(addr, auth, from, []string{m.To}, msg)
	}
	// Without STARTTLS, connect and send directly (local/dev relays).
	c, err := smtp.Dial(addr)
	if err != nil {
		return fmt.Errorf("mail: dial: %w", err)
	}
	defer func() { _ = c.Close() }()
	if err := c.Mail(from); err != nil {
		return fmt.Errorf("mail: mail: %w", err)
	}
	if err := c.Rcpt(m.To); err != nil {
		return fmt.Errorf("mail: rcpt: %w", err)
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("mail: data: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		return fmt.Errorf("mail: write: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("mail: close: %w", err)
	}
	return c.Quit()
}

// buildMessage assembles the RFC 5322 message bytes.
func buildMessage(from string, m Message) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\n", from)
	fmt.Fprintf(&b, "To: %s\r\n", m.To)
	fmt.Fprintf(&b, "Subject: %s\r\n", m.Subject)
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	b.WriteString("\r\n")
	b.WriteString(m.Body)
	return []byte(b.String())
}

// LogSender is a Sender that logs the message instead of sending. It is the
// development fallback when SMTP is not configured, so magic links remain
// testable without a mail server.
type LogSender struct {
	Log *slog.Logger
}

// NewLogSender builds a logging sender.
func NewLogSender(log *slog.Logger) *LogSender {
	return &LogSender{Log: log}
}

// Send logs the message at info level.
func (l *LogSender) Send(_ context.Context, m Message) error {
	if l.Log == nil {
		return nil
	}
	l.Log.Info("mail (dev fallback, SMTP not configured)",
		"to", m.To, "subject", m.Subject, "body", m.Body)
	return nil
}
