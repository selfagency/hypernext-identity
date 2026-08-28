package mail

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
)

// fakeSMTPServer is a minimal SMTP server that accepts a single message
// conversation (EHLO/MAIL/RCPT/DATA/QUIT) and records the delivered message.
type fakeSMTPServer struct {
	ln      net.Listener
	addr    string
	gotData string
}

// startFakeSMTP boots a fake SMTP server on a random localhost port.
func startFakeSMTP(t *testing.T) *fakeSMTPServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &fakeSMTPServer{ln: ln, addr: ln.Addr().String()}
	go s.serve()
	t.Cleanup(func() { _ = ln.Close() })
	return s
}

func (s *fakeSMTPServer) serve() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(conn)
	}
}

func (s *fakeSMTPServer) handle(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	r := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)
	write := func(line string) { _, _ = w.WriteString(line + "\r\n"); _ = w.Flush() }

	write("220 fake ESMTP")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.ToUpper(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(cmd, "EHLO"):
			write("250-fake")
			write("250 OK")
		case strings.HasPrefix(cmd, "MAIL"):
			write("250 OK")
		case strings.HasPrefix(cmd, "RCPT"):
			write("250 OK")
		case strings.HasPrefix(cmd, "DATA"):
			write("354 go ahead")
			var body strings.Builder
			for {
				dl, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if strings.TrimRight(dl, "\r\n") == "." {
					break
				}
				body.WriteString(dl)
			}
			s.gotData = body.String()
			write("250 OK")
		case strings.HasPrefix(cmd, "QUIT"):
			write("221 bye")
			return
		default:
			write("250 OK")
		}
	}
}

// TestSMTPHappyPath proves SMTP.Send delivers a message through a real SMTP
// conversation (non-TLS direct dial).
func TestSMTPHappyPath(t *testing.T) {
	srv := startFakeSMTP(t)
	host, port, _ := net.SplitHostPort(srv.addr)
	var portNum int
	_, _ = fmt.Sscanf(port, "%d", &portNum)

	s := NewSMTP(SMTPConfig{Host: host, Port: portNum, From: "no-reply@example.com"})
	if err := s.Send(context.Background(), Message{To: "alice@example.com", Subject: "hi", Body: "body"}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if !strings.Contains(srv.gotData, "Subject: hi") {
		t.Fatalf("delivered message missing subject: %q", srv.gotData)
	}
	if !strings.Contains(srv.gotData, "body") {
		t.Fatalf("delivered message missing body: %q", srv.gotData)
	}
}

// TestSMTPDialError proves a connection failure surfaces an error.
func TestSMTPDialError(t *testing.T) {
	// Grab a port that is closed by binding then closing it.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	host, port, _ := net.SplitHostPort(addr)
	var portNum int
	_, _ = fmt.Sscanf(port, "%d", &portNum)

	s := NewSMTP(SMTPConfig{Host: host, Port: portNum})
	if err := s.Send(context.Background(), Message{To: "a@example.com", Subject: "s", Body: "b"}); err == nil {
		t.Fatal("expected dial error")
	}
}
