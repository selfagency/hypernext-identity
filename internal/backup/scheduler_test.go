package backup

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/hypernext/identity/internal/storage"
)

// TestSchedulerStart verifies a valid schedule starts and runs a backup.
func TestSchedulerStart(t *testing.T) {
	fs := &storage.FS{Root: t.TempDir()}
	dest := &FSDestination{Backend: fs, Prefix: "backups"}

	ran := make(chan string, 1)
	s := NewScheduler(Config{
		Schedule:    "* * * * * *", // every second (seconds field enabled)
		Destination: dest,
	}, func(ctx context.Context) (io.Reader, error) {
		ran <- "ran"
		return strings.NewReader("backup-data"), nil
	})

	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer s.Stop()

	// Wait for the backup to run (cron fires within a second).
	select {
	case <-ran:
	case <-time.After(3 * time.Second):
		t.Fatal("backup did not run")
	}

	// Poll for the backup to be written (WriteBackup runs after BackupFn).
	deadline := time.Now().Add(3 * time.Second)
	for {
		blobs, err := fs.List(context.Background(), "backups/")
		if err != nil {
			t.Fatal(err)
		}
		if len(blobs) == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("backups = %d, want 1", len(blobs))
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestSchedulerEmptySchedule verifies an empty schedule is rejected.
func TestSchedulerEmptySchedule(t *testing.T) {
	fs := &storage.FS{Root: t.TempDir()}
	s := NewScheduler(Config{Schedule: "", Destination: &FSDestination{Backend: fs}}, nil)
	if err := s.Start(); err == nil {
		t.Fatal("expected error for empty schedule")
	}
}

// TestSchedulerNilDestination verifies a nil destination is rejected.
func TestSchedulerNilDestination(t *testing.T) {
	s := NewScheduler(Config{Schedule: "0 2 * * *"}, nil)
	if err := s.Start(); err == nil {
		t.Fatal("expected error for nil destination")
	}
}

// TestSchedulerInvalidSchedule verifies a bad cron expression is rejected.
func TestSchedulerInvalidSchedule(t *testing.T) {
	fs := &storage.FS{Root: t.TempDir()}
	s := NewScheduler(Config{Schedule: "not-a-cron", Destination: &FSDestination{Backend: fs}}, nil)
	if err := s.Start(); err == nil {
		t.Fatal("expected error for invalid schedule")
	}
}

// TestFSDestinationWrite verifies FS destination writes a backup.
func TestFSDestinationWrite(t *testing.T) {
	fs := &storage.FS{Root: t.TempDir()}
	dest := &FSDestination{Backend: fs, Prefix: "backups"}
	key, err := dest.WriteBackup(context.Background(), "backup-1.tar.gz", strings.NewReader("data"))
	if err != nil {
		t.Fatalf("WriteBackup: %v", err)
	}
	if key != "backups/backup-1.tar.gz" {
		t.Fatalf("key = %q", key)
	}
	rc, _, err := fs.Get(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rc.Close() }()
	body, _ := io.ReadAll(rc)
	if string(body) != "data" {
		t.Fatalf("body = %q, want data", body)
	}
}

// TestS3DestinationWrites verifies S3 destination writes a backup.
func TestS3DestinationWrites(t *testing.T) {
	fs := &storage.FS{Root: t.TempDir()}
	dest := &S3Destination{Backend: fs, Prefix: "backups"}
	key, err := dest.WriteBackup(context.Background(), "backup-1.tar.gz", strings.NewReader("data"))
	if err != nil {
		t.Fatalf("WriteBackup: %v", err)
	}
	if key != "backups/backup-1.tar.gz" {
		t.Fatalf("key = %q", key)
	}
}

// TestSchedulerBackupFnNil verifies a nil BackupFn is a no-op.
func TestSchedulerBackupFnNil(t *testing.T) {
	fs := &storage.FS{Root: t.TempDir()}
	s := NewScheduler(Config{Schedule: "* * * * * *", Destination: &FSDestination{Backend: fs, Prefix: "backups"}}, nil)
	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer s.Stop()
	// Should not panic; wait briefly.
	time.Sleep(100 * time.Millisecond)
}
