// Package backup implements the scheduled backup system. Users configure a
// cron schedule and a destination (local filesystem or S3-compatible) via the
// admin UI; the scheduler runs backups on that schedule.
package backup

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/robfig/cron/v3"

	"github.com/hypernext/identity/internal/storage"
)

// Destination is where backups are written.
type Destination interface {
	// WriteBackup stores a backup blob and returns its key.
	WriteBackup(ctx context.Context, name string, r io.Reader) (string, error)
}

// Validation sentinels for backup config.
var (
	ErrEmptySchedule      = errors.New("backup schedule is empty")
	ErrInvalidDestination = errors.New("backup destination must be fs or s3")
	ErrEmptyPrefix        = errors.New("backup prefix is empty")
)

// FSDestination writes backups to a local directory.
type FSDestination struct {
	Backend storage.Backend
	Prefix  string
}

// WriteBackup stores a backup in the FS backend.
func (d *FSDestination) WriteBackup(ctx context.Context, name string, r io.Reader) (string, error) {
	key := d.Prefix + "/" + name
	blob, err := d.Backend.Put(ctx, key, r, "application/octet-stream")
	if err != nil {
		return "", err
	}
	return blob.Key, nil
}

// S3Destination writes backups to an S3-compatible bucket.
type S3Destination struct {
	Backend storage.Backend
	Prefix  string
}

// WriteBackup stores a backup in the S3 backend.
func (d *S3Destination) WriteBackup(ctx context.Context, name string, r io.Reader) (string, error) {
	key := d.Prefix + "/" + name
	blob, err := d.Backend.Put(ctx, key, r, "application/octet-stream")
	if err != nil {
		return "", err
	}
	return blob.Key, nil
}

// Config holds the backup schedule and destination.
type Config struct {
	// Schedule is a cron expression (e.g. "0 2 * * *" for 2am daily).
	Schedule string
	// Destination is where backups are written.
	Destination Destination
}

// Scheduler runs backups on a cron schedule.
type Scheduler struct {
	cron   *cron.Cron
	config Config
	// BackupFn produces the backup bytes. The storage phase wires a real
	// implementation; the interface keeps the scheduler testable.
	BackupFn func(ctx context.Context) (io.Reader, error)
}

// NewScheduler builds a scheduler for a config.
func NewScheduler(config Config, backupFn func(ctx context.Context) (io.Reader, error)) *Scheduler {
	return &Scheduler{
		cron:     cron.New(cron.WithSeconds()),
		config:   config,
		BackupFn: backupFn,
	}
}

// Start registers the backup job and starts the cron loop.
func (s *Scheduler) Start() error {
	if s.config.Schedule == "" {
		return errors.New("backup schedule is empty")
	}
	if s.config.Destination == nil {
		return errors.New("backup destination is nil")
	}
	if _, err := s.cron.AddFunc(s.config.Schedule, s.runBackup); err != nil {
		return fmt.Errorf("invalid schedule %q: %w", s.config.Schedule, err)
	}
	s.cron.Start()
	return nil
}

// Stop halts the cron loop.
func (s *Scheduler) Stop() {
	s.cron.Stop()
}

// runBackup executes a single backup.
func (s *Scheduler) runBackup() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	if s.BackupFn == nil {
		return
	}
	r, err := s.BackupFn(ctx)
	if err != nil {
		return
	}
	name := "backup-" + time.Now().UTC().Format("20060102-150405") + ".tar.gz"
	_, _ = s.config.Destination.WriteBackup(ctx, name, r)
}
