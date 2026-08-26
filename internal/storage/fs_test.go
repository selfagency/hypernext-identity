package storage

import (
	"testing"
)

func TestFSContract(t *testing.T) {
	RunContractTests(t, func() Backend {
		return &FS{Root: t.TempDir()}
	})
}
