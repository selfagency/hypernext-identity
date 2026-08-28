// Package pdsstore implements a durable SQLite-backed blockstore for the
// atproto PDS repo. It satisfies the go-ipfs-blockstore Blockstore interface
// so it can replace the in-memory TinyBlockstore, persisting the MST/records/
// commits across restarts.
package pdsstore

import (
	"context"
	"database/sql"
	"errors"

	blocks "github.com/ipfs/go-block-format"
	"github.com/ipfs/go-cid"
	ipld "github.com/ipfs/go-ipld-format"
	_ "modernc.org/sqlite"
)

// Blockstore is a SQLite-backed implementation of the go-ipfs-blockstore
// Blockstore interface.
type Blockstore struct {
	db *sql.DB
}

// Open opens (and creates if needed) a SQLite blockstore at path. Pragmas
// (WAL, busy timeout) are set via the DSN so they apply to every pooled
// connection.
func Open(path string) (*Blockstore, error) {
	dsn := path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS blocks (
		cid  TEXT PRIMARY KEY,
		data BLOB NOT NULL
	)`); err != nil {
		_ = db.Close()
		return nil, err
	}
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS repo_root (
		id   INTEGER PRIMARY KEY CHECK (id = 1),
		root TEXT NOT NULL
	)`); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Blockstore{db: db}, nil
}

// Close closes the underlying database.
func (b *Blockstore) Close() error {
	return b.db.Close()
}

// Root returns the persisted repo root CID, or "" if none is stored.
func (b *Blockstore) Root(ctx context.Context) (string, error) {
	var root string
	err := b.db.QueryRowContext(ctx, `SELECT root FROM repo_root WHERE id = 1`).Scan(&root)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return root, err
}

// SetRoot persists the repo root CID.
func (b *Blockstore) SetRoot(ctx context.Context, root string) error {
	_, err := b.db.ExecContext(ctx, `INSERT INTO repo_root (id, root) VALUES (1, ?)
		ON CONFLICT(id) DO UPDATE SET root = excluded.root`, root)
	return err
}

// Put stores a block keyed by its CID.
func (b *Blockstore) Put(ctx context.Context, block blocks.Block) error {
	_, err := b.db.ExecContext(ctx, `INSERT OR REPLACE INTO blocks (cid, data) VALUES (?, ?)`,
		block.Cid().String(), block.RawData())
	return err
}

// PutMany stores multiple blocks in a transaction.
func (b *Blockstore) PutMany(ctx context.Context, bs []blocks.Block) error {
	tx, err := b.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, block := range bs {
		if _, err := tx.ExecContext(ctx, `INSERT OR REPLACE INTO blocks (cid, data) VALUES (?, ?)`,
			block.Cid().String(), block.RawData()); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Get retrieves a block by CID.
func (b *Blockstore) Get(ctx context.Context, c cid.Cid) (blocks.Block, error) {
	var data []byte
	err := b.db.QueryRowContext(ctx, `SELECT data FROM blocks WHERE cid = ?`, c.String()).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, &ipld.ErrNotFound{Cid: c}
	}
	if err != nil {
		return nil, err
	}
	return blocks.NewBlockWithCid(data, c)
}

// GetSize returns the size of a block.
func (b *Blockstore) GetSize(ctx context.Context, c cid.Cid) (int, error) {
	var size int
	err := b.db.QueryRowContext(ctx, `SELECT length(data) FROM blocks WHERE cid = ?`, c.String()).Scan(&size)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, &ipld.ErrNotFound{Cid: c}
	}
	return size, err
}

// Has reports whether a block exists.
func (b *Blockstore) Has(ctx context.Context, c cid.Cid) (bool, error) {
	var one int
	err := b.db.QueryRowContext(ctx, `SELECT 1 FROM blocks WHERE cid = ?`, c.String()).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

// DeleteBlock removes a block.
func (b *Blockstore) DeleteBlock(ctx context.Context, c cid.Cid) error {
	_, err := b.db.ExecContext(ctx, `DELETE FROM blocks WHERE cid = ?`, c.String())
	return err
}

// AllKeysChan returns a channel of all CIDs.
func (b *Blockstore) AllKeysChan(ctx context.Context) (<-chan cid.Cid, error) {
	rows, err := b.db.QueryContext(ctx, `SELECT cid FROM blocks`)
	if err != nil {
		return nil, err
	}
	ch := make(chan cid.Cid)
	go func() {
		defer func() { _ = rows.Close() }()
		defer close(ch)
		for rows.Next() {
			var s string
			if err := rows.Scan(&s); err != nil {
				return
			}
			c, err := cid.Decode(s)
			if err != nil {
				return
			}
			select {
			case ch <- c:
			case <-ctx.Done():
				return
			}
		}
	}()
	return ch, nil
}

// HashOnRead is a no-op (blocks are stored verbatim).
func (b *Blockstore) HashOnRead(_ bool) {}
