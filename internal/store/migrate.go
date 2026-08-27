package store

import (
	"context"
	"database/sql"
	"fmt"
)

// migration is a single versioned schema change. Migrations run in order and
// are applied transactionally; once applied, a version is recorded in
// schema_version and never re-run. Never edit a shipped migration — add a new
// one instead.
type migration struct {
	version int
	name    string
	up      func(ctx context.Context, tx *sql.Tx) error
}

// migrations is the ordered list of schema migrations. Version 1 is the
// initial schema (previously applied ad-hoc by migrate()); later versions
// evolve it.
var migrations = []migration{
	{version: 1, name: "initial_schema", up: migrateV1},
	{version: 2, name: "accounts_table", up: migrateV2},
	{version: 3, name: "auth_tables", up: migrateV3},
}

// migrate runs all pending migrations inside transactions and records each
// applied version in schema_version. It is safe to call on every Open.
func (s *Store) migrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_version (
		version    INTEGER PRIMARY KEY,
		name       TEXT NOT NULL,
		applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`); err != nil {
		return fmt.Errorf("store: create schema_version: %w", err)
	}

	current, err := s.currentVersion(ctx)
	if err != nil {
		return err
	}

	for _, m := range migrations {
		if m.version <= current {
			continue
		}
		if err := s.applyMigration(ctx, m); err != nil {
			return fmt.Errorf("store: migration %d (%s): %w", m.version, m.name, err)
		}
	}
	return nil
}

// currentVersion returns the highest applied migration version (0 if none).
func (s *Store) currentVersion(ctx context.Context) (int, error) {
	var v int
	err := s.db.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM schema_version`).Scan(&v)
	if err != nil {
		return 0, fmt.Errorf("store: read schema_version: %w", err)
	}
	return v, nil
}

// applyMigration runs one migration in a transaction and records it.
func (s *Store) applyMigration(ctx context.Context, m migration) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if err := m.up(ctx, tx); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO schema_version (version, name) VALUES (?, ?)`, m.version, m.name); err != nil {
		return err
	}
	return tx.Commit()
}

// migrateV1 is the initial schema. It is idempotent (CREATE IF NOT EXISTS) so
// databases created before the migration runner was introduced converge to the
// same shape.
func migrateV1(ctx context.Context, tx *sql.Tx) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS public_keys (
			id            TEXT PRIMARY KEY,
			tenant_id     TEXT NOT NULL,
			account_id    TEXT NOT NULL,
			key_type      TEXT NOT NULL,
			label         TEXT,
			fingerprint   TEXT NOT NULL,
			key_material  TEXT NOT NULL,
			algorithm     TEXT,
			revoked_at    TIMESTAMP,
			expires_at    TIMESTAMP,
			created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(tenant_id, fingerprint)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_public_keys_account ON public_keys(account_id, key_type)`,
		`CREATE TABLE IF NOT EXISTS profile_pages (
			id              TEXT PRIMARY KEY,
			tenant_id       TEXT NOT NULL UNIQUE,
			account_id      TEXT NOT NULL,
			display_name    TEXT,
			bio             TEXT,
			avatar_blob_key TEXT,
			theme           TEXT NOT NULL DEFAULT 'default',
			is_published    BOOLEAN NOT NULL DEFAULT 0,
			sync_atproto_profile BOOLEAN NOT NULL DEFAULT 0,
			updated_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS profile_links (
			id              TEXT PRIMARY KEY,
			profile_page_id TEXT NOT NULL REFERENCES profile_pages(id) ON DELETE CASCADE,
			position        INTEGER NOT NULL,
			kind            TEXT NOT NULL,
			brand_key       TEXT,
			label           TEXT NOT NULL,
			url             TEXT NOT NULL,
			icon_blob_key   TEXT,
			is_visible      BOOLEAN NOT NULL DEFAULT 1,
			click_count     INTEGER NOT NULL DEFAULT 0,
			created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_profile_links_page_position ON profile_links(profile_page_id, position)`,
		`CREATE TABLE IF NOT EXISTS proof_claims (
			id              TEXT PRIMARY KEY,
			tenant_id       TEXT NOT NULL,
			account_id      TEXT NOT NULL,
			anchor_type     TEXT NOT NULL,
			anchor_value    TEXT NOT NULL,
			service         TEXT NOT NULL,
			claim_location  TEXT NOT NULL,
			expected_token  TEXT NOT NULL,
			status          TEXT NOT NULL DEFAULT 'pending',
			last_checked_at TIMESTAMP,
			last_error      TEXT,
			created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(tenant_id, service, claim_location)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_proof_claims_recheck ON proof_claims(status, last_checked_at)`,
		`CREATE TABLE IF NOT EXISTS auth_signing_keys (
			id         TEXT PRIMARY KEY,
			key_pem    TEXT NOT NULL,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS auth_refresh_tokens (
			token      TEXT PRIMARY KEY,
			subject    TEXT NOT NULL,
			client_id  TEXT NOT NULL,
			scopes     TEXT NOT NULL,
			auth_time  TIMESTAMP NOT NULL,
			expires_at TIMESTAMP,
			revoked_at TIMESTAMP,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS tenants (
			id         TEXT PRIMARY KEY,
			handle     TEXT NOT NULL UNIQUE,
			did_method TEXT NOT NULL DEFAULT 'web',
			did        TEXT,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
	}
	for _, stmt := range stmts {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	return nil
}

// migrateV2 creates the minimal accounts table. It holds the identity
// primitives (DID, WebID) that authorization and profile features depend on.
// Web3/SIWE/ENS identity is deliberately out of scope (decision 7).
func migrateV2(ctx context.Context, tx *sql.Tx) error {
	_, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS accounts (
		id         TEXT PRIMARY KEY,
		tenant_id  TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
		did        TEXT,
		webid      TEXT,
		created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(tenant_id, did)
	)`)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS idx_accounts_tenant ON accounts(tenant_id)`)
	return err
}

// migrateV3 creates the auth tables: users (OIDC/WebAuthn subjects with an
// admin flag), OIDC clients, WebAuthn credentials, and the persistent audit
// log. The first user created is the instance admin (enforced in store code,
// not here).
func migrateV3(ctx context.Context, tx *sql.Tx) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id           TEXT PRIMARY KEY,
			tenant_id    TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
			handle       TEXT NOT NULL,
			display_name TEXT,
			is_admin     BOOLEAN NOT NULL DEFAULT 0,
			created_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(tenant_id, handle)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_users_tenant ON users(tenant_id)`,
		`CREATE TABLE IF NOT EXISTS clients (
			id            TEXT PRIMARY KEY,
			secret        TEXT NOT NULL,
			redirect_uris TEXT NOT NULL,
			scopes        TEXT NOT NULL,
			created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS webauthn_credentials (
			id            TEXT PRIMARY KEY,
			user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			credential_id BLOB NOT NULL,
			public_key    BLOB NOT NULL,
			sign_count    INTEGER NOT NULL DEFAULT 0,
			created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(user_id, credential_id)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_webauthn_user ON webauthn_credentials(user_id)`,
		`CREATE TABLE IF NOT EXISTS audit_log (
			id         TEXT PRIMARY KEY,
			tenant_id  TEXT NOT NULL,
			actor      TEXT NOT NULL,
			action     TEXT NOT NULL,
			target     TEXT,
			detail     TEXT,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_tenant ON audit_log(tenant_id, created_at)`,
	}
	for _, stmt := range stmts {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	return nil
}
