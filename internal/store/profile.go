package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// ProfilePage is a stored profile page row.
type ProfilePage struct {
	ID                 string
	TenantID           string
	AccountID          string
	DisplayName        string
	Bio                string
	AvatarBlobKey      string
	Theme              string
	IsPublished        bool
	SyncAtprotoProfile bool
	UpdatedAt          time.Time
}

// ProfileLink is a stored profile link row.
type ProfileLink struct {
	ID            string
	ProfilePageID string
	Position      int
	Kind          string
	BrandKey      string
	Label         string
	URL           string
	IconBlobKey   string
	IsVisible     bool
	ClickCount    int
	CreatedAt     time.Time
}

// UpsertProfilePage inserts or updates a tenant's profile page.
func (s *Store) UpsertProfilePage(ctx context.Context, p *ProfilePage) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO profile_pages (id, tenant_id, account_id, display_name, bio, avatar_blob_key, theme, is_published, sync_atproto_profile, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(tenant_id) DO UPDATE SET
		   display_name = excluded.display_name,
		   bio = excluded.bio,
		   avatar_blob_key = excluded.avatar_blob_key,
		   theme = excluded.theme,
		   is_published = excluded.is_published,
		   sync_atproto_profile = excluded.sync_atproto_profile,
		   updated_at = excluded.updated_at`,
		p.ID, p.TenantID, p.AccountID, p.DisplayName, p.Bio, p.AvatarBlobKey,
		p.Theme, p.IsPublished, p.SyncAtprotoProfile, p.UpdatedAt)
	return err
}

// GetProfilePage returns a tenant's profile page.
func (s *Store) GetProfilePage(ctx context.Context, tenantID string) (*ProfilePage, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, tenant_id, account_id, display_name, bio, avatar_blob_key, theme, is_published, sync_atproto_profile, updated_at
		 FROM profile_pages WHERE tenant_id = ?`, tenantID)
	var p ProfilePage
	err := row.Scan(&p.ID, &p.TenantID, &p.AccountID, &p.DisplayName, &p.Bio,
		&p.AvatarBlobKey, &p.Theme, &p.IsPublished, &p.SyncAtprotoProfile, &p.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &p, err
}

// ListProfileLinks returns a profile page's links ordered by position.
func (s *Store) ListProfileLinks(ctx context.Context, profilePageID string) ([]ProfileLink, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, profile_page_id, position, kind, brand_key, label, url, icon_blob_key, is_visible, click_count, created_at
		 FROM profile_links WHERE profile_page_id = ? ORDER BY position`, profilePageID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []ProfileLink
	for rows.Next() {
		var l ProfileLink
		if err := rows.Scan(&l.ID, &l.ProfilePageID, &l.Position, &l.Kind, &l.BrandKey,
			&l.Label, &l.URL, &l.IconBlobKey, &l.IsVisible, &l.ClickCount, &l.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// AddProfileLink inserts a link at the end of the list.
func (s *Store) AddProfileLink(ctx context.Context, l *ProfileLink) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO profile_links (id, profile_page_id, position, kind, brand_key, label, url, icon_blob_key, is_visible, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		l.ID, l.ProfilePageID, l.Position, l.Kind, l.BrandKey, l.Label, l.URL, l.IconBlobKey, l.IsVisible, l.CreatedAt)
	return err
}

// ReorderProfileLinks atomically sets the position of each link by ID.
func (s *Store) ReorderProfileLinks(ctx context.Context, profilePageID string, orderedIDs []string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for i, id := range orderedIDs {
		if _, err := tx.ExecContext(ctx,
			`UPDATE profile_links SET position = ? WHERE profile_page_id = ? AND id = ?`,
			i, profilePageID, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// DeleteProfileLink removes a link (scoped to profile page).
func (s *Store) DeleteProfileLink(ctx context.Context, profilePageID, id string) error {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM profile_links WHERE profile_page_id = ? AND id = ?`, profilePageID, id)
	if err != nil {
		return err
	}
	return requireAffected(res)
}

// DeleteProfilePage removes a page and cascades to its links.
func (s *Store) DeleteProfilePage(ctx context.Context, tenantID string) error {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM profile_pages WHERE tenant_id = ?`, tenantID)
	if err != nil {
		return err
	}
	return requireAffected(res)
}
