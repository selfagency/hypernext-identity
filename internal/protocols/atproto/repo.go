package atproto

import (
	"context"
	"fmt"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	atrepo "github.com/bluesky-social/indigo/atproto/repo"
	"github.com/bluesky-social/indigo/repo"
)

// Repo wraps an atproto repository with commit signing.
type Repo struct {
	r  *repo.Repo
	sk atcrypto.PrivateKey
}

// NewRepo creates a new in-memory repo for a DID with the given signing key.
func NewRepo(ctx context.Context, did string, sk atcrypto.PrivateKey) (*Repo, error) {
	bs := atrepo.NewTinyBlockstore()
	r := repo.NewRepo(ctx, did, bs)
	return &Repo{r: r, sk: sk}, nil
}

// CreateRecord writes a record to the repo and returns its CID and TID.
func (r *Repo) CreateRecord(ctx context.Context, nsid string, rec repo.CborMarshaler) (cidStr, tid string, err error) {
	c, tid, err := r.r.CreateRecord(ctx, nsid, rec)
	if err != nil {
		return "", "", err
	}
	return c.String(), tid, nil
}

// Commit signs and commits the repo, returning the commit CID and revision.
func (r *Repo) Commit(ctx context.Context) (commitCid, rev string, err error) {
	c, rev, err := r.r.Commit(ctx, func(_ context.Context, _ string, data []byte) ([]byte, error) {
		return r.sk.HashAndSign(data)
	})
	if err != nil {
		return "", "", err
	}
	return c.String(), rev, nil
}

// SignedCommit returns the current signed commit.
func (r *Repo) SignedCommit() repo.SignedCommit {
	return r.r.SignedCommit()
}

// VerifyCommit verifies the repo's signed commit against a public key.
func (r *Repo) VerifyCommit(pub atcrypto.PublicKey) error {
	sc := r.r.SignedCommit()
	signingBytes, err := sc.Unsigned().BytesForSigning()
	if err != nil {
		return fmt.Errorf("commit signing bytes: %w", err)
	}
	if err := pub.HashAndVerify(signingBytes, sc.Sig); err != nil {
		return fmt.Errorf("commit signature invalid: %w", err)
	}
	return nil
}
