package atproto

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/selfagency/sovereign/internal/storage"
	"github.com/selfagency/sovereign/internal/store"
)

// XRPCServer serves atproto XRPC endpoints (com.atproto.*) for the tenant
// in the request context.
type XRPCServer struct {
	Store *store.Store
	// Backend returns the storage backend for a tenant (used for blobs).
	Backend func(tenantID string) storage.Backend
	// RepoFactory builds a repo for a DID (per-tenant blockstore).
	RepoFactory func(ctx context.Context, did string) (*Repo, error)
}

// ServeHTTP routes XRPC method calls.
func (s *XRPCServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Path is /xrpc/<method>.
	method := strings.TrimPrefix(r.URL.Path, "/xrpc/")
	switch method {
	case "com.atproto.identity.resolveHandle":
		s.resolveHandle(w, r)
	case "app.bsky.actor.getProfile":
		s.getProfile(w, r)
	case "com.atproto.repo.createRecord":
		s.createRecord(w, r)
	case "com.atproto.repo.getRecord":
		s.getRecord(w, r)
	default:
		writeXRPCError(w, http.StatusNotImplemented, "MethodNotImplemented", "method not implemented: "+method)
	}
}

// resolveHandle resolves a handle to a DID.
func (s *XRPCServer) resolveHandle(w http.ResponseWriter, r *http.Request) {
	handle := r.URL.Query().Get("handle")
	if handle == "" {
		writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "handle is required")
		return
	}
	t, err := s.Store.GetTenantByHandle(r.Context(), handle)
	if err != nil {
		writeXRPCError(w, http.StatusNotFound, "HandleNotFound", "handle not found")
		return
	}
	did := t.DID
	if did == "" {
		did = "did:web:" + handle
	}
	writeJSON(w, map[string]string{"did": did})
}

// getProfile implements app.bsky.actor.getProfile.
func (s *XRPCServer) getProfile(w http.ResponseWriter, r *http.Request) {
	actor := r.URL.Query().Get("actor")
	if actor == "" {
		writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "actor is required")
		return
	}
	// actor may be a handle or DID.
	handle := actor
	if strings.HasPrefix(actor, "did:") {
		// Resolve DID to handle via the tenant store (best-effort).
		handle = actor
	}
	t, err := s.Store.GetTenantByHandle(r.Context(), handle)
	if err != nil {
		writeXRPCError(w, http.StatusNotFound, "ActorNotFound", "actor not found")
		return
	}
	writeJSON(w, map[string]any{
		"did":         t.DID,
		"handle":      t.Handle,
		"displayName": t.Handle,
	})
}

// createRecord implements com.atproto.repo.createRecord. It writes a record
// to the repo for the authenticated DID and commits it.
func (s *XRPCServer) createRecord(w http.ResponseWriter, r *http.Request) {
	if s.RepoFactory == nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalError", "repo factory not configured")
		return
	}
	var in struct {
		Repo       string          `json:"repo"`
		Collection string          `json:"collection"`
		Record     json.RawMessage `json:"record"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "bad body")
		return
	}
	if in.Repo == "" || in.Collection == "" || len(in.Record) == 0 {
		writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "repo, collection, and record are required")
		return
	}
	repo, err := s.RepoFactory(r.Context(), in.Repo)
	if err != nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	defer func() { _ = repo.Close() }()
	rec := &jsonRecord{data: in.Record}
	cid, tid, err := repo.CreateRecord(r.Context(), in.Collection, rec)
	if err != nil {
		writeXRPCError(w, http.StatusBadRequest, "InvalidRecord", err.Error())
		return
	}
	commitCid, rev, err := repo.Commit(r.Context())
	if err != nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	writeJSON(w, map[string]any{
		"uri":    "at://" + in.Repo + "/" + in.Collection + "/" + tid,
		"cid":    cid,
		"commit": map[string]string{"cid": commitCid, "rev": rev},
	})
}

// getRecord implements com.atproto.repo.getRecord. It reads a record back
// from the repo.
func (s *XRPCServer) getRecord(w http.ResponseWriter, r *http.Request) {
	if s.RepoFactory == nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalError", "repo factory not configured")
		return
	}
	repo := r.URL.Query().Get("repo")
	collection := r.URL.Query().Get("collection")
	rkey := r.URL.Query().Get("rkey")
	if repo == "" || collection == "" || rkey == "" {
		writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "repo, collection, and rkey are required")
		return
	}
	rp, err := s.RepoFactory(r.Context(), repo)
	if err != nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	defer func() { _ = rp.Close() }()
	_, data, err := rp.GetRecordBytes(r.Context(), collection+"/"+rkey)
	if err != nil {
		writeXRPCError(w, http.StatusNotFound, "RecordNotFound", "record not found")
		return
	}
	// The record is stored as a CBOR byte-string wrapping the JSON; unwrap it.
	value := unwrapCBORBytes(data)
	writeJSON(w, map[string]any{
		"uri":   "at://" + repo + "/" + collection + "/" + rkey,
		"value": json.RawMessage(value),
	})
}

// jsonRecord adapts a raw JSON record to the repo's CborMarshaler.
type jsonRecord struct {
	data json.RawMessage
}

// MarshalCBOR encodes the JSON record as a CBOR byte string so it round-trips.
func (j *jsonRecord) MarshalCBOR(w io.Writer) error {
	if len(j.data) > 255 {
		return errors.New("atproto: record too large for byte-string encoding")
	}
	// #nosec G115 -- len(j.data) is bounded to <= 255 above, so the int->byte
	// conversion cannot overflow.
	hdr := []byte{0x58, byte(len(j.data))}
	_, err := w.Write(append(hdr, j.data...))
	return err
}

// unwrapCBORBytes extracts the JSON payload from a CBOR byte-string wrapper
// (the format jsonRecord.MarshalCBOR writes).
func unwrapCBORBytes(data []byte) []byte {
	// CBOR major type 2 (byte string): 0x40-0x5b. We wrote 0x58 <len> <json>.
	if len(data) >= 2 && data[0] == 0x58 {
		l := int(data[1])
		if len(data) >= 2+l {
			return data[2 : 2+l]
		}
	}
	return data
}

// writeJSON writes a JSON response.
func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// writeXRPCError writes an XRPC error response.
func writeXRPCError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "message": message})
}
