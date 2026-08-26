package storage

import (
	"context"
	"errors"
	"io"
	"strings"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// S3 is a Backend backed by any S3-compatible endpoint (AWS S3, MinIO,
// Backblaze B2, etc.) via minio-go.
type S3 struct {
	client *minio.Client
	bucket string
}

// S3Config holds connection settings for an S3-compatible endpoint.
type S3Config struct {
	Endpoint  string // e.g. "s3.amazonaws.com" or "localhost:9000"
	Bucket    string
	AccessKey string
	SecretKey string
	Region    string
	Secure    bool // https when true
}

// NewS3 builds an S3 backend and verifies the bucket exists (creating it
// if missing).
func NewS3(cfg S3Config) (*S3, error) {
	client, err := minio.New(cfg.Endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.AccessKey, cfg.SecretKey, ""),
		Secure: cfg.Secure,
		Region: cfg.Region,
	})
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	exists, err := client.BucketExists(ctx, cfg.Bucket)
	if err != nil {
		return nil, err
	}
	if !exists {
		if err := client.MakeBucket(ctx, cfg.Bucket, minio.MakeBucketOptions{Region: cfg.Region}); err != nil {
			return nil, err
		}
	}
	return &S3{client: client, bucket: cfg.Bucket}, nil
}

func (s *S3) Put(ctx context.Context, key string, r io.Reader, contentType string) (Blob, error) {
	info, err := s.client.PutObject(ctx, s.bucket, key, r, -1, minio.PutObjectOptions{ContentType: contentType})
	if err != nil {
		return Blob{}, err
	}
	return Blob{Key: key, ContentType: contentType, Size: info.Size}, nil
}

func (s *S3) Get(ctx context.Context, key string) (io.ReadCloser, Blob, error) {
	obj, err := s.client.GetObject(ctx, s.bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return nil, Blob{}, err
	}
	st, err := obj.Stat()
	if err != nil {
		obj.Close()
		if isNotFound(err) {
			return nil, Blob{}, ErrNotFound
		}
		return nil, Blob{}, err
	}
	return obj, Blob{Key: key, ContentType: st.ContentType, Size: st.Size}, nil
}

func (s *S3) Delete(ctx context.Context, key string) error {
	err := s.client.RemoveObject(ctx, s.bucket, key, minio.RemoveObjectOptions{})
	if err != nil && !isNotFound(err) {
		return err
	}
	return nil
}

func (s *S3) List(ctx context.Context, prefix string) ([]Blob, error) {
	var out []Blob
	for obj := range s.client.ListObjects(ctx, s.bucket, minio.ListObjectsOptions{Prefix: prefix, Recursive: true}) {
		if obj.Err != nil {
			return nil, obj.Err
		}
		out = append(out, Blob{Key: obj.Key, ContentType: obj.ContentType, Size: obj.Size})
	}
	return out, nil
}

func isNotFound(err error) bool {
	var resp minio.ErrorResponse
	return errors.As(err, &resp) && resp.Code == "NoSuchKey" ||
		strings.Contains(err.Error(), "NoSuchKey")
}

var _ Backend = (*S3)(nil)
