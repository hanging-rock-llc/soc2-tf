// Package sink abstracts where evidence records are stored: an S3 bucket
// (production, with Object Lock) or a local directory (testing).
package sink

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/hanging-rock-llc/soc2-tf/internal/s3"
)

var (
	// ErrNotFound is returned by Get for a missing key.
	ErrNotFound = errors.New("sink: not found")
	// ErrExists is returned by Create when the key already holds different
	// content.
	ErrExists = errors.New("sink: object already exists")
)

// Object is one stored key and its history.
type Object struct {
	Key string
	// Versions is how many times the key was written. Records are written
	// once, so anything above 1 means a record was overwritten.
	Versions int
	// Deleted is true when the current version is a delete marker.
	Deleted bool
}

// Sink stores evidence objects.
type Sink interface {
	// Put writes key, replacing any current version (index objects).
	Put(key string, data []byte, contentType string) error
	// Create writes key only if it doesn't exist yet (records). Re-creating a
	// key with identical content succeeds, so retried writes are safe.
	Create(key string, data []byte, contentType string) error
	Get(key string) ([]byte, error)
	// List returns every key under prefix, sorted, including deleted ones.
	List(prefix string) ([]Object, error)
	String() string
}

// Options configure sink construction.
type Options struct {
	Region     string
	RetainDays int // optional explicit per-object Object Lock retention
	LockMode   string
}

// Open parses s3://bucket/prefix, file:///path or a plain path.
func Open(uri string, opt Options) (Sink, error) {
	switch {
	case uri == "":
		return nil, errors.New("no sink configured (use --sink or TFPROOF_SINK, e.g. s3://my-evidence-bucket/tfproof)")
	case strings.HasPrefix(uri, "s3://"):
		rest := strings.TrimPrefix(uri, "s3://")
		bucket, prefix, _ := strings.Cut(rest, "/")
		if bucket == "" {
			return nil, fmt.Errorf("invalid s3 sink %q", uri)
		}
		c, err := s3.New(bucket, opt.Region)
		if err != nil {
			return nil, err
		}
		return &S3{Client: c, Prefix: strings.Trim(prefix, "/"), RetainDays: opt.RetainDays, LockMode: opt.LockMode}, nil
	case strings.HasPrefix(uri, "file://"):
		return &Dir{Root: strings.TrimPrefix(uri, "file://")}, nil
	default:
		return &Dir{Root: uri}, nil
	}
}

// S3 stores objects in a bucket under a prefix.
type S3 struct {
	Client     *s3.Client
	Prefix     string
	RetainDays int
	LockMode   string
}

func (s *S3) full(key string) string {
	if s.Prefix == "" {
		return key
	}
	return s.Prefix + "/" + key
}

func (s *S3) put(key string, data []byte, contentType string, createOnly bool) error {
	opt := s3.PutOptions{ContentType: contentType, LockMode: s.LockMode, IfNoneMatch: createOnly}
	if s.RetainDays > 0 {
		opt.RetainUntil = time.Now().Add(time.Duration(s.RetainDays) * 24 * time.Hour)
	}
	return s.Client.Put(s.full(key), data, opt)
}

func (s *S3) Put(key string, data []byte, contentType string) error {
	return s.put(key, data, contentType, false)
}

func (s *S3) Create(key string, data []byte, contentType string) error {
	err := s.put(key, data, contentType, true)
	if !errors.Is(err, s3.ErrPreconditionFailed) {
		return err
	}
	return sameOrExists(s, key, data)
}

// sameOrExists resolves a create conflict: identical content means an earlier
// attempt of this same write landed.
func sameOrExists(s Sink, key string, data []byte) error {
	cur, err := s.Get(key)
	if err != nil {
		return fmt.Errorf("%w: %s (and reading it back failed: %v)", ErrExists, key, err)
	}
	if bytes.Equal(cur, data) {
		return nil
	}
	return fmt.Errorf("%w: %s", ErrExists, key)
}

func (s *S3) Get(key string) ([]byte, error) {
	b, err := s.Client.Get(s.full(key))
	if errors.Is(err, s3.ErrNotFound) {
		return nil, ErrNotFound
	}
	return b, err
}

func (s *S3) List(prefix string) ([]Object, error) {
	vs, err := s.Client.ListVersions(s.full(prefix))
	if err != nil {
		return nil, err
	}
	out := make([]Object, 0, len(vs))
	for _, v := range vs {
		k := v.Key
		if s.Prefix != "" {
			k = strings.TrimPrefix(k, s.Prefix+"/")
		}
		out = append(out, Object{Key: k, Versions: v.Versions, Deleted: v.Deleted})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

func (s *S3) String() string { return "s3://" + s.Client.Bucket + "/" + s.Prefix }

// Dir stores objects on the local filesystem. Records written here are NOT
// immutable; use it for local testing and demos only.
type Dir struct{ Root string }

func (d *Dir) path(key string) string {
	return filepath.Join(d.Root, filepath.FromSlash(path.Clean("/"+key)))
}

func (d *Dir) Put(key string, data []byte, _ string) error {
	p := d.path(key)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	return os.WriteFile(p, data, 0o644)
}

func (d *Dir) Create(key string, data []byte, _ string) error {
	p := d.path(key)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if errors.Is(err, fs.ErrExist) {
		return sameOrExists(d, key, data)
	}
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func (d *Dir) Get(key string) ([]byte, error) {
	b, err := os.ReadFile(d.path(key))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNotFound
	}
	return b, err
}

func (d *Dir) List(prefix string) ([]Object, error) {
	// Match on slash-separated keys, like S3 prefixes, so "records/acme/infra/"
	// doesn't also match "records/acme/infra2/". A directory keeps no history,
	// so every object has one version.
	var out []Object
	err := filepath.WalkDir(d.Root, func(p string, e fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		if e.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(d.Root, p)
		key := filepath.ToSlash(rel)
		if strings.HasPrefix(key, prefix) {
			out = append(out, Object{Key: key, Versions: 1})
		}
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, err
}

func (d *Dir) String() string { return "file://" + d.Root }
