// Package sink abstracts where evidence records are stored: an S3 bucket
// (production, with Object Lock) or a local directory (testing).
package sink

import (
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

// ErrNotFound is returned by Get for a missing key.
var ErrNotFound = errors.New("sink: not found")

// Sink stores evidence objects.
type Sink interface {
	Put(key string, data []byte, contentType string) error
	Get(key string) ([]byte, error)
	List(prefix string) ([]string, error)
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

func (s *S3) Put(key string, data []byte, contentType string) error {
	opt := s3.PutOptions{ContentType: contentType, LockMode: s.LockMode}
	if s.RetainDays > 0 {
		opt.RetainUntil = time.Now().Add(time.Duration(s.RetainDays) * 24 * time.Hour)
	}
	return s.Client.Put(s.full(key), data, opt)
}

func (s *S3) Get(key string) ([]byte, error) {
	b, err := s.Client.Get(s.full(key))
	if errors.Is(err, s3.ErrNotFound) {
		return nil, ErrNotFound
	}
	return b, err
}

func (s *S3) List(prefix string) ([]string, error) {
	keys, err := s.Client.List(s.full(prefix))
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		if s.Prefix != "" {
			k = strings.TrimPrefix(k, s.Prefix+"/")
		}
		out = append(out, k)
	}
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

func (d *Dir) Get(key string) ([]byte, error) {
	b, err := os.ReadFile(d.path(key))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNotFound
	}
	return b, err
}

func (d *Dir) List(prefix string) ([]string, error) {
	// Match on slash-separated keys, like S3 prefixes, so "records/acme/infra/"
	// doesn't also match "records/acme/infra2/".
	var out []string
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
			out = append(out, key)
		}
		return nil
	})
	sort.Strings(out)
	return out, err
}

func (d *Dir) String() string { return "file://" + d.Root }
