package sink

import (
	"errors"
	"testing"
)

func TestDirListUsesKeyPrefixes(t *testing.T) {
	d := &Dir{Root: t.TempDir()}
	for _, k := range []string{"records/acme/infra/a.json", "records/acme/infra2/b.json", "index/x.json"} {
		if err := d.Put(k, []byte("{}"), ""); err != nil {
			t.Fatal(err)
		}
	}
	got, err := d.List("records/acme/infra/")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Key != "records/acme/infra/a.json" {
		t.Fatalf("List = %v", got)
	}
	if _, err := d.Get("missing.json"); err != ErrNotFound {
		t.Fatalf("Get missing: %v", err)
	}
	if err := d.Put("../../escape.json", []byte("x"), ""); err != nil {
		t.Fatal(err)
	}
	if got, _ := d.List("escape.json"); len(got) != 1 {
		t.Fatalf("path traversal should be confined to root, got %v", got)
	}
}

func TestDirCreateIsWriteOnce(t *testing.T) {
	d := &Dir{Root: t.TempDir()}
	if err := d.Create("records/r.json", []byte("one"), ""); err != nil {
		t.Fatal(err)
	}
	if err := d.Create("records/r.json", []byte("one"), ""); err != nil {
		t.Fatalf("re-creating with identical content (a retried write) should succeed: %v", err)
	}
	if err := d.Create("records/r.json", []byte("two"), ""); !errors.Is(err, ErrExists) {
		t.Fatalf("overwriting a record must fail with ErrExists, got %v", err)
	}
	if b, _ := d.Get("records/r.json"); string(b) != "one" {
		t.Fatalf("record changed to %q", b)
	}
}
