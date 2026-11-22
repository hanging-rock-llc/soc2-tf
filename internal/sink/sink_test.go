package sink

import "testing"

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
	if len(got) != 1 || got[0] != "records/acme/infra/a.json" {
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
