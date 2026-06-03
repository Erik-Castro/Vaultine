package vaultine

import (
	"testing"
)

func newTestHandle(t *testing.T) *Vaultine {
	t.Helper()
	v, err := New(":memory:", nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return v
}

func TestNewDestroy(t *testing.T) {
	v, err := New(":memory:", nil)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	v.Destroy()
}

func TestUserRegisterAndAuth(t *testing.T) {
	v := newTestHandle(t)
	defer v.Destroy()

	err := v.UserRegister("alice", "p@ss")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	ok, err := v.UserAuthenticate("alice", "p@ss")
	if err != nil {
		t.Fatalf("Auth: %v", err)
	}
	if !ok {
		t.Fatal("expected valid auth")
	}

	ok, err = v.UserAuthenticate("alice", "wrong")
	if err != nil {
		t.Fatalf("Auth: %v", err)
	}
	if ok {
		t.Fatal("expected invalid auth")
	}
}

func TestSecretStoreGetDelete(t *testing.T) {
	v := newTestHandle(t)
	defer v.Destroy()
	v.UserRegister("alice", "p@ss")

	err := v.SecretStore("alice", []byte("my-key-data"), nil,
		"k1", "test key")
	if err != nil {
		t.Fatalf("Store: %v", err)
	}

	priv, pub, err := v.SecretGet("alice", "k1", 4096)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(priv) != "my-key-data" {
		t.Fatalf("got %q, want %q", string(priv), "my-key-data")
	}
	if pub != nil {
		t.Fatal("expected nil pub key")
	}

	err = v.SecretDelete("alice", "k1")
	if err != nil {
		t.Fatalf("Delete: %v", err)
	}

	_, _, err = v.SecretGet("alice", "k1", 4096)
	if err != ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestSecretList(t *testing.T) {
	v := newTestHandle(t)
	defer v.Destroy()
	v.UserRegister("alice", "p@ss")
	v.SecretStore("alice", []byte("data"), nil, "k1", "desc1")
	v.SecretStore("alice", []byte("data2"), nil, "k2", "")

	var names []string
	err := v.SecretList("alice", func(e SecretEntry) {
		names = append(names, e.Name)
	})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(names) != 2 {
		t.Fatalf("expected 2 secrets, got %d", len(names))
	}
}

func TestKEKRotate(t *testing.T) {
	v := newTestHandle(t)
	defer v.Destroy()
	v.UserRegister("alice", "p@ss")

	err := v.KEKRotate("alice")
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
}

func TestCacheStats(t *testing.T) {
	v := newTestHandle(t)
	defer v.Destroy()
	v.UserRegister("alice", "p@ss")

	cs, err := v.CacheStats()
	if err != nil {
		t.Fatalf("CacheStats: %v", err)
	}
	if cs == nil {
		t.Fatal("expected non-nil stats")
	}
}

func TestExport(t *testing.T) {
	v := newTestHandle(t)
	defer v.Destroy()
	v.UserRegister("alice", "p@ss")
	v.SecretStore("alice", []byte("data"), nil, "k1", "")

	jsonOut, err := v.Export(ExportJSON, false)
	if err != nil {
		t.Fatalf("Export JSON: %v", err)
	}
	if len(jsonOut) == 0 {
		t.Fatal("export returned empty")
	}

	csvOut, err := v.Export(ExportCSV, false)
	if err != nil {
		t.Fatalf("Export CSV: %v", err)
	}
	if len(csvOut) == 0 {
		t.Fatal("csv export empty")
	}
}

func TestDBVersion(t *testing.T) {
	v := newTestHandle(t)
	defer v.Destroy()

	ver, err := v.DBVersion()
	if err != nil {
		t.Fatalf("DBVersion: %v", err)
	}
	if ver < 1 {
		t.Fatalf("expected version >= 1, got %d", ver)
	}
}

func TestUserDelete(t *testing.T) {
	v := newTestHandle(t)
	defer v.Destroy()
	v.UserRegister("bob", "p@ss")
	err := v.UserDelete("bob", "p@ss")
	if err != nil {
		t.Fatalf("Delete user: %v", err)
	}
}

func TestUserChangePassword(t *testing.T) {
	v := newTestHandle(t)
	defer v.Destroy()
	v.UserRegister("carol", "p@ss")
	err := v.UserChangePassword("carol", "p@ss", "newp@ss")
	if err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}
	ok, _ := v.UserAuthenticate("carol", "newp@ss")
	if !ok {
		t.Fatal("expected new password to work")
	}
}

func TestErrorDisplay(t *testing.T) {
	if StatusOK.Error() != "ok" {
		t.Fatalf("unexpected StatusOK string")
	}
	if ErrAuth.Error() != "authentication failed" {
		t.Fatalf("unexpected ErrAuth string")
	}
}
