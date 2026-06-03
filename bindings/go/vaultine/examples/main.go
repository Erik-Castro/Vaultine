package main

import (
	"fmt"
	"log"

	"github.com/anomalyco/vaultine"
)

func main() {
	v, err := vaultine.New(":memory:", nil)
	if err != nil {
		log.Fatalf("New: %v", err)
	}
	defer v.Destroy()

	// User registration & auth
	if err := v.UserRegister("alice", "p@ss"); err != nil {
		log.Fatalf("Register: %v", err)
	}

	ok, err := v.UserAuthenticate("alice", "p@ss")
	if err != nil {
		log.Fatalf("Auth: %v", err)
	}
	fmt.Printf("alice authenticated: %v\n", ok)

	// Store a secret
	if err := v.SecretStore("alice", []byte("my-secret-key"), nil, "k1", "test key"); err != nil {
		log.Fatalf("Store: %v", err)
	}

	// Retrieve it
	priv, pub, err := v.SecretGet("alice", "k1", 4096)
	if err != nil {
		log.Fatalf("Get: %v", err)
	}
	fmt.Printf("got secret: %d bytes (pub: %v)\n", len(priv), pub != nil)

	// List secrets
	if err := v.SecretList("alice", func(e vaultine.SecretEntry) {
		desc := ""
		if e.Description != nil {
			desc = *e.Description
		}
		fmt.Printf("  - %s (desc: %q)\n", e.Name, desc)
	}); err != nil {
		log.Fatalf("List: %v", err)
	}

	// KEK rotation
	if err := v.KEKRotate("alice"); err != nil {
		log.Fatalf("Rotate: %v", err)
	}

	// DB version & export
	ver, _ := v.DBVersion()
	fmt.Printf("db schema version: %d\n", ver)

	meta, _ := v.Export(vaultine.ExportJSON, false)
	fmt.Printf("metadata:\n%s\n", meta)

	fmt.Println("done")
}
