package vault

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
)

func TestAuthenticateWithKeyPair(t *testing.T) {
	svc := NewService()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	if err := svc.CreateUser("alice", KeyTypeEd25519, pub); err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}

	challenge := []byte("login challenge")
	sig := ed25519.Sign(priv, challenge)

	ok, err := svc.Authenticate("alice", challenge, sig)
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if !ok {
		t.Fatal("Authenticate() expected true")
	}
}

func TestAuthenticateFailsWithWrongSignature(t *testing.T) {
	svc := NewService()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	_, wrongPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	if err := svc.CreateUser("alice", KeyTypeEd25519, pub); err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}

	challenge := []byte("login challenge")
	sig := ed25519.Sign(wrongPriv, challenge)

	ok, err := svc.Authenticate("alice", challenge, sig)
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if ok {
		t.Fatal("Authenticate() expected false")
	}
}

func TestUserAndGroupSecretsAccessControl(t *testing.T) {
	svc := NewService()
	alicePub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	bobPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	mustCreateUser := func(id string, key []byte) {
		t.Helper()
		if err := svc.CreateUser(id, KeyTypeEd25519, key); err != nil {
			t.Fatalf("CreateUser(%s) error = %v", id, err)
		}
	}
	mustCreateUser("alice", alicePub)
	mustCreateUser("bob", bobPub)

	if err := svc.CreateGroup("devs"); err != nil {
		t.Fatalf("CreateGroup() error = %v", err)
	}
	if err := svc.AddUserToGroup("alice", "devs"); err != nil {
		t.Fatalf("AddUserToGroup() error = %v", err)
	}

	if err := svc.StoreSecretForUser("alice-note", "alice", []byte("alice-only")); err != nil {
		t.Fatalf("StoreSecretForUser() error = %v", err)
	}
	if err := svc.StoreSecretForGroup("devs-token", "devs", []byte("devs-shared")); err != nil {
		t.Fatalf("StoreSecretForGroup() error = %v", err)
	}

	gotUserSecret, err := svc.ReadSecret("alice-note", "alice")
	if err != nil {
		t.Fatalf("ReadSecret() error = %v", err)
	}
	if !bytes.Equal(gotUserSecret, []byte("alice-only")) {
		t.Fatalf("ReadSecret() user secret mismatch: got %q", gotUserSecret)
	}

	gotGroupSecret, err := svc.ReadSecret("devs-token", "alice")
	if err != nil {
		t.Fatalf("ReadSecret() error = %v", err)
	}
	if !bytes.Equal(gotGroupSecret, []byte("devs-shared")) {
		t.Fatalf("ReadSecret() group secret mismatch: got %q", gotGroupSecret)
	}

	if _, err := svc.ReadSecret("alice-note", "bob"); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("ReadSecret() expected ErrAccessDenied for user secret, got %v", err)
	}
	if _, err := svc.ReadSecret("devs-token", "bob"); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("ReadSecret() expected ErrAccessDenied for group secret, got %v", err)
	}
}

func TestUnknownKeyTypeRequiresVerifierRegistration(t *testing.T) {
	svc := NewService()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	if err := svc.CreateUser("alice", KeyTypeOQS, pub); err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}

	ok, err := svc.Authenticate("alice", []byte("challenge"), []byte("signature"))
	if !errors.Is(err, ErrVerifierNotFound) {
		t.Fatalf("Authenticate() expected ErrVerifierNotFound, got %v", err)
	}
	if ok {
		t.Fatal("Authenticate() expected false")
	}
}
