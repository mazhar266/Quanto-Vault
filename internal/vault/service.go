package vault

import (
	"crypto/ed25519"
	"errors"
	"sync"
)

const (
	KeyTypeEd25519 = "ed25519"
	KeyTypeOQS     = "oqs"
)

var (
	ErrEmptyID          = errors.New("id is required")
	ErrUserExists       = errors.New("user already exists")
	ErrGroupExists      = errors.New("group already exists")
	ErrSecretExists     = errors.New("secret already exists")
	ErrUserNotFound     = errors.New("user not found")
	ErrGroupNotFound    = errors.New("group not found")
	ErrSecretNotFound   = errors.New("secret not found")
	ErrAccessDenied     = errors.New("access denied")
	ErrInvalidPublicKey = errors.New("invalid public key")
	ErrVerifierNotFound = errors.New("key verifier not registered")
	ErrInvalidOwner     = errors.New("invalid secret owner")
	ErrInvalidAuthInput = errors.New("invalid authentication input")
)

type KeyVerifier interface {
	Verify(publicKey, message, signature []byte) bool
}

type ed25519Verifier struct{}

func (ed25519Verifier) Verify(publicKey, message, signature []byte) bool {
	return ed25519.Verify(ed25519.PublicKey(publicKey), message, signature)
}

type User struct {
	ID        string
	KeyType   string
	PublicKey []byte
}

type Group struct {
	ID      string
	Members map[string]struct{}
}

type SecretOwner string

const (
	OwnerUser  SecretOwner = "user"
	OwnerGroup SecretOwner = "group"
)

type Secret struct {
	ID      string
	Owner   SecretOwner
	OwnerID string
	Value   []byte
}

type Service struct {
	mu        sync.RWMutex
	users     map[string]User
	groups    map[string]Group
	secrets   map[string]Secret
	verifiers map[string]KeyVerifier
}

func NewService() *Service {
	return &Service{
		users:   make(map[string]User),
		groups:  make(map[string]Group),
		secrets: make(map[string]Secret),
		verifiers: map[string]KeyVerifier{
			KeyTypeEd25519: ed25519Verifier{},
		},
	}
}

func (s *Service) RegisterKeyVerifier(keyType string, verifier KeyVerifier) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.verifiers[keyType] = verifier
}

func (s *Service) CreateUser(id, keyType string, publicKey []byte) error {
	if id == "" {
		return ErrEmptyID
	}
	if len(publicKey) == 0 {
		return ErrInvalidPublicKey
	}
	if keyType == "" {
		keyType = KeyTypeEd25519
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.users[id]; exists {
		return ErrUserExists
	}

	s.users[id] = User{ID: id, KeyType: keyType, PublicKey: append([]byte(nil), publicKey...)}
	return nil
}

func (s *Service) CreateGroup(id string) error {
	if id == "" {
		return ErrEmptyID
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.groups[id]; exists {
		return ErrGroupExists
	}

	s.groups[id] = Group{ID: id, Members: map[string]struct{}{}}
	return nil
}

func (s *Service) AddUserToGroup(userID, groupID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.users[userID]; !exists {
		return ErrUserNotFound
	}
	group, exists := s.groups[groupID]
	if !exists {
		return ErrGroupNotFound
	}

	group.Members[userID] = struct{}{}
	s.groups[groupID] = group
	return nil
}

func (s *Service) Authenticate(userID string, challenge, signature []byte) (bool, error) {
	if len(challenge) == 0 || len(signature) == 0 {
		return false, ErrInvalidAuthInput
	}

	s.mu.RLock()
	user, exists := s.users[userID]
	if !exists {
		s.mu.RUnlock()
		return false, ErrUserNotFound
	}
	verifier, ok := s.verifiers[user.KeyType]
	s.mu.RUnlock()

	if !ok {
		return false, ErrVerifierNotFound
	}

	return verifier.Verify(user.PublicKey, challenge, signature), nil
}

func (s *Service) StoreSecretForUser(secretID, userID string, value []byte) error {
	return s.storeSecret(secretID, OwnerUser, userID, value)
}

func (s *Service) StoreSecretForGroup(secretID, groupID string, value []byte) error {
	return s.storeSecret(secretID, OwnerGroup, groupID, value)
}

func (s *Service) storeSecret(secretID string, owner SecretOwner, ownerID string, value []byte) error {
	if secretID == "" || ownerID == "" {
		return ErrEmptyID
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.secrets[secretID]; exists {
		return ErrSecretExists
	}

	switch owner {
	case OwnerUser:
		if _, exists := s.users[ownerID]; !exists {
			return ErrUserNotFound
		}
	case OwnerGroup:
		if _, exists := s.groups[ownerID]; !exists {
			return ErrGroupNotFound
		}
	default:
		return ErrInvalidOwner
	}

	s.secrets[secretID] = Secret{
		ID:      secretID,
		Owner:   owner,
		OwnerID: ownerID,
		Value:   append([]byte(nil), value...),
	}

	return nil
}

func (s *Service) ReadSecret(secretID, requesterUserID string) ([]byte, error) {
	s.mu.RLock()
	secret, exists := s.secrets[secretID]
	if !exists {
		s.mu.RUnlock()
		return nil, ErrSecretNotFound
	}

	switch secret.Owner {
	case OwnerUser:
		if secret.OwnerID != requesterUserID {
			s.mu.RUnlock()
			return nil, ErrAccessDenied
		}
	case OwnerGroup:
		group, exists := s.groups[secret.OwnerID]
		if !exists {
			s.mu.RUnlock()
			return nil, ErrGroupNotFound
		}
		if _, member := group.Members[requesterUserID]; !member {
			s.mu.RUnlock()
			return nil, ErrAccessDenied
		}
	default:
		s.mu.RUnlock()
		return nil, ErrInvalidOwner
	}

	value := append([]byte(nil), secret.Value...)
	s.mu.RUnlock()
	return value, nil
}
