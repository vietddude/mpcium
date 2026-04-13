package storage

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"filippo.io/age"
	"github.com/dgraph-io/badger/v4"
	"github.com/fystack/mpcium-sdk/mpcore"
)

type KeyShareStorage interface {
	SaveKeyShare(record KeyShareRecord) error
	LoadKeyShare(walletID string, keyType string, cosignerID string) (KeyShareRecord, error)
	HasKeyShare(walletID string, keyType string, cosignerID string) (bool, error)
}

var (
	_ KeyShareStorage = (*ShareStore)(nil)
)

const shareNamespace = "cosigner_shares"

var ErrNotFound = errors.New("record not found")

type ShareStore struct {
	db         *badger.DB
	passphrase string
}

type KeyShareRecord struct {
	WalletID           string    `json:"wallet_id"`
	KeyID              string    `json:"key_id"`
	KeyType            string    `json:"key_type"`
	Protocol           string    `json:"protocol"`
	ECDSAPreparamsBlob []byte    `json:"ecdsa_preparams_blob,omitempty"`
	Network            string    `json:"network"`
	CosignerID         string    `json:"cosigner_id"`
	SessionID          string    `json:"session_id"`
	ParticipantIndex   uint16    `json:"participant_index"`
	Threshold          uint16    `json:"threshold"`
	Participants       []string  `json:"participants"`
	ShareBlob          []byte    `json:"share_blob"`
	CreatedAt          time.Time `json:"created_at"`
}

func NewShareStore(path string, passphrase string) (*ShareStore, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("storage path is required")
	}
	if strings.TrimSpace(passphrase) == "" {
		return nil, errors.New("age passphrase is required")
	}

	cleanPath := filepath.Clean(path)
	options := badger.DefaultOptions(cleanPath)
	options.Logger = nil
	db, err := badger.Open(options)
	if err != nil {
		return nil, fmt.Errorf("open badger DB: %w", err)
	}
	return &ShareStore{
		db:         db,
		passphrase: passphrase,
	}, nil
}

func (s *ShareStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *ShareStore) DB() *badger.DB {
	if s == nil {
		return nil
	}
	return s.db
}

func (s *ShareStore) SaveKeyShare(record KeyShareRecord) error {
	if strings.TrimSpace(record.WalletID) == "" {
		return errors.New("wallet ID is required")
	}
	if strings.TrimSpace(record.KeyType) == "" {
		return errors.New("key type is required")
	}
	if strings.TrimSpace(record.CosignerID) == "" {
		return errors.New("cosigner ID is required")
	}
	if len(record.ShareBlob) == 0 {
		return errors.New("share blob is required")
	}
	if record.CreatedAt.IsZero() {
		record.CreatedAt = time.Now().UTC()
	}
	return s.putJSON(shareKey(record.WalletID, record.KeyType, record.CosignerID), record)
}

func (s *ShareStore) LoadKeyShare(walletID string, keyType string, cosignerID string) (KeyShareRecord, error) {
	var record KeyShareRecord
	ok, err := s.getJSON(shareKey(walletID, keyType, cosignerID), &record)
	if err != nil {
		return KeyShareRecord{}, err
	}
	if !ok {
		return KeyShareRecord{}, ErrNotFound
	}
	return record, nil
}

func (s *ShareStore) HasKeyShare(walletID string, keyType string, cosignerID string) (bool, error) {
	_, err := s.LoadKeyShare(walletID, keyType, cosignerID)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	return false, err
}

func (s *ShareStore) putJSON(key string, value any) error {
	plaintext, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("encode %q: %w", key, err)
	}
	ciphertext, err := encryptBytes(s.passphrase, plaintext)
	if err != nil {
		return fmt.Errorf("encrypt %q: %w", key, err)
	}
	return s.db.Update(func(txn *badger.Txn) error {
		return txn.Set([]byte(key), ciphertext)
	})
}

func (s *ShareStore) getJSON(key string, out any) (bool, error) {
	var ciphertext []byte
	err := s.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(key))
		if errors.Is(err, badger.ErrKeyNotFound) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		return item.Value(func(value []byte) error {
			ciphertext = append(ciphertext, value...)
			return nil
		})
	})
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return false, nil
		}
		return false, err
	}
	plaintext, err := decryptBytes(s.passphrase, ciphertext)
	if err != nil {
		return false, fmt.Errorf("decrypt %q: %w", key, err)
	}
	if err := json.Unmarshal(plaintext, out); err != nil {
		return false, fmt.Errorf("decode %q: %w", key, err)
	}
	return true, nil
}

func shareKey(walletID string, keyType string, cosignerID string) string {
	return fmt.Sprintf("%s/%s/%s/%s", shareNamespace, walletID, mpcore.NormalizeKeyType(keyType), cosignerID)
}

func ShareRef(walletID string, keyType string, cosignerID string) string {
	return shareKey(walletID, keyType, cosignerID)
}

func encryptBytes(passphrase string, plaintext []byte) ([]byte, error) {
	recipient, err := age.NewScryptRecipient(passphrase)
	if err != nil {
		return nil, err
	}
	var buffer bytes.Buffer
	writer, err := age.Encrypt(&buffer, recipient)
	if err != nil {
		return nil, err
	}
	if _, err := writer.Write(plaintext); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func decryptBytes(passphrase string, ciphertext []byte) ([]byte, error) {
	identity, err := age.NewScryptIdentity(passphrase)
	if err != nil {
		return nil, err
	}
	reader, err := age.Decrypt(bytes.NewReader(ciphertext), identity)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(reader)
}
