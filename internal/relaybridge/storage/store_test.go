package storage

import (
	"bytes"
	"errors"
	"path/filepath"
	"testing"

	"github.com/dgraph-io/badger/v4"
)

func TestKeyShareRoundTrip(t *testing.T) {
	store, err := NewShareStore(filepath.Join(t.TempDir(), "badger"), "secret")
	if err != nil {
		t.Fatalf("new share store: %v", err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			t.Fatalf("close store: %v", err)
		}
	}()

	record := KeyShareRecord{
		WalletID:   "wallet-1",
		KeyType:    "eddsa",
		Protocol:   "eddsa",
		CosignerID: "cosigner-1",
		SessionID:  "wallet-1:eddsa:keygen",
		ShareBlob:  []byte("share-blob"),
	}
	if err := store.SaveKeyShare(record); err != nil {
		t.Fatalf("save key share: %v", err)
	}

	loaded, err := store.LoadKeyShare("wallet-1", "eddsa", "cosigner-1")
	if err != nil {
		t.Fatalf("load key share: %v", err)
	}
	if string(loaded.ShareBlob) != "share-blob" {
		t.Fatalf("unexpected share blob: %q", string(loaded.ShareBlob))
	}
}

func TestWrongPassphraseFailsDecrypt(t *testing.T) {
	root := filepath.Join(t.TempDir(), "badger")
	store, err := NewShareStore(root, "correct")
	if err != nil {
		t.Fatalf("new share store: %v", err)
	}
	if err := store.SaveKeyShare(KeyShareRecord{
		WalletID:   "wallet-1",
		KeyType:    "eddsa",
		Protocol:   "eddsa",
		CosignerID: "cosigner-1",
		SessionID:  "wallet-1:eddsa:keygen",
		ShareBlob:  []byte("share-blob"),
	}); err != nil {
		t.Fatalf("save key share: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close initial store: %v", err)
	}

	reopened, err := NewShareStore(root, "wrong")
	if err != nil {
		t.Fatalf("reopen share store: %v", err)
	}
	defer func() {
		if err := reopened.Close(); err != nil {
			t.Fatalf("close reopened store: %v", err)
		}
	}()

	_, err = reopened.LoadKeyShare("wallet-1", "eddsa", "cosigner-1")
	if err == nil {
		t.Fatal("expected decrypt error")
	}
	if errors.Is(err, ErrNotFound) {
		t.Fatal("expected decrypt error, got not found")
	}
}

func TestShareCiphertextDoesNotContainPlaintext(t *testing.T) {
	store, err := NewShareStore(filepath.Join(t.TempDir(), "badger"), "secret")
	if err != nil {
		t.Fatalf("new share store: %v", err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			t.Fatalf("close store: %v", err)
		}
	}()

	if err := store.SaveKeyShare(KeyShareRecord{
		WalletID:   "wallet-1",
		KeyType:    "eddsa",
		Protocol:   "eddsa",
		CosignerID: "cosigner-1",
		SessionID:  "wallet-1:eddsa:keygen",
		ShareBlob:  []byte("share-blob"),
	}); err != nil {
		t.Fatalf("save key share: %v", err)
	}

	var rawValue []byte
	err = store.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(ShareRef("wallet-1", "eddsa", "cosigner-1")))
		if err != nil {
			return err
		}
		return item.Value(func(value []byte) error {
			rawValue = append(rawValue, value...)
			return nil
		})
	})
	if err != nil {
		t.Fatalf("read raw value: %v", err)
	}
	if bytes.Contains(rawValue, []byte("share-blob")) {
		t.Fatal("expected ciphertext not to contain plaintext")
	}
}
