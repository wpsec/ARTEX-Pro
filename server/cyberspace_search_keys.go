package server

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
)

const cyberspaceKeySize = 32

func loadCyberspaceCipher(path string, create bool) (cipher.AEAD, error) {
	key, err := readCyberspaceKey(path)
	if errors.Is(err, os.ErrNotExist) && create {
		if err := createCyberspaceKey(path); err != nil && !errors.Is(err, os.ErrExist) {
			return nil, err
		}
		key, err = readCyberspaceKey(path)
	}
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	clear(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCMWithRandomNonce(block)
}

func readCyberspaceKey(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() != cyberspaceKeySize {
		return nil, fmt.Errorf("invalid cyberspace credential key file")
	}
	return os.ReadFile(path)
}

func createCyberspaceKey(path string) error {
	temp, err := os.CreateTemp(filepath.Dir(path), ".cyberspace-key-*")
	if err != nil {
		return err
	}
	defer func() {
		if err := os.Remove(temp.Name()); err != nil {
			log.Printf("[cyberspace-search] temporary wrapping key cleanup failed")
		}
	}()
	key := make([]byte, cyberspaceKeySize)
	defer clear(key)
	rand.Read(key)
	_, writeErr := temp.Write(key)
	syncErr := temp.Sync()
	if err := errors.Join(writeErr, syncErr, temp.Close()); err != nil {
		return err
	}
	// Publish only a complete key, without replacing a key created by another process.
	return os.Link(temp.Name(), path)
}

func sealCyberspaceValue(aead cipher.AEAD, scope, value string) string {
	return base64.RawStdEncoding.EncodeToString(aead.Seal(nil, nil, []byte(value), []byte(scope)))
}

func openCyberspaceValue(aead cipher.AEAD, scope, value string) (string, error) {
	if value == "" {
		return "", nil
	}
	data, err := base64.RawStdEncoding.DecodeString(value)
	if err != nil {
		return "", err
	}
	plain, err := aead.Open(nil, nil, data, []byte(scope))
	return string(plain), err
}

func (c *cyberspaceSearch) openCredentials(id string, config cyberspaceConfig) (key, account string, err error) {
	aead, err := loadCyberspaceCipher(c.keyPath, false)
	if err != nil {
		return "", "", err
	}
	key, err = openCyberspaceValue(aead, id+"/key", config.Key)
	if err != nil {
		return "", "", err
	}
	account, err = openCyberspaceValue(aead, id+"/account", config.Account)
	if err == nil && key == account {
		err = fmt.Errorf("provider account identifier matches its credential")
	}
	return key, account, err
}
