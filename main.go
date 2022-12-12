package main

import (
	"bytes"
	"crypto/sha256"
	"flag"
	"fmt"
	"io"
	"log"

	"github.com/AlecAivazis/survey/v2"
	"github.com/google/tink/go/aead/subtle"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/streamingaead"
	"github.com/google/tink/go/subtle/random"
	"github.com/google/tink/go/testutil"
	"github.com/google/tink/go/tink"
)

var masterKey = flag.String("master-key", "dummy", "dummy, random, password")

func main() {
	flag.Parse()
	if err := realMain(); err != nil {
		log.Fatalln(err)
	}
}

func realMain() error {
	mk, err := newMasterKey()
	if err != nil {
		return err
	}
	sk1, err := newStreamingKey()
	if err != nil {
		return err
	}
	encoded, err := encodeStreamingKey(sk1, mk)
	if err != nil {
		return err
	}
	log.Println("Key:", encoded)
	sk2, err := decodeStreamingKey(encoded, mk)
	if err != nil {
		return err
	}

	data := "there is no place like home"

	var cipherText bytes.Buffer
	err = encrypt(sk1, bytes.NewReader([]byte(data)), &cipherText)
	if err != nil {
		return err
	}

	var plainText bytes.Buffer
	err = decrypt(sk2, bytes.NewReader(cipherText.Bytes()), &plainText)
	if err != nil {
		return err
	}

	log.Printf("Expected: %q\n", data)
	log.Printf("Actual:   %q\n", plainText.String())
	return nil
}

func newMasterKey() (tink.AEAD, error) {
	switch *masterKey {
	case "dummy":
		log.Println("Using dummy master key")
		return &testutil.DummyAEAD{Name: "dummy"}, nil
	case "random":
		log.Println("Using random master key")
		key, err := subtle.NewAESGCMSIV(random.GetRandomBytes(32))
		if err != nil {
			return nil, fmt.Errorf("newMasterKey: %w", err)
		}
		return key, nil
	default:
		var password string
		prompt := &survey.Input{Message: "Enter password"}
		if err := survey.AskOne(prompt, &password); err != nil {
			return nil, fmt.Errorf("newMasterKey.prompt: %w", err)
		}
		if password == "" {
			return nil, fmt.Errorf("blank password")
		}
		buf := sha256.Sum256([]byte(password))
		key, err := subtle.NewAESGCMSIV(buf[:])
		if err != nil {
			return nil, fmt.Errorf("newMasterKey: %w", err)
		}
		return key, nil
	}
}

func newStreamingKey() (*keyset.Handle, error) {
	key, err := keyset.NewHandle(streamingaead.AES128GCMHKDF1MBKeyTemplate())
	if err != nil {
		return nil, fmt.Errorf("newStreamingKey: %w", err)
	}
	return key, nil
}

func encodeStreamingKey(key *keyset.Handle, masterKey tink.AEAD) (string, error) {
	var buf bytes.Buffer
	w := keyset.NewJSONWriter(&buf)
	if err := key.Write(w, masterKey); err != nil {
		return "", fmt.Errorf("encodeStreamingKey: %w", err)
	}
	return buf.String(), nil
}

func decodeStreamingKey(encoded string, masterKey tink.AEAD) (*keyset.Handle, error) {
	r := keyset.NewJSONReader(bytes.NewReader([]byte(encoded)))
	key, err := keyset.Read(r, masterKey)
	if err != nil {
		return nil, fmt.Errorf("decodeStreamingKey: %w", err)
	}
	return key, nil
}

func encrypt(key *keyset.Handle, plainText io.Reader, cipherText io.Writer) error {
	encCipher, err := streamingaead.New(key)
	if err != nil {
		return fmt.Errorf("encrypt.NewStreamingAEAD: %w", err)
	}
	writer, err := encCipher.NewEncryptingWriter(cipherText, nil)
	if err != nil {
		return fmt.Errorf("encrypt.NewEncryptingWriter: %w", err)
	}
	_, err = io.Copy(writer, plainText)
	if err != nil {
		return fmt.Errorf("encrypt.Copy: %w", err)
	}
	if err = writer.Close(); err != nil {
		return fmt.Errorf("encrypt.Close: %w", err)
	}
	return nil
}

func decrypt(key *keyset.Handle, cipherText io.Reader, plainText io.Writer) error {
	decCipher, err := streamingaead.New(key)
	if err != nil {
		return fmt.Errorf("decrypt.NewStreamingAEAD: %w", err)
	}
	reader, err := decCipher.NewDecryptingReader(cipherText, nil)
	if err != nil {
		return fmt.Errorf("decrypt.NewDecryptingReader: %w", err)
	}
	_, err = io.Copy(plainText, reader)
	if err != nil {
		log.Fatalln("decrypt.Copy", err)
	}
	return nil
}
