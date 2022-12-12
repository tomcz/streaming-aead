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
	"github.com/google/tink/go/tink"
)

var masterKey = flag.String("master-key", "none", "none, random, password")

func main() {
	flag.Parse()
	if err := realMain(); err != nil {
		log.Fatalln(err)
	}
}

func realMain() error {
	sk1, err := newStreamingKey()
	if err != nil {
		return err
	}

	// NOTE: There's no need to encode/decode the key before use.
	// Doing this here to document how to do that for future me.
	mk, err := newMasterKey()
	if err != nil {
		return err
	}
	encoded, err := encodeStreamingKey(sk1, mk)
	if err != nil {
		return err
	}
	sk2, err := decodeStreamingKey(encoded, mk)
	if err != nil {
		return err
	}
	// So, what does an encoded key look like?
	log.Println("Key:", encoded)

	// We're going to encrypt this with the generated key
	// and decrypt it with the decoded key, just to make
	// sure that we're handling the keys properly.
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

	// Well, did it work or not?
	log.Printf("Expected: %q\n", data)
	log.Printf("Actual:   %q\n", plainText.String())
	return nil
}

func newMasterKey() (tink.AEAD, error) {
	switch *masterKey {
	case "none":
		return noopAEAD{}, nil
	case "random":
		log.Println("Using random master key")
		key, err := subtle.NewAESGCMSIV(random.GetRandomBytes(32))
		if err != nil {
			return nil, fmt.Errorf("newMasterKey.random: %w", err)
		}
		return key, nil
	default:
		var password string
		// survey has a password prompt, but it's not necessary here
		prompt := &survey.Input{Message: "Enter password"}
		if err := survey.AskOne(prompt, &password); err != nil {
			return nil, fmt.Errorf("newMasterKey.prompt: %w", err)
		}
		if password == "" {
			return nil, fmt.Errorf("blank password")
		}
		// ensure we get a proper 256-bit AES key
		buf := sha256.Sum256([]byte(password))
		key, err := subtle.NewAESGCMSIV(buf[:])
		if err != nil {
			return nil, fmt.Errorf("newMasterKey.password: %w", err)
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

type noopAEAD struct{}

func (n noopAEAD) Encrypt(plaintext, _ []byte) ([]byte, error) {
	return plaintext, nil
}

func (n noopAEAD) Decrypt(ciphertext, _ []byte) ([]byte, error) {
	return ciphertext, nil
}
