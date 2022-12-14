package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"flag"
	"io"
	"log"

	"github.com/AlecAivazis/survey/v2"
	"github.com/google/tink/go/aead/subtle"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/streamingaead"
	"github.com/google/tink/go/subtle/random"
	"github.com/google/tink/go/tink"
	"github.com/pkg/errors"
)

var (
	masterKey = flag.String("master-key", "none", "none, random, prompt")
	binaryEnc = flag.Bool("binary", false, "Encode the key as bytes rather than JSON")
)

func main() {
	flag.Parse()
	if err := realMain(); err != nil {
		log.Fatalf("%+v\n", err)
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
	data := "there is no place like 127.0.0.1"

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

// NOTE: there is a tink.AEAD implementation
// that uses HashiCorp's vault transit engine,
// but we're not going to play with vault here.
func newMasterKey() (tink.AEAD, error) {
	var buf []byte
	switch *masterKey {
	case "":
		return nil, errors.New("blank master key")
	case "none":
		log.Println("Not using a master key")
		return noopAEAD{}, nil
	case "random":
		log.Println("Using random master key")
		buf = random.GetRandomBytes(32)
	case "prompt":
		var password string
		// survey has a password prompt, but it's not necessary here
		prompt := &survey.Input{Message: "Enter password"}
		if err := survey.AskOne(prompt, &password); err != nil {
			return nil, errors.Wrap(err, "newMasterKey.prompt")
		}
		if password == "" {
			return nil, errors.New("blank password")
		}
		buf = []byte(password)
	default:
		log.Println("Using given master key")
		buf = []byte(*masterKey)
	}
	if len(buf) != 32 {
		sum := sha256.Sum256(buf)
		buf = sum[:]
	}
	key, err := subtle.NewAESGCMSIV(buf)
	if err != nil {
		return nil, errors.Wrap(err, "newMasterKey")
	}
	return key, nil
}

func newStreamingKey() (*keyset.Handle, error) {
	// AES128_GCM_HKDF_1MB key type is recommended by tink docs for file use-cases.
	// Ref: https://developers.google.com/tink/encrypt-large-files-or-data-streams
	key, err := keyset.NewHandle(streamingaead.AES128GCMHKDF1MBKeyTemplate())
	if err != nil {
		return nil, errors.Wrap(err, "newStreamingKey")
	}
	return key, nil
}

func encodeStreamingKey(key *keyset.Handle, masterKey tink.AEAD) (string, error) {
	var buf bytes.Buffer
	var w keyset.Writer
	if *binaryEnc {
		w = keyset.NewBinaryWriter(&buf)
	} else {
		w = keyset.NewJSONWriter(&buf)
	}
	if err := key.Write(w, masterKey); err != nil {
		return "", errors.Wrap(err, "encodeStreamingKey")
	}
	if *binaryEnc {
		return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
	}
	return buf.String(), nil
}

func decodeStreamingKey(encoded string, masterKey tink.AEAD) (*keyset.Handle, error) {
	var r keyset.Reader
	if *binaryEnc {
		buf, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, errors.Wrap(err, "decodeStreamingKey.Decode")
		}
		r = keyset.NewBinaryReader(bytes.NewReader(buf))
	} else {
		r = keyset.NewJSONReader(bytes.NewReader([]byte(encoded)))
	}
	key, err := keyset.Read(r, masterKey)
	if err != nil {
		return nil, errors.Wrap(err, "decodeStreamingKey.Read")
	}
	return key, nil
}

func encrypt(key *keyset.Handle, plainText io.Reader, cipherText io.Writer) error {
	cipher, err := streamingaead.New(key)
	if err != nil {
		return errors.Wrap(err, "encrypt.NewStreamingAEAD")
	}
	writer, err := cipher.NewEncryptingWriter(cipherText, nil)
	if err != nil {
		return errors.Wrap(err, "encrypt.NewEncryptingWriter")
	}
	_, err = io.Copy(writer, plainText)
	if err != nil {
		return errors.Wrap(err, "encrypt.Copy")
	}
	err = writer.Close()
	if err != nil {
		return errors.Wrap(err, "encrypt.Close")
	}
	return nil
}

func decrypt(key *keyset.Handle, cipherText io.Reader, plainText io.Writer) error {
	cipher, err := streamingaead.New(key)
	if err != nil {
		return errors.Wrap(err, "decrypt.NewStreamingAEAD")
	}
	reader, err := cipher.NewDecryptingReader(cipherText, nil)
	if err != nil {
		return errors.Wrap(err, "decrypt.NewDecryptingReader")
	}
	_, err = io.Copy(plainText, reader)
	if err != nil {
		return errors.Wrap(err, "decrypt.Copy")
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
