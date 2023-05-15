package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"github.com/free5gc/nas/security"
)

// NIA1(ik [16]byte, countI uint32, bearer byte, direction uint32, msg []byte, length uint64)
// func genMac(m []byte, stream []uint32, blength int)

func NIA4(ik [16]byte, count uint32, bearer byte, direction uint32, msg []byte, length uint64) (mac []byte, err error) {
	h := sha256.New()
	h.Write(msg)
	bs := h.Sum(nil)
	return bs[0:4], nil
}

func PrintCrypto() {
	var ik [16]byte
	fmt.Println("Hello from crypto!")
	fmt.Println(security.NIA1(ik, 1, byte(0), 1, []byte("msg"), 3))
	fmt.Println(NIA4(ik, 1, byte(0), 1, []byte("msg"), 3))
}

func ComputeRes(inputRand []byte) (res []byte) {
	key := []byte("passphrasewhichneedstobe32bytes!")

	// generate a new aes cipher using our 32 byte long key
	c, err := aes.NewCipher(key)
	// if there are any errors, handle them
	if err != nil {
		fmt.Println(err)
	}

	// gcm or Galois/Counter Mode, is a mode of operation
	// for symmetric key cryptographic block ciphers
	// - https://en.wikipedia.org/wiki/Galois/Counter_Mode
	gcm, err := cipher.NewGCM(c)
	// if any error generating new GCM
	// handle them
	if err != nil {
		fmt.Println(err)
	}

	// creates a new byte array the size of the nonce
	// which must be passed to Seal
	nonce := make([]byte, gcm.NonceSize())
	// populates our nonce with a cryptographically secure
	// random sequence
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		fmt.Println(err)
	}

	// here we encrypt our text using the Seal function
	// Seal encrypts and authenticates plaintext, authenticates the
	// additional data and appends the result to dst, returning the updated
	// slice. The nonce must be NonceSize() bytes long and unique for all
	// time, for a given key.
	return gcm.Seal(nonce, nonce, inputRand, nil)
}

func ComputeHash(input []byte) (hash string) {
	h := sha256.New()
	h.Write(input)
	bs := h.Sum(nil)
	return string(bs)
}
