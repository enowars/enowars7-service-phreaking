package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"io"
	"log"
	"os"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/sha3"
)

var key = []byte(string(os.Getenv("SIM_KEY")))

func ComputeHash(input []byte) (hash string) {
	h := sha256.New()
	h.Write(input)
	bs := h.Sum(nil)
	return string(bs)
}

func EncryptAES(input []byte) (res []byte) {
	aesBlock, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println(err)
	}

	gcmInstance, err := cipher.NewGCM(aesBlock)
	if err != nil {
		fmt.Println(err)
	}
	nonce := make([]byte, gcmInstance.NonceSize())
	_, _ = io.ReadFull(rand.Reader, nonce)
	return gcmInstance.Seal(nonce, nonce, input, nil)
}

func DecryptAES(ct []byte) (res []byte) {
	aesBlock, err := aes.NewCipher(key)
	if err != nil {
		log.Fatalln(err)
	}
	gcmInstance, err := cipher.NewGCM(aesBlock)
	if err != nil {
		log.Fatalln(err)
	}
	nonceSize := gcmInstance.NonceSize()
	nonce, cipheredText := ct[:nonceSize], ct[nonceSize:]
	originalText, err := gcmInstance.Open(nil, nonce, cipheredText, nil)
	if err != nil {
		log.Fatalln(err)
	}
	return originalText
}

func CheckIntegrity(buf []byte, mac []byte) bool {
	dec := string(DecryptAES(mac))
	hash := ComputeHash(buf)
	return (dec == hash)
}

func IA0(msg []byte) (mac []byte) {
	h := sha256.New()
	h.Write(msg)
	return h.Sum(nil)
}

func IA1(msg []byte) (mac []byte) {
	hash := hmac.New(sha256.New, []byte(key))
	hash.Write(msg)
	return hash.Sum(nil)
}

func IA2(msg []byte) (mac []byte) {
	hash := hmac.New(sha512.New, []byte(key))
	hash.Write(msg)
	return hash.Sum(nil)
}

func IA3(msg []byte) (mac []byte) {
	hash := hmac.New(sha3.New256, []byte(key))
	hash.Write(msg)
	return hash.Sum(nil)
}

func IA4(msg []byte) (mac []byte) {
	hash, _ := blake2b.New256(key)
	hash.Write(msg)
	return hash.Sum(nil)
}

var IAalg = map[uint8]func([]byte) []byte{0: IA0, 1: IA1, 2: IA2, 3: IA3, 4: IA4}
