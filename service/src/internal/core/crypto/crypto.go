package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"log"

	"github.com/free5gc/nas/security"
)

var key = []byte("passphrasewhichneedstobe32bytes!")

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

/*
func DecryptAES(ct []byte) (res []byte) {
	c, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	pt := make([]byte, len(ct))
	c.Decrypt(pt, ct)

	//	s := string(pt[:])
	//	fmt.Println("DECRYPTED:", s)

	return pt
}

func EncryptAES(input []byte) (res []byte) {
	c, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	// allocate space for ciphered data
	out := make([]byte, len(input))

	// encrypt
	c.Encrypt(out, input)
	return out

}
*/
