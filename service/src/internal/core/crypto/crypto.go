package crypto

import (
	"crypto/aes"
	"crypto/sha256"
	"fmt"

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

func EncryptAES(input []byte) (res []byte) {
	c, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	// allocate space for ciphered data
	out := make([]byte, len(input))

	// encrypt
	c.Encrypt(out, []byte(input))
	return out

}

func ComputeHash(input []byte) (hash string) {
	h := sha256.New()
	h.Write(input)
	bs := h.Sum(nil)
	return string(bs)
}

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
