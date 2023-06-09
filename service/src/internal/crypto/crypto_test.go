package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCrypto(t *testing.T) {
	in := []byte("TESTTESTTSTSTSTT")
	enc := EncryptAES(in)
	dec := DecryptAES(enc)
	assert.Equal(t, string(in), string(dec))

}
