package ngap

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHandleNGAP(t *testing.T) {
	buf := make([]byte, 8)
	err := HandleNGAP(buf)
	assert.Error(t, err)

	msg := NGSetupRequestMsg{1, 2, 3}
	buf, err = EncodeMsg(NGSetupRequest, &msg)
	assert.Nil(t, err)

	err = HandleNGAP(buf)
	assert.Nil(t, err)
}
