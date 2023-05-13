package core

import (
	"phreaking/pkg/ngap"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHandleNGAP(t *testing.T) {
	buf := make([]byte, 8)
	err := HandleNGAP(buf)
	assert.Error(t, err)

	msg := ngap.NGSetupRequestMsg{GRANid: 1, Tac: 2, Plmn: 3}
	buf, err = ngap.EncodeMsg(ngap.NGSetupRequest, &msg)
	assert.Nil(t, err)

	err = HandleNGAP(buf)
	assert.Nil(t, err)
}
