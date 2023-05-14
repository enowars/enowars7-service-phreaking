package core

import (
	"net"
	"phreaking/pkg/ngap"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHandleNGAP(t *testing.T) {
	_, w := net.Pipe()
	buf := make([]byte, 8)
	err := HandleNGAP(w, buf)
	assert.Error(t, err)

	w.Close()

	server, _ := net.Pipe()
	msg := ngap.NGSetupRequestMsg{GRANid: 1, Tac: 2, Plmn: 3}
	buf, err = ngap.EncodeMsg(ngap.NGSetupRequest, &msg)
	assert.Nil(t, err)

	go func() {
		err = HandleNGAP(w, buf)
		assert.Nil(t, err)
		server.Close()
	}()
}
