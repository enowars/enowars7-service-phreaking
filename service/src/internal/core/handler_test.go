package core

import (
	"net"
	"phreaking/pkg/ngap"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHandleNGAP(t *testing.T) {
	server, _ := net.Pipe()
	buf := make([]byte, 8)
	err := HandleNGAP(server, buf)
	assert.Error(t, err)

	server.Close()

	server, _ = net.Pipe()
	setupMsg := ngap.NGSetupRequestMsg{GranId: 1, Tac: 2, Plmn: 3}
	buf, err = ngap.EncodeMsg(ngap.NGSetupRequest, &setupMsg)
	assert.Nil(t, err)

	go func() {
		err = HandleNGAP(server, buf)
		assert.Nil(t, err)
		server.Close()
	}()

	server, _ = net.Pipe()
	regMsg := ngap.NASRegRequestMsg{SecHeader: 0,
		MobileId: ngap.MobileIdType{Mcc: 0, Mnc: 0, ProtecScheme: 0, HomeNetPki: 0, Msin: 0},
		SecCap:   ngap.SecCapType{EA: 0, IA: 0},
	}
	pdu, err := ngap.EncodeMsg(ngap.NGSetupRequest, &regMsg)
	assert.Nil(t, err)

	initUeMsg := ngap.InitUEMessageMsg{NasPdu: pdu, RanUeNgapId: 1}
	buf, err = ngap.EncodeMsg(ngap.InitUEMessage, &initUeMsg)

	go func() {
		err = HandleNGAP(server, buf)
		assert.Nil(t, err)
		server.Close()
	}()
}
