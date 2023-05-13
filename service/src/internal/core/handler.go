package core

import (
	"errors"
	"phreaking/pkg/ngap"
)

var (
	errDecode = errors.New("cannot decode message")
)

func HandleNGAP(buf []byte) (err error) {

	msgType := ngap.MsgType(buf[0])

	switch msgType {
	case ngap.NGSetupRequest:
		err := handleNGSetupRequest(buf[1:])
		if err != nil {
			return err
		}

	case ngap.InitUERegRequest:
		handleInitUERegRequest()
	case ngap.NASIdResponse:
		handleNASIdResponse()
	case ngap.NASAuthResponse:
		handleNASAuthResponse()
	case ngap.NASSecurityModeComplete:
		handleNASSecurityModeComplete()
	case ngap.UECapInfoIndication:
		handleUECapInfoIndication()
	case ngap.InitialContextSetupResponse:
		handleInitialContextSetupResponse()
	case ngap.RegisterComplete:
		handleRegisterComplete()
	case ngap.PDUSessionResourceSetupRequest:
		handlePDUSessionResourceSetupRequest()
	default:
		return errors.New("invalid message type for core")
	}
	return nil
}

func handlePDUSessionResourceSetupRequest() {
	panic("unimplemented")
}

func handleRegisterComplete() {
	panic("unimplemented")
}

func handleInitialContextSetupResponse() {
	panic("unimplemented")
}

func handleUECapInfoIndication() {
	panic("unimplemented")
}

func handleNASSecurityModeComplete() {
	panic("unimplemented")
}

func handleNASAuthResponse() {
	panic("unimplemented")
}

func handleNASIdResponse() {
	panic("unimplemented")
}

func handleInitUERegRequest() {
	panic("unimplemented")
}

func handleNGSetupRequest(buf []byte) error {
	var msg ngap.NGSetupRequestMsg
	err := ngap.DecodeMsg(buf, &msg)
	if err != nil {
		return errDecode
	}
	return nil
}
