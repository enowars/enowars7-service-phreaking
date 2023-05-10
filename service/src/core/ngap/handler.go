package ngap

import (
	"errors"
	"phreaking/core/ngap/msgTypes"
)

func handler(buf []byte) (err error) {

	msgType := int(buf[0])

	// TODO: check buffer length according to message type

	switch msgType {
	case msgTypes.NGSetupRequest:
		handleNGSetupRequest()
	case msgTypes.InitUERegRequest:
		handleInitUERegRequest()
	case msgTypes.NASIdResponse:
		handleNASIdResponse()
	case msgTypes.NASAuthResponse:
		handleNASAuthResponse()
	case msgTypes.NASSecurityModeComplete:
		handleNASSecurityModeComplete()
	case msgTypes.UECapInfoIndication:
		handleUECapInfoIndication()
	case msgTypes.InitialContextSetupResponse:
		handleInitialContextSetupResponse()
	case msgTypes.RegisterComplete:
		handleRegisterComplete()
	case msgTypes.PDUSessionResourceSetupRequest:
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

func handleNGSetupRequest() {
	panic("unimplemented")
}
