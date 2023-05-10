package ngap

import (
	"errors"
)

func handler(buf []byte) (err error) {

	msgType := int(buf[0])

	// TODO: check buffer length according to message type

	switch msgType {
	case 1:
		handleNGSetupRequest()
	case 2:
		handleNGSetupResponse()
	case 3:
		handleNGSetupFailure()
	case 4:
		handleInitUERegRequest()
	case 5:
		handleNASIdRequest()
	case 6:
		handleNASIdResponse()
	case 7:
		handleNASAuthRequest()
	case 8:
		handleNASAuthResponse()
	case 9:
		handleNASSecurityModeCommand()
	case 10:
		handleNASSecurityModeComplete()
	case 11:
		handleInitialContextSetupRequestRegAcc()
	case 12:
		handleUECapInfoIndication()
	case 13:
		handleInitialContextSetupResponse()
	case 14:
		handleRegisterComplete()
	case 15:
		handlePDUSessionResourceSetupRequest()
	case 16:
		handlePDUSessionResourceSetupResponse()
	case 17:
		handlePDUSessionResourceReleaseCommand()
	default:
		return errors.New("invalid message type")
	}
	return nil
}

func handlePDUSessionResourceReleaseCommand() {
	panic("unimplemented")
}

func handlePDUSessionResourceSetupResponse() {
	panic("unimplemented")
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

func handleInitialContextSetupRequestRegAcc() {
	panic("unimplemented")
}

func handleNASSecurityModeComplete() {
	panic("unimplemented")
}

func handleNASSecurityModeCommand() {
	panic("unimplemented")
}

func handleNASAuthResponse() {
	panic("unimplemented")
}

func handleNASAuthRequest() {
	panic("unimplemented")
}

func handleNASIdResponse() {
	panic("unimplemented")
}

func handleNASIdRequest() {
	panic("unimplemented")
}

func handleInitUERegRequest() {
	panic("unimplemented")
}

func handleNGSetupFailure() {
	panic("unimplemented")
}

func handleNGSetupResponse() {
	panic("unimplemented")
}

func handleNGSetupRequest() {
	panic("unimplemented")
}
