package ngap

import (
	"bytes"
	"encoding/gob"
	"errors"
)

var (
	errDecode = errors.New("cannot decode message")
)

func HandleNGAP(buf []byte) (err error) {

	msgType := msgType(buf[0])

	switch msgType {
	case NGSetupRequest:
		err := handleNGSetupRequest(buf[1:])
		if err != nil {
			return err
		}

	case InitUERegRequest:
		handleInitUERegRequest()
	case NASIdResponse:
		handleNASIdResponse()
	case NASAuthResponse:
		handleNASAuthResponse()
	case NASSecurityModeComplete:
		handleNASSecurityModeComplete()
	case UECapInfoIndication:
		handleUECapInfoIndication()
	case InitialContextSetupResponse:
		handleInitialContextSetupResponse()
	case RegisterComplete:
		handleRegisterComplete()
	case PDUSessionResourceSetupRequest:
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
	var msg NGSetupRequestMsg
	err := DecodeMsg(buf, &msg)
	if err != nil {
		return errDecode
	}
	return nil
}

// Generic message decoder
func DecodeMsg[T any](buf []byte, msgPtr *T) error {
	reader := bytes.NewReader(buf)
	dec := gob.NewDecoder(reader)
	return dec.Decode(&msgPtr)
}
