package ngap

import (
	"bytes"
	"encoding/gob"
	"errors"
	"fmt"
)

func HandleNGAP(buf []byte) (err error) {

	msgType := int(buf[0])

	switch msgType {
	case NGSetupRequest:
		handleNGSetupRequest(buf[1:])
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

func handleNGSetupRequest(buf []byte) {
	var msg NGSetupRequestMsg
	decodeMsg(buf, &msg)
	fmt.Println("Decoded Setup request")
}

// Generic msg decoder
func decodeMsg[T any](buf []byte, msgPtr *T) {
	reader := bytes.NewReader(buf)
	dec := gob.NewDecoder(reader)
	if err := dec.Decode(&msgPtr); err != nil {
		panic(err)
	}
}
