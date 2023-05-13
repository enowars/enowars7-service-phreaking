package ngap

import (
	"bytes"
	"encoding/gob"
)

func buildNGSetupResponse() {
	panic("unimplemented")
}

func buildNGSetupFailure() {
	panic("unimplemented")
}

func buildNASIdRequest() {
	panic("unimplemented")
}

func buildNASAuthRequest() {
	panic("unimplemented")
}

func buildNASSecurityModeCommand() {
	panic("unimplemented")
}

func buildInitialContextSetupRequestRegAccept() {
	panic("unimplemented")
}

func buildPDUSessionResourceReleaseCommand() {
	panic("unimplemented")
}

func buildPDUSessionResourceSetupResponse() {
	panic("unimplemented")
}

// Generic message encoder
func EncodeMsg[T any](t msgType, msgPtr *T) ([]byte, error) {
	var b bytes.Buffer
	b.WriteByte(byte(t))
	e := gob.NewEncoder(&b)
	err := e.Encode(&msgPtr)
	return b.Bytes(), err
}
