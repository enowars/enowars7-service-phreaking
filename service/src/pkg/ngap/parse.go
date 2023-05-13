package ngap

import (
	"bytes"
	"encoding/gob"
)

// Generic message decoder
func DecodeMsg[T any](buf []byte, msgPtr *T) error {
	reader := bytes.NewReader(buf)
	dec := gob.NewDecoder(reader)
	return dec.Decode(&msgPtr)
}

// Generic message encoder
func EncodeMsg[T any](t MsgType, msgPtr *T) ([]byte, error) {
	var b bytes.Buffer
	b.WriteByte(byte(t))
	e := gob.NewEncoder(&b)
	err := e.Encode(&msgPtr)
	return b.Bytes(), err
}
