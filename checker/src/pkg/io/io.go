package io

import (
	"errors"
	"net"
)

func SendMsg(conn net.Conn, msg []byte) (err error) {
	msgLen := uint16(len(msg))
	buf := make([]byte, 2)
	buf[0] = uint8(msgLen >> 8)
	buf[1] = uint8(msgLen & 0xff)
	_, err = conn.Write(buf)
	if err != nil {
		return err
	}
	_, err = conn.Write(msg)
	if err != nil {
		return err
	}
	return nil
}

func RecvMsg(conn net.Conn) ([]byte, error) {
	buf := make([]byte, 2)

	_, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}

	msgLen := uint16(buf[1]) | uint16(buf[0])<<8
	if msgLen < 1 {
		return nil, errors.New("msg length of buffer is zero or negative")
	}
	buf = make([]byte, msgLen)
	_, err = conn.Read(buf)
	return buf, err

}
