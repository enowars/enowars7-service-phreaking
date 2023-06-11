package io

import (
	"fmt"
	"log"
	"net"
)

func SendMsg(conn net.Conn, msg []byte) (err error) {
	msgLen := uint16(len(msg))
	buf := make([]byte, 2)
	buf[0] = uint8(msgLen >> 8)
	buf[1] = uint8(msgLen & 0xff)
	n, err := conn.Write(buf)
	if err != nil {
		log.Printf("write failed: %v", err)
		return err
	}
	log.Printf("write: %d", n)
	n, err = conn.Write(msg)
	if err != nil {
		log.Printf("write failed: %v", err)
		return err
	}
	log.Printf("write: %d", n)
	return nil
}

func RecvMsg(conn net.Conn) ([]byte, error) {
	buf := make([]byte, 2)

	_, err := conn.Read(buf)
	if err != nil {
		fmt.Printf("Error reading: %#v\n", err)
		conn.Close()
		return nil, err
	}

	msgLen := uint16(buf[1]) | uint16(buf[0])<<8
	buf = make([]byte, msgLen)
	_, err = conn.Read(buf)
	return buf, err

}
