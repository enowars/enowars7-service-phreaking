package ngap

import (
	"log"
	"net"
)

func SendMsg(conn net.Conn, msg []byte) (err error) {
	n, err := conn.Write(msg)
	if err != nil {
		log.Printf("write failed: %v", err)
		return err
	}
	log.Printf("write: %d", n)
	return
}
