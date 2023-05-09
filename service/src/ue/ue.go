package ue

import (
	"fmt"
	"log"
	"net"
	"time"
)

func Ue() {
	// listen to incoming udp packets
	udpServer, err := net.ListenPacket("udp", ":3000")
	if err != nil {
		log.Fatal(err)
	}
	defer udpServer.Close()

	for {
		buf := make([]byte, 1024)
		_, addr, err := udpServer.ReadFrom(buf)
		if err != nil {
			continue
		}
		go response(udpServer, addr, buf)
	}

}

func response(udpServer net.PacketConn, addr net.Addr, buf []byte) {
	time := time.Now().Format(time.ANSIC)

	fmt.Printf("time received: %v. message: %v", time, string(buf))

	responseStr := fmt.Sprintf("time received: %v. Your message: %v", time, string(buf))

	udpServer.WriteTo([]byte(responseStr), addr)
}
