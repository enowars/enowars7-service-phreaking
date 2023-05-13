package main

import (
	"bufio"
	"bytes"
	"encoding/gob"
	"fmt"
	"net"
	"strings"
)

type NGSetupRequestMsg struct {
	GRANid int32
	Tac    int32
	Plmn   int32
}

func handleConnection(c net.Conn) {
	fmt.Printf("Serving %s\n", c.RemoteAddr().String())
	for {
		netData, err := bufio.NewReader(c).ReadString('\n')
		if err != nil {
			fmt.Println(err)
			return
		}

		temp := strings.TrimSpace(string(netData))
		if temp == "STOP" {
			break
		}

		if temp == "START" {
			msg := NGSetupRequestMsg{1, 2, 3}

			var b bytes.Buffer
			b.WriteByte(0x00)
			e := gob.NewEncoder(&b)
			if err := e.Encode(msg); err != nil {
				panic(err)
			}
			b.WriteByte(0x99)

			fmt.Println("Encoded Struct ", b)

			c.Write(b.Bytes())
		}

	}
	c.Close()
}

func main() {
	l, err := net.Listen("tcp4", ":3000")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer l.Close()

	for {
		c, err := l.Accept()
		if err != nil {
			fmt.Println(err)
			return
		}
		go handleConnection(c)
	}
}
