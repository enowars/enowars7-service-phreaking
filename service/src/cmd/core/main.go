package main

import (
	"fmt"
	"net"
	"phreaking/internal/core"
)

func main() {
	l, err := net.Listen("tcp4", ":3399")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer l.Close()

	// 0x00ff10 = MCC 001, MNC 01
	amf := core.Amf{AmfName: "CORE", GuamPlmn: 0x00ff10, AmfRegionId: 1, AmfSetId: 1, AmfPtr: 0, AmfCap: 255}

	for {
		c, err := l.Accept()
		if err != nil {
			fmt.Println(err)
			return
		}
		go amf.HandleConnection(c)
	}
}
