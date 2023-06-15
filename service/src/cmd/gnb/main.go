package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"phreaking/internal/io"
	"phreaking/pkg/ngap"
	"time"
)

var coreConn *net.TCPConn

func handleUeConnection(ueConn net.Conn) {
	timeout := time.NewTimer(time.Minute)
	defer func() {
		timeout.Stop()
		ueConn.Close()
	}()

	for {
		select {
		case <-timeout.C:
			log.Println("handleConnection ran for more than a minute.")
			return
		default:

			// msgType := ngap.MsgType(buf[0])
			reply, err := io.RecvMsg(ueConn)
			if err != nil {
				fmt.Printf("Error reading: %#v\n", err)
				return
			}

			fmt.Printf("RegReq: %s\n", reply)

			var reg ngap.NASRegRequestMsg
			err = ngap.DecodeMsg(reply[1:], &reg)
			if err != nil {
				fmt.Println("cannot decode")
				return
			}

			pdu, _ := ngap.EncodeMsg(ngap.NASRegRequest, &reg)

			initUeMsg := ngap.InitUEMessageMsg{NasPdu: pdu, RanUeNgapId: 1}
			buf, _ := ngap.EncodeMsg(ngap.InitUEMessage, &initUeMsg)

			err = io.SendMsg(coreConn, buf)
			if err != nil {
				fmt.Printf("Error sending: %#v\n", err)
				return
			}

			// AuthReq
			reply, err = io.RecvMsg(coreConn)
			if err != nil {
				fmt.Printf("Error reading: %#v\n", err)
				return
			}

			fmt.Printf("AuthReq: %s\n", reply)

			var down ngap.DownNASTransMsg
			err = ngap.DecodeMsg(reply[1:], &down)
			if err != nil {
				fmt.Println("cannot decode")
				return
			}

			err = io.SendMsg(ueConn, down.NasPdu)
			if err != nil {
				fmt.Printf("Error sending: %#v\n", err)
				return
			}

			reply, err = io.RecvMsg(ueConn)
			if err != nil {
				fmt.Printf("Error reading: %#v\n", err)
				return
			}

			fmt.Printf("AuthRes: %s\n", reply)

			// AuthRes
			up := ngap.UpNASTransMsg{NasPdu: reply, RanUeNgapId: 1, AmfUeNgapId: down.AmfUeNgapId}
			buf, _ = ngap.EncodeMsg(ngap.UpNASTrans, &up)

			err = io.SendMsg(coreConn, buf)
			if err != nil {
				fmt.Printf("Error sending: %#v\n", err)
				return
			}

			// SecModeCmd
			reply, err = io.RecvMsg(coreConn)
			if err != nil {
				fmt.Printf("Error reading: %#v\n", err)
				return
			}

			fmt.Printf("SecModeCmd: %s\n", reply)

			down = ngap.DownNASTransMsg{}

			err = ngap.DecodeMsg(reply[1:], &down)
			if err != nil {
				fmt.Println("cannot decode")
				return
			}

			err = io.SendMsg(ueConn, down.NasPdu)
			if err != nil {
				fmt.Printf("Error sending: %#v\n", err)
				return
			}

			// LocationUpdate
			reply, err = io.RecvMsg(ueConn)
			if err != nil {
				fmt.Printf("Error reading: %#v\n", err)
				return
			}

			fmt.Printf("LocationUpdate: %s\n", reply)
		}
	}

}

func main() {
	/*
		l, err := net.Listen("tcp4", ":9003")
		if err != nil {
			fmt.Println(err)
			return
		}
		defer l.Close()
	*/
	fmt.Println("Enter core address: <IP:PORT>")
	reader := bufio.NewReader(os.Stdin)
	addr, err := reader.ReadString('\n')
	addr = addr[:len(addr)-1]
	if err != nil {
		log.Fatal(err)
	}

	//coretcpAddr, err := net.ResolveTCPAddr("tcp", "localhost:3399")
	coretcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		fmt.Println(err)
		return
	}

	coreConn, err = net.DialTCP("tcp", nil, coretcpAddr)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer coreConn.Close()

	setup := ngap.NGSetupRequestMsg{GranId: 0, Tac: 0, Plmn: 0}
	buf, _ := ngap.EncodeMsg(ngap.NGSetupRequest, &setup)

	err = io.SendMsg(coreConn, buf)
	if err != nil {
		fmt.Println(err)
		return
	}

	_, err = io.RecvMsg(coreConn)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println("Enter UE address: <IP:PORT>")
	reader = bufio.NewReader(os.Stdin)
	addr, err = reader.ReadString('\n')
	addr = addr[:len(addr)-1]
	if err != nil {
		log.Fatal(err)
	}

	//uetcpAddr, err := net.ResolveTCPAddr("tcp", "phreaking_service-phreaking-ue-1:6060")
	uetcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		fmt.Println(err)
		return
	}

	ueConn, err := net.DialTCP("tcp", nil, uetcpAddr)
	if err != nil {
		fmt.Println(err)
		return
	}

	handleUeConnection(ueConn)

	/*
		for {
			c, err := l.Accept()
			if err != nil {
				fmt.Println(err)
				return
			}
			go handleUeConnection(c)
		}
	*/
}
