package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"phreaking/internal/io"
	"phreaking/pkg/ngap"
)

var coreConn *net.TCPConn

func handleUeConnection(ueConn net.Conn) {
	defer ueConn.Close()

	for {
		// msgType := ngap.MsgType(buf[0])
		reply, err := io.RecvMsg(ueConn)
		if err != nil {
			fmt.Printf("Error reading: %#v\n", err)
			return
		}

		fmt.Println("=============================")
		fmt.Printf("FROM UE: (NASRegRequest)\n %s\n", reply)

		initUeMsg := ngap.InitUEMessageMsg{NasPdu: reply, RanUeNgapId: 1}
		buf, _ := ngap.EncodeMsg(ngap.InitUEMessage, &initUeMsg)

		fmt.Println("=============================")
		fmt.Printf("TO CORE: (InitUEMessage + NASRegRequest)\n %s\n", buf)
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

		fmt.Println("=============================")
		fmt.Printf("FROM CORE: (DownNASTrans + NASAuthRequest)\n %s\n", reply)

		var down ngap.DownNASTransMsg
		err = ngap.DecodeMsg(reply[1:], &down)
		if err != nil {
			fmt.Println("cannot decode")
			return
		}

		fmt.Println("=============================")
		fmt.Printf("TO UE: (NASAuthRequest)\n %s\n", down.NasPdu)
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

		fmt.Println("=============================")
		fmt.Printf("FROM UE: (NASAuthRes)\n %s\n", reply)

		amfUeNgapId := down.AmfUeNgapId

		// AuthRes
		up := ngap.UpNASTransMsg{NasPdu: reply, RanUeNgapId: 1, AmfUeNgapId: amfUeNgapId}
		buf, _ = ngap.EncodeMsg(ngap.UpNASTrans, &up)

		err = io.SendMsg(coreConn, buf)
		if err != nil {
			fmt.Printf("Error sending: %#v\n", err)
			return
		}

		fmt.Println("=============================")
		fmt.Printf("TO CORE: (UpNASTrans + NASAuthRes)\n %s\n", buf)

		// SecModeCmd
		reply, err = io.RecvMsg(coreConn)
		if err != nil {
			fmt.Printf("Error reading: %#v\n", err)
			return
		}

		fmt.Println("=============================")
		fmt.Printf("FROM CORE: (DownNASTrans + NASSecurityModeCommand)\n %s\n", reply)

		down = ngap.DownNASTransMsg{}

		err = ngap.DecodeMsg(reply[1:], &down)
		if err != nil {
			fmt.Println("cannot decode")
			return
		}

		fmt.Println("=============================")
		fmt.Printf("TO UE: (NASSecurityModeCommand)\n %s\n", down.NasPdu)
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
		fmt.Println("=============================")
		fmt.Printf("FROM UE: (LocationUpdate)\n %s\n", reply)

		up = ngap.UpNASTransMsg{NasPdu: reply, RanUeNgapId: 1, AmfUeNgapId: amfUeNgapId}
		buf, _ = ngap.EncodeMsg(ngap.UpNASTrans, &up)
		io.SendMsg(coreConn, buf)

		fmt.Println("=============================")
		fmt.Printf("TO CORE: (UpNASTrans + LocationUpdate)\n %s\n", buf)

		// PDUSessionReq
		reply, err = io.RecvMsg(ueConn)
		if err != nil {
			fmt.Printf("Error reading: %#v\n", err)
			return
		}
		fmt.Println("=============================")
		fmt.Printf("FROM UE: (PDUSessionEstRequest)\n %s\n", reply)

		up = ngap.UpNASTransMsg{NasPdu: reply, RanUeNgapId: 1, AmfUeNgapId: amfUeNgapId}
		buf, _ = ngap.EncodeMsg(ngap.UpNASTrans, &up)
		err = io.SendMsg(coreConn, buf)
		if err != nil {
			fmt.Printf("Error sending: %#v\n", err)
			return
		}
		fmt.Println("=============================")
		fmt.Printf("TO CORE: (UpNASTrans + PDUSessionEstRequest)\n %s\n", buf)

		// PDUSessionAccept

		reply, err = io.RecvMsg(coreConn)
		if err != nil {
			fmt.Printf("Error reading: %#v\n", err)
			return
		}

		fmt.Println("=============================")
		fmt.Printf("FROM CORE: (DownNASTrans + PDUSessionEstResponse)\n %s\n", reply)

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

		fmt.Println("=============================")
		fmt.Printf("TO UE: (PDUSessionEstResponse)\n %s\n", down.NasPdu)

		// PDUReq

		reply, err = io.RecvMsg(ueConn)
		if err != nil {
			fmt.Printf("Error reading: %#v\n", err)
			return
		}

		fmt.Println("=============================")
		fmt.Printf("FROM UE: (PDUReq)\n %s\n", reply)

		up = ngap.UpNASTransMsg{NasPdu: reply, RanUeNgapId: 1, AmfUeNgapId: amfUeNgapId}
		buf, _ = ngap.EncodeMsg(ngap.UpNASTrans, &up)
		io.SendMsg(coreConn, buf)

		fmt.Println("=============================")
		fmt.Printf("TO CORE: (UpNASTrans + PDUReq)\n %s\n", buf)

		// PDURes

		reply, err = io.RecvMsg(coreConn)
		if err != nil {
			fmt.Printf("Error reading: %#v\n", err)
			return
		}

		fmt.Println("=============================")
		fmt.Printf("FROM CORE: (DownNASTrans + PDURes)\n %s\n", reply)

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

		fmt.Println("=============================")
		fmt.Printf("TO UE: (PDURes)\n %s\n", down.NasPdu)

		return
	}

}

func main() {
	fmt.Println("5Go gNB tool - your friendly fake basestation")
	fmt.Println("Enter 5Go CORE address: <IP:PORT>")
	reader := bufio.NewReader(os.Stdin)
	addr, err := reader.ReadString('\n')
	addr = addr[:len(addr)-1]
	if err != nil {
		fmt.Println(err)
		return
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

	fmt.Println("=============================")
	fmt.Printf("TO CORE: (NGSetupRequest)\n %s\n", buf)
	err = io.SendMsg(coreConn, buf)
	if err != nil {
		fmt.Println(err)
		return
	}

	buf, err = io.RecvMsg(coreConn)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("=============================")
	fmt.Printf("FROM CORE: (NGSetupResponse)\n %s\n", buf)

	fmt.Println("Enter 5Go UE address: <IP:PORT>")
	reader = bufio.NewReader(os.Stdin)
	addr, err = reader.ReadString('\n')
	addr = addr[:len(addr)-1]
	if err != nil {
		fmt.Println(err)
		return
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
}
