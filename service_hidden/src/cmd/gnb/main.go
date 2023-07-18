package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"phreaking/internal/io"
	"phreaking/pkg/nas"
	"phreaking/pkg/ngap"
	"phreaking/pkg/parser"
)

var coreConn *net.TCPConn

func handleUeConnection(ueConn net.Conn) {
	defer ueConn.Close()

	for {
		var gmm nas.GmmHeader

		reply, err := io.Recv(ueConn)
		if err != nil {
			fmt.Printf("Error reading: %#v\n", err)
			return
		}

		fmt.Printf("\nSuccessfully connected to UE\n\n")

		fmt.Println("=============================")
		fmt.Printf("FROM UE: (NASRegRequest)\n %s\n", reply)

		err = parser.DecodeMsg(reply, &gmm)
		if err != nil {
			fmt.Printf("Error decoding: %#v\n", err)
			return
		}

		var reg nas.NASRegRequestMsg
		err = parser.DecodeMsg(gmm.Message, &reg)
		if err != nil {
			fmt.Printf("Error decoding: %#v\n", err)
			return
		}

		//fmt.Printf("FROM UE: (NASRegRequest)\n %s\n", reg)

		newreg := nas.NASRegRequestMsg{MobileId: reg.MobileId}
		newreg.SecCap.EaCap = reg.SecCap.EaCap
		newreg.SecCap.IaCap = reg.SecCap.IaCap

		msg, err := parser.EncodeMsg(&newreg)
		if err != nil {
			fmt.Printf("Error encoding NASRegRequest: %#v\n", err)
			return
		}

		newgmm := nas.GmmHeader{}
		newgmm.MessageType = gmm.MessageType
		newgmm.Mac = gmm.Mac
		newgmm.Message = msg

		initUeMsg := ngap.InitUEMessageMsg{NasPdu: newgmm, RanUeNgapId: 1}
		buf, _ := parser.EncodeMsg(&initUeMsg)
		fmt.Println("=============================")
		fmt.Printf("TO CORE: (InitUEMessage + NASRegRequest)\n %s\n", buf)
		err = io.SendNgapMsg(coreConn, ngap.InitUEMessage, &initUeMsg)
		if err != nil {
			fmt.Printf("Error sending: %#v\n", err)
			return
		}

		// AuthReq
		reply, err = io.Recv(coreConn)
		if err != nil {
			fmt.Printf("Error reading: %#v\n", err)
			return
		}
		var ngapHeader ngap.NgapHeader
		err = parser.DecodeMsg(reply, &ngapHeader)
		if err != nil {
			fmt.Printf("Error decoding: %#v\n", err)
			return
		}

		fmt.Println("=============================")
		fmt.Printf("FROM CORE: (DownNASTrans + NASAuthRequest)\n %s\n", reply)

		var down ngap.DownNASTransMsg
		err = parser.DecodeMsg(ngapHeader.NgapPdu, &down)
		if err != nil {
			fmt.Println("cannot decode")
			return
		}

		buf, _ = parser.EncodeMsg(&down.NasPdu)
		fmt.Println("=============================")
		fmt.Printf("TO UE: (NASAuthRequest)\n %s\n", buf)
		err = io.SendGmm(ueConn, down.NasPdu)
		if err != nil {
			fmt.Printf("Error sending: %#v\n", err)
			return
		}

		reply, err = io.Recv(ueConn)
		if err != nil {
			fmt.Printf("Error reading: %#v\n", err)
			return
		}

		fmt.Println("=============================")
		fmt.Printf("FROM UE: (NASAuthRes)\n %s\n", reply)
		amfUeNgapId := down.AmfUeNgapId

		// AuthRes

		gmm = nas.GmmHeader{}
		err = parser.DecodeMsg(reply, &gmm)
		if err != nil {
			fmt.Printf("Error decoding: %#v\n", err)
			return
		}

		up := ngap.UpNASTransMsg{NasPdu: gmm, RanUeNgapId: 1, AmfUeNgapId: amfUeNgapId}
		err = io.SendNgapMsg(coreConn, ngap.UpNASTrans, &up)
		if err != nil {
			fmt.Printf("Error sending: %#v\n", err)
			return
		}

		buf, _ = parser.EncodeMsg(&up)
		fmt.Println("=============================")
		fmt.Printf("TO CORE: (UpNASTrans + NASAuthRes)\n %s\n", buf)

		// SecModeCmd
		reply, err = io.Recv(coreConn)
		if err != nil {
			fmt.Printf("Error reading: %#v\n", err)
			return
		}

		fmt.Println("=============================")
		fmt.Printf("FROM CORE: (DownNASTrans + NASSecurityModeCommand)\n %s\n", reply)

		ngapHeader = ngap.NgapHeader{}
		err = parser.DecodeMsg(reply, &ngapHeader)
		if err != nil {
			fmt.Printf("Error decoding: %#v\n", err)
			return
		}

		down = ngap.DownNASTransMsg{}

		err = parser.DecodeMsg(ngapHeader.NgapPdu, &down)
		if err != nil {
			fmt.Println("cannot decode")
			return
		}

		buf, _ = parser.EncodeMsg(&down.NasPdu)
		fmt.Println("=============================")
		fmt.Printf("TO UE: (NASSecurityModeCommand)\n %s\n", buf)
		err = io.SendGmm(ueConn, down.NasPdu)
		if err != nil {
			fmt.Printf("Error sending: %#v\n", err)
			return
		}

		// LocationUpdate
		reply, err = io.Recv(ueConn)
		if err != nil {
			fmt.Printf("Error reading: %#v\n", err)
			return
		}
		fmt.Println("=============================")
		fmt.Printf("FROM UE: (LocationUpdate)\n %s\n", reply)

		gmm = nas.GmmHeader{}
		err = parser.DecodeMsg(reply, &gmm)
		if err != nil {
			fmt.Printf("Error decoding: %#v\n", err)
			return
		}

		up = ngap.UpNASTransMsg{NasPdu: gmm, RanUeNgapId: 1, AmfUeNgapId: amfUeNgapId}
		err = io.SendNgapMsg(coreConn, ngap.UpNASTrans, &up)
		if err != nil {
			fmt.Printf("Error sending: %#v\n", err)
			return
		}

		buf, _ = parser.EncodeMsg(&up)
		fmt.Println("=============================")
		fmt.Printf("TO CORE: (UpNASTrans + LocationUpdate)\n %s\n", buf)

		// PDUSessionReq
		reply, err = io.Recv(ueConn)
		if err != nil {
			fmt.Printf("Error reading: %#v\n", err)
			return
		}
		fmt.Println("=============================")
		fmt.Printf("FROM UE: (PDUSessionEstRequest)\n %s\n", reply)

		gmm = nas.GmmHeader{}
		err = parser.DecodeMsg(reply, &gmm)
		if err != nil {
			fmt.Printf("Error decoding: %#v\n", err)
			return
		}

		up = ngap.UpNASTransMsg{NasPdu: gmm, RanUeNgapId: 1, AmfUeNgapId: amfUeNgapId}
		err = io.SendNgapMsg(coreConn, ngap.UpNASTrans, &up)
		if err != nil {
			fmt.Printf("Error sending: %#v\n", err)
			return
		}
		fmt.Println("=============================")
		buf, _ = parser.EncodeMsg(&up)
		fmt.Printf("TO CORE: (UpNASTrans + PDUSessionEstRequest)\n %s\n", buf)

		// PDUSessionAccept

		reply, err = io.Recv(coreConn)
		if err != nil {
			fmt.Printf("Error reading: %#v\n", err)
			return
		}

		fmt.Println("=============================")
		fmt.Printf("FROM CORE: (DownNASTrans + PDUSessionEstResponse)\n %s\n", reply)

		ngapHeader = ngap.NgapHeader{}
		err = parser.DecodeMsg(reply, &ngapHeader)
		if err != nil {
			fmt.Printf("Error decoding: %#v\n", err)
			return
		}

		down = ngap.DownNASTransMsg{}

		err = parser.DecodeMsg(ngapHeader.NgapPdu, &down)
		if err != nil {
			fmt.Println("cannot decode")
			return
		}

		err = io.SendGmm(ueConn, down.NasPdu)
		if err != nil {
			fmt.Printf("Error sending: %#v\n", err)
			return
		}

		buf, _ = parser.EncodeMsg(&down.NasPdu)
		fmt.Println("=============================")
		fmt.Printf("TO UE: (PDUSessionEstResponse)\n %s\n", buf)

		// PDUReq

		reply, err = io.Recv(ueConn)
		if err != nil {
			fmt.Printf("Error reading: %#v\n", err)
			return
		}

		fmt.Println("=============================")
		fmt.Printf("FROM UE: (PDUReq)\n %s\n", reply)

		gmm = nas.GmmHeader{}
		err = parser.DecodeMsg(reply, &gmm)
		if err != nil {
			fmt.Printf("Error decoding: %#v\n", err)
			return
		}

		up = ngap.UpNASTransMsg{NasPdu: gmm, RanUeNgapId: 1, AmfUeNgapId: amfUeNgapId}
		err = io.SendNgapMsg(coreConn, ngap.UpNASTrans, &up)
		if err != nil {
			fmt.Printf("Error sending: %#v\n", err)
			return
		}

		buf, _ = parser.EncodeMsg(&up)
		fmt.Println("=============================")
		fmt.Printf("TO CORE: (UpNASTrans + PDUReq)\n %s\n", buf)

		// PDURes

		reply, err = io.Recv(coreConn)
		if err != nil {
			fmt.Printf("Error reading: %#v\n", err)
			return
		}

		fmt.Println("=============================")
		fmt.Printf("FROM CORE: (DownNASTrans + PDURes)\n %s\n", reply)

		ngapHeader = ngap.NgapHeader{}
		err = parser.DecodeMsg(reply, &ngapHeader)
		if err != nil {
			fmt.Printf("Error decoding: %#v\n", err)
			return
		}

		down = ngap.DownNASTransMsg{}

		err = parser.DecodeMsg(ngapHeader.NgapPdu, &down)
		if err != nil {
			fmt.Println("cannot decode")
			return
		}

		err = io.SendGmm(ueConn, down.NasPdu)
		if err != nil {
			fmt.Printf("Error sending: %#v\n", err)
			return
		}

		buf, _ = parser.EncodeMsg(&down.NasPdu)
		fmt.Println("=============================")
		fmt.Printf("TO UE: (PDURes)\n %s\n", buf)

		return
	}

}

func main() {
	fmt.Printf("\n===== 5Go gNB jammer =====\n\n")
	fmt.Println("Bip bop... overpowering nearest basestations....")
	fmt.Println("CORE <-X-> gNB <-X-> UE")
	fmt.Printf("Creating fake basetation...\n\n")
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
	setupBuf, _ := parser.EncodeMsg(&setup)

	fmt.Println("=============================")
	fmt.Printf("TO CORE: (NGSetupRequest)\n %s\n", setupBuf)
	err = io.SendNgapMsg(coreConn, ngap.NGSetupRequest, &setup)
	if err != nil {
		fmt.Println(err)
		return
	}

	buf, err := io.Recv(coreConn)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("=============================")
	fmt.Printf("FROM CORE: (NGSetupResponse)\n %s\n", buf)

	fmt.Println("=============================")
	fmt.Printf("\nSuccessfully connected to CORE\n\n")
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
