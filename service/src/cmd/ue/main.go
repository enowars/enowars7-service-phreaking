package main

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"net"
	"phreaking/internal/core/crypto"
	"phreaking/internal/ue/pb"
	"phreaking/pkg/ngap"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

var ea = make(map[net.Conn]uint8)
var ia = make(map[net.Conn]uint8)

func handleConnection(c net.Conn) {
	fmt.Printf("Serving %s\n", c.RemoteAddr().String())

	regMsg := ngap.NASRegRequestMsg{SecHeader: 0,
		MobileId: ngap.MobileIdType{Mcc: 0, Mnc: 0, ProtecScheme: 0, HomeNetPki: 0, Msin: 0},
		SecCap:   ngap.SecCapType{EA: 0, IA: 1},
	}

	pdu, _ := ngap.EncodeMsg(ngap.NASRegRequest, &regMsg)

	// TODO: remove gNB encapsulation
	initUeMsg := ngap.InitUEMessageMsg{NasPdu: pdu, RanUeNgapId: 1}
	buf, _ := ngap.EncodeMsg(ngap.InitUEMessage, &initUeMsg)
	c.Write(buf)

	for {
		buf := make([]byte, 1024)

		//len, err := c.Read(buf)
		_, err := c.Read(buf)
		if err != nil {
			fmt.Printf("Error reading: %#v\n", err)
			return
		}
		msgType := ngap.MsgType(buf[0])

		switch msgType {
		case ngap.DownNASTrans:

			var msg ngap.DownNASTransMsg
			ngap.DecodeMsg(buf[1:], &msg)
			pduType := ngap.MsgType(msg.NasPdu[0])

			switch pduType {
			case ngap.NASAuthRequest:
				err := handleNASAuthRequest(c, msg.NasPdu[1:])
				if err != nil {
					fmt.Printf("Error: %s", err)
				}
			case ngap.NASSecurityModeCommand:
				err := handleNASSecurityModeCommand(c, msg.NasPdu[1:])
				if err != nil {
					fmt.Printf("Error: %s", err)
				}
			}
		default:
			fmt.Println("invalid message type for UE")
		}
	}
	c.Close()
}

func handleNASSecurityModeCommand(c net.Conn, buf []byte) error {
	var msg ngap.NASSecurityModeCommandMsg
	err := ngap.DecodeMsg(buf, &msg)
	if err != nil {
		return errors.New("cannot decode!")
	}

	ea[c] = msg.EaAlg
	ia[c] = msg.IaAlg

	pduReq := ngap.PDUSessionEstRequestMsg{PduSesId: 0, PduSesType: 2}

	pdu, err := ngap.EncodeMsgBytes(&pduReq)
	if err != nil {
		fmt.Println(err)
	}

	mac := crypto.IAalg[int8(ia[c])](pdu)[:8]

	if ea[c] == 1 {
		pdu = crypto.EncryptAES(pdu)
	}

	var b bytes.Buffer
	b.WriteByte(byte(ngap.PDUSessionEstRequest))
	b.Write(mac)
	b.Write(pdu)

	pdu = b.Bytes()

	up := ngap.UpNASTransMsg{NasPdu: pdu, RanUeNgapId: 1}
	buf, err = ngap.EncodeMsg(ngap.UpNASTrans, &up)
	if err != nil {
		fmt.Println(err)
	}

	c.Write(buf)
	return nil
}

func handleNASAuthRequest(c net.Conn, buf []byte) error {
	var msg ngap.NASAuthRequestMsg
	err := ngap.DecodeMsg(buf, &msg)
	if err != nil {
		return errors.New("cannot decode!")
	}

	res := crypto.IA2(msg.Rand)

	authRes := ngap.NASAuthResponseMsg{SecHeader: 0, Res: res}
	pdu, _ := ngap.EncodeMsg(ngap.NASAuthResponse, &authRes)

	// TODO: remove gNB encapsulation
	up := ngap.UpNASTransMsg{NasPdu: pdu, RanUeNgapId: 1}
	buf, _ = ngap.EncodeMsg(ngap.UpNASTrans, &up)

	c.Write(buf)
	return nil
}

func main() {
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", 9000))
	if err != nil {
		log.Fatalf("grpc server failed to listen: %v", err)
	}

	s := pb.Server{}

	grpcServer := grpc.NewServer(grpc.UnaryInterceptor(pb.AuthInterceptor))

	pb.RegisterLocationServer(grpcServer, &s)
	reflection.Register(grpcServer)

	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %s", err)
	}

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
