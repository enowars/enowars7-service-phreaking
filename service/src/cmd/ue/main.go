package main

import (
	"errors"
	"fmt"
	"net"
	"phreaking/internal/core/crypto"
	"phreaking/pkg/ngap"
)

var ea = make(map[net.Conn]uint8)
var ia = make(map[net.Conn]uint8)

func handleConnection(c net.Conn) {
	fmt.Printf("Serving %s\n", c.RemoteAddr().String())

	regMsg := ngap.NASRegRequestMsg{SecHeader: 0,
		MobileId: ngap.MobileIdType{Mcc: 0, Mnc: 0, ProtecScheme: 0, HomeNetPki: 0, Msin: 0},
		SecCap:   ngap.SecCapType{EA: 0, IA: 0},
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

	var pdu []byte

	if ea[c] == 1 {
		pdu, err = ngap.EncodeEncMsg(ngap.PDUSessionEstRequest, &pduReq)
		if err != nil {
			fmt.Println(err)
		}
	} else {
		pdu, err = ngap.EncodeMsg(ngap.PDUSessionEstRequest, &pduReq)
		if err != nil {
			fmt.Println(err)
		}
	}

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

	res := crypto.EncryptAES(msg.Rand)

	authRes := ngap.NASAuthResponseMsg{SecHeader: 0, Res: res}
	pdu, _ := ngap.EncodeMsg(ngap.NASAuthResponse, &authRes)

	// TODO: remove gNB encapsulation
	up := ngap.UpNASTransMsg{NasPdu: pdu, RanUeNgapId: 1}
	buf, _ = ngap.EncodeMsg(ngap.UpNASTrans, &up)

	c.Write(buf)
	return nil
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
