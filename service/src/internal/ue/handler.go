package ue

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"phreaking/internal/crypto"
	"phreaking/internal/io"
	"phreaking/pkg/ngap"
	"time"
)

var (
	errDecode        = errors.New("cannot decode message")
	errIntegrity     = errors.New("integrity check failed")
	errNullIntegrity = errors.New("null integrity is not allowed")
	errIntegrityImp  = errors.New("integrity not implemented")
)

func (u *UE) HandlePDUSessionEstAccept(c net.Conn, msgbuf []byte) error {
	var msg ngap.PDUSessionEstAcceptMsg

	mac := msgbuf[:8]

	msgbuf = msgbuf[8:]

	if u.EaAlg == 1 {
		msgbuf = crypto.DecryptAES(msgbuf)
	}

	switch {
	case u.IaAlg == 0:
		return errNullIntegrity
	case u.IaAlg < 5:
		alg, ok := crypto.IAalg[u.IaAlg]
		if !ok {
			return errIntegrityImp
		}
		if !bytes.Equal(mac, alg(msgbuf)[:8]) {
			return errIntegrity
		}
	default:
		return errIntegrityImp
	}

	err := ngap.DecodeMsg(msgbuf, &msg)
	if err != nil {
		return errDecode
	}

	return nil
}

func (u *UE) HandleNASSecurityModeCommand(c net.Conn, msgbuf []byte) error {
	var msg ngap.NASSecurityModeCommandMsg
	err := ngap.DecodeMsg(msgbuf, &msg)
	if err != nil {
		return errors.New("cannot decode!")
	}

	u.EaAlg = msg.EaAlg
	u.IaAlg = msg.IaAlg

	// LocationUpdate

	location := ""

	readFile, err := os.Open("/service/data/location.data")

	if err != nil {
		fmt.Println(err)
	}
	fileScanner := bufio.NewScanner(readFile)

	fileScanner.Split(bufio.ScanLines)

	for fileScanner.Scan() {
		location = fileScanner.Text()
	}

	readFile.Close()

	pduLoc := ngap.LocationUpdateMsg{Location: location}

	pdu, err := ngap.EncodeMsgBytes(&pduLoc)
	if err != nil {
		fmt.Println(err)
	}

	if u.EaAlg == 1 {
		pdu = crypto.EncryptAES(pdu)
	}

	mac := crypto.IAalg[u.IaAlg](pdu)[:8]

	var b bytes.Buffer
	b.WriteByte(byte(ngap.LocationUpdate))
	b.Write(mac)
	b.Write(pdu)

	pdu = b.Bytes()

	io.SendMsg(c, pdu)

	b.Reset()

	time.Sleep(500 * time.Millisecond)

	// PDUSessionEstRequestMsg

	pduReq := ngap.PDUSessionEstRequestMsg{PduSesId: 0, PduSesType: 2}

	pdu, err = ngap.EncodeMsgBytes(&pduReq)
	if err != nil {
		fmt.Println(err)
	}

	if u.EaAlg == 1 {
		pdu = crypto.EncryptAES(pdu)
	}

	mac = crypto.IAalg[u.IaAlg](pdu)[:8]

	b.WriteByte(byte(ngap.PDUSessionEstRequest))
	b.Write(mac)
	b.Write(pdu)

	pdu = b.Bytes()

	io.SendMsg(c, pdu)
	return nil
}

func (u *UE) HandleNASAuthRequest(c net.Conn, msgbuf []byte) error {
	var msg ngap.NASAuthRequestMsg
	err := ngap.DecodeMsg(msgbuf, &msg)
	if err != nil {
		return errors.New("cannot decode!")
	}

	res := crypto.IA2(msg.Rand)

	authRes := ngap.NASAuthResponseMsg{SecHeader: 0, Res: res}
	pdu, _ := ngap.EncodeMsg(ngap.NASAuthResponse, &authRes)

	io.SendMsg(c, pdu)
	return nil
}
