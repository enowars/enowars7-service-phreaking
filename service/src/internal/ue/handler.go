package ue

import (
	"bufio"
	"errors"
	"net"
	"os"
	"phreaking/internal/crypto"
	"phreaking/internal/io"
	"phreaking/pkg/ngap"
)

var (
	errDecode = errors.New("cannot decode message")
)

func (u *UE) HandlePDURes(c net.Conn, msgbuf []byte) error {
	var msg ngap.PDUResMsg

	err := ngap.DecodeMsg(msgbuf, &msg)
	if err != nil {
		return errDecode
	}

	u.Logger.Sugar().Debugf("http response len: %d", len(msg.Response))
	return nil
}

func (u *UE) HandlePDUSessionEstAccept(c net.Conn, msgbuf []byte) error {
	var msg ngap.PDUSessionEstAcceptMsg

	err := ngap.DecodeMsg(msgbuf, &msg)
	if err != nil {
		return errDecode
	}

	u.ActivePduId = msg.PduSesId

	pduReq := ngap.PDUReqMsg{PduSesId: u.ActivePduId, Request: []byte("http://httpbin.org/html")}

	pduReqMsg, mac, err := ngap.BuildMessage(u.EaAlg, u.IaAlg, &pduReq)
	if err != nil {
		return err
	}

	gmm := ngap.GmmPacket{Security: true, Mac: mac, MessageType: ngap.PDUReq, Message: pduReqMsg}
	return io.SendGmm(c, gmm)
}

func (u *UE) HandleNASSecurityModeCommand(c net.Conn, msgbuf []byte) error {
	var msg ngap.NASSecurityModeCommandMsg
	err := ngap.DecodeMsg(msgbuf, &msg)
	if err != nil {
		return errors.New("cannot decode")
	}

	u.EaAlg = msg.EaAlg
	u.IaAlg = msg.IaAlg

	location := ""
	readFile, err := os.Open("/service/data/location.data")
	if err != nil {
		return err
	}

	fileScanner := bufio.NewScanner(readFile)
	fileScanner.Split(bufio.ScanLines)
	for fileScanner.Scan() {
		location = fileScanner.Text()
	}
	readFile.Close()

	loc := ngap.LocationUpdateMsg{Location: location}
	locMsg, mac, err := ngap.BuildMessage(u.EaAlg, u.IaAlg, &loc)
	if err != nil {
		return err
	}

	gmm := ngap.GmmPacket{Security: true, Mac: mac, MessageType: ngap.LocationUpdate, Message: locMsg}
	err = io.SendGmm(c, gmm)
	if err != nil {
		return err
	}

	pduEstReq := ngap.PDUSessionEstRequestMsg{PduSesId: 0, PduSesType: 0}
	pduEstReqMsg, mac, err := ngap.BuildMessage(u.EaAlg, u.IaAlg, &pduEstReq)
	if err != nil {
		return err
	}

	gmm = ngap.GmmPacket{Security: true, Mac: mac, MessageType: ngap.PDUSessionEstRequest, Message: pduEstReqMsg}
	return io.SendGmm(c, gmm)
}

func (u *UE) HandleNASAuthRequest(c net.Conn, msgbuf []byte) error {
	var msg ngap.NASAuthRequestMsg
	err := ngap.DecodeMsg(msgbuf, &msg)
	if err != nil {
		return errors.New("cannot decode")
	}

	if !(string(crypto.IA2(msg.AuthRand)) == string(msg.Auth)) {
		return errors.New("cannot authenticate core")
	}

	res := crypto.IA2(msg.Rand)
	authRes := ngap.NASAuthResponseMsg{SecHeader: 0, Res: res}
	authResMsg, mac, err := ngap.BuildMessagePlain(&authRes)
	if err != nil {
		return err
	}

	gmm := ngap.GmmPacket{Security: false, Mac: mac, MessageType: ngap.NASAuthRequest, Message: authResMsg}
	return io.SendGmm(c, gmm)
}
