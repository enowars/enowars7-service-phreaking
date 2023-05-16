package core

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"phreaking/internal/core/crypto"
	"phreaking/pkg/ngap"
)

var (
	errDecode = errors.New("cannot decode message")
	errEncode = errors.New("cannot encode message")
	errAuth   = errors.New("cannot authenticate UE")
)

var lastHandle = make(map[net.Conn]int)
var ranUeNgapId = make(map[net.Conn]int)
var amfUeNgapId = make(map[net.Conn]int)
var randTokens = make(map[net.Conn][]byte)
var ea = make(map[net.Conn]uint8)
var ia = make(map[net.Conn]uint8)

func HandleNGAP(c net.Conn, buf []byte) error {
	msgType := ngap.MsgType(buf[0])

	switch msgType {
	case ngap.NGSetupRequest:
		err := handleNGSetupRequest(c, buf[1:])
		if err != nil {
			return err
		}

	case ngap.InitUEMessage:
		err := handleInitUEMessage(c, buf[1:])
		if err != nil {
			return err
		}

	case ngap.UpNASTrans:
		err := handleUpNASTrans(c, buf[1:])
		if err != nil {
			return err
		}

	default:
		return errors.New("invalid message type for NGAP (non NAS-PDU)")
	}
	return nil
}

func handleNASPDU(c net.Conn, buf []byte) error {
	msgType := ngap.MsgType(buf[0])

	switch msgType {
	case ngap.NASRegRequest:
		err := handleNASRegRequest(c, buf[1:])
		if err != nil {
			return err
		}
	case ngap.NASAuthResponse:
		err := handleNASAuthResponse(c, buf[1:])
		if err != nil {
			return err
		}
	default:
		return errors.New("invalid message type for NAS-PDU")
	}
	return nil
}

func handlePDUSessionResourceSetupRequest() {
	panic("unimplemented")
}

func handleRegisterComplete() {
	panic("unimplemented")
}

func handleInitialContextSetupResponse() {
	panic("unimplemented")
}

func handleUECapInfoIndication() {
	panic("unimplemented")
}

func handleNASSecurityModeComplete() {
	panic("unimplemented")
}

func handleNASIdResponse() {
	panic("unimplemented")
}

func handleInitUEMessage(c net.Conn, buf []byte) error {
	var msg ngap.InitUEMessageMsg
	err := ngap.DecodeMsg(buf, &msg)
	if err != nil {
		return errDecode
	}
	lastHandle[c] = int(ngap.InitUEMessage)
	ranUeNgapId[c] = int(msg.RanUeNgapId)

	return handleNASPDU(c, msg.NasPdu)
}

func handleUpNASTrans(c net.Conn, buf []byte) error {
	var msg ngap.UpNASTransMsg
	err := ngap.DecodeMsg(buf, &msg)
	if err != nil {
		return errDecode
	}
	lastHandle[c] = int(ngap.UpNASTrans)

	return handleNASPDU(c, msg.NasPdu)
}

func handleNASRegRequest(c net.Conn, buf []byte) error {
	var msg ngap.NASRegRequestMsg
	err := ngap.DecodeMsg(buf, &msg)
	if err != nil {
		return errDecode
	}
	lastHandle[c] = int(ngap.NASRegRequest)
	ea[c] = msg.SecCap.EA
	ia[c] = msg.SecCap.IA

	randToken := make([]byte, 32)
	rand.Read(randToken)

	randTokens[c] = randToken

	authReq := ngap.NASAuthRequestMsg{SecHeader: 0, Rand: randToken}

	authReqbuf, err := ngap.EncodeMsg(ngap.NASAuthRequest, &authReq)
	if err != nil {
		return errEncode
	}

	amfUeNgapId[c] = 1

	downTrans := ngap.DownNASTransMsg{AmfUeNgapId: uint32(amfUeNgapId[c]), RanUeNgapId: uint32(ranUeNgapId[c]), NasPdu: authReqbuf}

	downBuf, err := ngap.EncodeMsg(ngap.DownNASTrans, &downTrans)
	if err != nil {
		return errEncode
	}

	return SendMsg(c, downBuf)
}

func handleNASAuthResponse(c net.Conn, buf []byte) error {
	var msg ngap.NASAuthResponseMsg
	err := ngap.DecodeMsg(buf, &msg)
	if err != nil {
		return errDecode
	}
	lastHandle[c] = int(ngap.NASAuthResponse)

	kres := crypto.EncryptAES(randTokens[c])
	hkres := crypto.ComputeHash(kres)
	hres := crypto.ComputeHash(msg.Res)

	if hkres != hres {
		return errAuth
	}
	fmt.Println("AUTHENTICATION SUCCESSFULL")

	secModeCmd := ngap.NASSecurityModeCommandMsg{SecHeader: 1, EaAlg: ea[c],
		IaAlg: ia[c], SecCap: ngap.SecCapType{EA: ea[c], IA: ia[c]},
	}

	pdu, _ := ngap.EncodeMsg(ngap.NASSecurityModeCommand, &secModeCmd)

	downTrans := ngap.DownNASTransMsg{AmfUeNgapId: uint32(amfUeNgapId[c]), RanUeNgapId: uint32(ranUeNgapId[c]), NasPdu: pdu}
	downTransBuf, _ := ngap.EncodeMsg(ngap.DownNASTrans, &downTrans)

	return SendMsg(c, downTransBuf)
}

func handleNGSetupRequest(c net.Conn, buf []byte) error {
	var msg ngap.NGSetupRequestMsg
	err := ngap.DecodeMsg(buf, &msg)
	if err != nil {
		return errDecode
	}
	lastHandle[c] = int(ngap.NGSetupRequest)

	// 0x00ff10 = MCC 001, MNC 01
	res := ngap.NGSetupResponseMsg{AmfName: "5GO-AMF", GuamPlmn: 0x00ff10,
		AmfRegionId: 1, AmfSetId: 1, AmfPtr: 0, AmfCap: 255, Plmn: msg.Plmn}

	bytesRes, err := ngap.EncodeMsg(ngap.NGSetupResponse, &res)
	if err != nil {
		return errEncode
	}

	SendMsg(c, []byte(bytesRes))
	return nil
}
