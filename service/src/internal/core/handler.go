package core

import (
	"bytes"
	"crypto/rand"
	"encoding/gob"
	"errors"
	"fmt"
	"net"
	"phreaking/internal/core/crypto"
	"phreaking/pkg/ngap"
)

var (
	errDecode        = errors.New("cannot decode message")
	errEncode        = errors.New("cannot encode message")
	errAuth          = errors.New("cannot authenticate UE")
	errNotAuth       = errors.New("not authenticated")
	errNullIntegrity = errors.New("null integrity is not allowed")
	errIntegrity     = errors.New("integrity check failed")
	errIntegrityImp  = errors.New("integrity not implemented")
)

var lastHandle = make(map[net.Conn]int32)
var ranUeNgapId = make(map[net.Conn]int32)
var amfUeNgapId = make(map[net.Conn]int32)
var randTokens = make(map[net.Conn][]byte)
var ea = make(map[net.Conn]int8)
var ia = make(map[net.Conn]int8)
var authenticated = make(map[net.Conn]bool)
var locations = make(map[net.Conn][]string)

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

	case ngap.LocationReportRequest:
		err := handleLocationReportRequest(c, buf[1:])
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
	case ngap.PDUSessionEstRequest:
		err := handlePDUSessionEstRequest(c, buf[1:])
		if err != nil {
			return err
		}
	case ngap.LocationUpdate:
		err := handleLocationUpdate(c, buf[1:])
		if err != nil {
			return err
		}
	default:
		return errors.New("invalid message type for NAS-PDU")
	}
	return nil
}

func handleLocationReportRequest(c net.Conn, buf []byte) error {
	var msg ngap.LocationReportRequestMsg

	fmt.Println(authenticated[c])
	if !authenticated[c] {
		return errNotAuth
	}

	err := ngap.DecodeMsg(buf, &msg)
	if err != nil {
		return errDecode
	}

	locs := locations[c]

	var locB bytes.Buffer
	enc := gob.NewEncoder(&locB)
	enc.Encode(locs)

	locBytes := locB.Bytes()

	// locBytes = crypto.EncryptAES(locBytes)

	locRes := ngap.LocationReportResponseMsg{AmfUeNgapId: msg.AmfUeNgapId, RanUeNgapId: msg.RanUeNgapId, Locations: locBytes}

	locResBytes, err := ngap.EncodeMsgBytes(&locRes)
	if err != nil {
		fmt.Println(err)
	}

	return SendMsg(c, locResBytes)
}

func handleLocationUpdate(c net.Conn, buf []byte) error {
	var msg ngap.LocationUpdateMsg

	if !authenticated[c] {
		return errNotAuth
	}

	if ea[c] == 1 {
		buf = crypto.DecryptAES(buf)
	}

	mac := buf[:8]
	buf = buf[8:]

	switch {
	case ia[c] == 0:
		return errNullIntegrity
	case ia[c] < 5:
		alg, ok := crypto.IAalg[ia[c]]
		if !ok {
			alg = crypto.IAalg[0]
		}
		if !bytes.Equal(mac, alg(buf)[:8]) {
			return errIntegrity
		}
	default:
		return errIntegrityImp
	}

	err := ngap.DecodeMsg(buf, &msg)
	if err != nil {
		return errDecode
	}

	fmt.Println(locations[c])
	fmt.Println(msg.Location)

	locations[c] = append(locations[c], msg.Location)
	fmt.Println(locations[c])
	return nil
}

func handlePDUSessionEstRequest(c net.Conn, buf []byte) error {
	var msg ngap.PDUSessionEstRequestMsg

	if ea[c] == 1 {
		buf = crypto.DecryptAES(buf)
	}

	mac := buf[:8]
	buf = buf[8:]

	switch {
	case ia[c] == 0:
		return errNullIntegrity
	case ia[c] < 5:
		alg, ok := crypto.IAalg[ia[c]]
		if !ok {
			alg = crypto.IAalg[0]
		}
		if !bytes.Equal(mac, alg(buf)[:8]) {
			return errIntegrity
		}
	default:
		return errIntegrityImp
	}

	fmt.Println("Integrity check successfull")

	err := ngap.DecodeMsg(buf, &msg)
	if err != nil {
		return errDecode
	}

	lastHandle[c] = int32(ngap.PDUSessionEstRequest)

	var pduAddr []byte

	switch msg.PduSesType {
	case 1:
		pduAddr = []byte{0xff, 0x00, 0x00, 0xff}
	/*
		case 2:
			pduAddr = []byte("ENO{GOGOGO5G}")
	*/
	default:
		pduAddr = []byte{10, 0, 0, 1}
	}

	pduAcc := ngap.PDUSessionEstAcceptMsg{PduSesId: msg.PduSesId, PduAddress: pduAddr}

	pdu, err := ngap.EncodeMsgBytes(&pduAcc)
	if err != nil {
		fmt.Println(err)
	}

	mac = crypto.IAalg[int8(ia[c])](pdu)[:8]

	if ea[c] == 1 {
		pdu = crypto.EncryptAES(pdu)
	}

	var b bytes.Buffer
	b.WriteByte(byte(ngap.PDUSessionEstAccept))
	b.Write(mac)
	b.Write(pdu)

	pdu = b.Bytes()

	down := ngap.DownNASTransMsg{NasPdu: pdu, RanUeNgapId: 1}
	buf, err = ngap.EncodeMsg(ngap.DownNASTrans, &down)
	if err != nil {
		fmt.Println(err)
	}

	return SendMsg(c, buf)
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
	lastHandle[c] = int32(ngap.InitUEMessage)
	ranUeNgapId[c] = int32(msg.RanUeNgapId)

	return handleNASPDU(c, msg.NasPdu)
}

func handleUpNASTrans(c net.Conn, buf []byte) error {
	var msg ngap.UpNASTransMsg
	err := ngap.DecodeMsg(buf, &msg)
	if err != nil {
		return errDecode
	}
	lastHandle[c] = int32(ngap.UpNASTrans)

	return handleNASPDU(c, msg.NasPdu)
}

func handleNASRegRequest(c net.Conn, buf []byte) error {
	var msg ngap.NASRegRequestMsg
	err := ngap.DecodeMsg(buf, &msg)
	if err != nil {
		return errDecode
	}
	lastHandle[c] = int32(ngap.NASRegRequest)
	ea[c] = int8(msg.SecCap.EA)
	ia[c] = int8(msg.SecCap.IA)

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
	lastHandle[c] = int32(ngap.NASAuthResponse)

	hkres := crypto.ComputeHash(crypto.IA2(randTokens[c]))
	hres := crypto.ComputeHash(msg.Res)

	if hkres != hres {
		return errAuth
	}
	fmt.Println("AUTHENTICATION SUCCESSFULL")
	authenticated[c] = true

	secModeCmd := ngap.NASSecurityModeCommandMsg{SecHeader: 1, EaAlg: uint8(ea[c]),
		IaAlg: uint8(ia[c]), SecCap: ngap.SecCapType{EA: uint8(ea[c]), IA: uint8(ia[c])},
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
	lastHandle[c] = int32(ngap.NGSetupRequest)
	authenticated[c] = false

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
