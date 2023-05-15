package core

import (
	"errors"
	"net"
	"phreaking/pkg/ngap"
)

var (
	errDecode = errors.New("cannot decode message")
	errEncode = errors.New("cannot encode message")
)

var lastHandle = make(map[net.Conn]int)

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
	case ngap.NASIdResponse:
		handleNASIdResponse()
	case ngap.NASAuthResponse:
		handleNASAuthResponse()
	case ngap.NASSecurityModeComplete:
		handleNASSecurityModeComplete()
	case ngap.UECapInfoIndication:
		handleUECapInfoIndication()
	case ngap.InitialContextSetupResponse:
		handleInitialContextSetupResponse()
	case ngap.RegisterComplete:
		handleRegisterComplete()
	case ngap.PDUSessionResourceSetupRequest:
		handlePDUSessionResourceSetupRequest()
	default:
		return errors.New("invalid message type for NGAP")
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

func handleNASAuthResponse() {
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

	handleNASPDU(c, buf)

	return nil
}

func handleNASRegRequest(c net.Conn, buf []byte) error {
	var msg ngap.NASRegRequestMsg
	err := ngap.DecodeMsg(buf, &msg)
	if err != nil {
		return errDecode
	}
	lastHandle[c] = int(ngap.NASRegRequest)
	return nil
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
