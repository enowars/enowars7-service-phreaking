package core

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"phreaking/internal/crypto"
	"phreaking/pkg/ngap"

	"github.com/gofrs/uuid"
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

func (amf *Amf) HandleConnection(c net.Conn) {
	fmt.Printf("Serving %s\n", c.RemoteAddr().String())

	var amfg *AmfGNB

	for {
		buf := make([]byte, 1024)

		//len, err := c.Read(buf)
		_, err := c.Read(buf)
		if err != nil {
			fmt.Printf("Error reading: %#v\n", err)
			c.Close()
			return
		}
		msgType := ngap.MsgType(buf[0])
		if msgType == ngap.NGSetupRequest && amfg == nil {
			amfg, err = amf.handleNGSetupRequest(c, buf[1:])
			if err != nil {
				fmt.Printf("Error creating gNB\n")
				c.Close()
				return
			}
		} else if amfg != nil {
			amf.HandleNGAP(c, buf, amfg)
		} else {
			fmt.Printf("Error gNB connection\n")
			c.Close()
			break
		}
	}
}

func (amf *Amf) handleNGSetupRequest(c net.Conn, buf []byte) (*AmfGNB, error) {
	var msg ngap.NGSetupRequestMsg
	err := ngap.DecodeMsg(buf, &msg)
	if err != nil {
		return nil, errDecode
	}

	amfg := &AmfGNB{GranId: msg.GranId, Tac: msg.Tac, Plmn: msg.Plmn}

	// 0x00ff10 = MCC 001, MNC 01
	res := ngap.NGSetupResponseMsg{AmfName: amf.AmfName, GuamPlmn: 0x00ff10,
		AmfRegionId: amf.AmfRegionId, AmfSetId: amf.AmfSetId, AmfPtr: amf.AmfPtr,
		AmfCap: amf.AmfCap, Plmn: msg.Plmn}

	bytesRes, err := ngap.EncodeMsg(ngap.NGSetupResponse, &res)
	if err != nil {
		return nil, errEncode
	}

	SendMsg(c, []byte(bytesRes))
	return amfg, nil
}

func (amf *Amf) HandleNGAP(c net.Conn, buf []byte, amfg *AmfGNB) error {
	msgType := ngap.MsgType(buf[0])

	switch msgType {

	case ngap.InitUEMessage:
		err := amf.handleInitUEMessage(c, buf[1:], amfg)
		if err != nil {
			return err
		}

	case ngap.UpNASTrans:
		err := amf.handleUpNASTrans(c, buf[1:], amfg)
		if err != nil {
			return err
		}

	default:
		return errors.New("invalid message type for NGAP (non NAS-PDU)")
	}
	return nil
}

func (amf *Amf) handleUpNASTrans(c net.Conn, buf []byte, amfg *AmfGNB) error {
	var msg ngap.UpNASTransMsg
	err := ngap.DecodeMsg(buf, &msg)
	if err != nil {
		return errDecode
	}

	ue, ok := amfg.AmfUEs[msg.AmfUeNgapId]
	if ok {
		return handleNASPDU(c, msg.NasPdu, amfg, &ue)
	}
	return errors.New("Cannot find NG for AmfUeNgapId")
}

func handleNASPDU(c net.Conn, buf []byte, amfg *AmfGNB, ue *AmfUE) error {
	msgType := ngap.MsgType(buf[0])

	switch msgType {
	case ngap.NASAuthResponse:
		err := handleNASAuthResponse(c, buf[1:], amfg, ue)
		if err != nil {
			return err
		}
	case ngap.PDUSessionEstRequest:
		err := handlePDUSessionEstRequest(c, buf[1:], amfg, ue)
		if err != nil {
			return err
		}
	case ngap.LocationUpdate:
		err := handleLocationUpdate(c, buf[1:], amfg, ue)
		if err != nil {
			return err
		}
	default:
		return errors.New("invalid message type for NAS-PDU")
	}
	return nil
}

func handleLocationUpdate(c net.Conn, buf []byte, amfg *AmfGNB, ue *AmfUE) error {
	var msg ngap.LocationUpdateMsg

	if !ue.Authenticated {
		return errNotAuth
	}

	if ue.EaAlg == 1 {
		buf = crypto.DecryptAES(buf)
	}

	mac := buf[:8]
	buf = buf[8:]

	switch {
	case ue.IaAlg == 0:
		return errNullIntegrity
	case ue.IaAlg < 5:
		alg, ok := crypto.IAalg[ue.IaAlg]
		if !ok {
			return errIntegrityImp
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

	ue.Locations = append(ue.Locations, msg.Location)
	fmt.Println(ue.Locations)
	return nil
}

func handlePDUSessionEstRequest(c net.Conn, buf []byte, amfg *AmfGNB, ue *AmfUE) error {
	var msg ngap.PDUSessionEstRequestMsg

	if ue.EaAlg == 1 {
		buf = crypto.DecryptAES(buf)
	}

	mac := buf[:8]
	buf = buf[8:]

	switch {
	case ue.IaAlg == 0:
		return errNullIntegrity
	case ue.IaAlg < 5:
		alg, ok := crypto.IAalg[ue.IaAlg]
		if !ok {
			return errIntegrityImp
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

	mac = crypto.IAalg[ue.IaAlg](pdu)[:8]

	if ue.EaAlg == 1 {
		pdu = crypto.EncryptAES(pdu)
	}

	var b bytes.Buffer
	b.WriteByte(byte(ngap.PDUSessionEstAccept))
	b.Write(mac)
	b.Write(pdu)

	pdu = b.Bytes()

	down := ngap.DownNASTransMsg{NasPdu: pdu, RanUeNgapId: ue.RanUeNgapId, AmfUeNgapId: ue.AmfUeNgapId}
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

func (amf *Amf) handleInitUEMessage(c net.Conn, buf []byte, amfg *AmfGNB) error {
	var initmsg ngap.InitUEMessageMsg
	err := ngap.DecodeMsg(buf, &initmsg)
	if err != nil {
		return errDecode
	}

	ue := AmfUE{RanUeNgapId: initmsg.RanUeNgapId}

	msgType := ngap.MsgType(initmsg.NasPdu[0])
	if msgType != ngap.NASRegRequest {
		return errors.New("InitUEMessage contains uknown message type")
	}
	var regmsg ngap.NASRegRequestMsg
	err = ngap.DecodeMsg(initmsg.NasPdu[1:], &regmsg)
	if err != nil {
		return errDecode
	}

	ue.SecCap = regmsg.SecCap

	randToken := make([]byte, 32)
	rand.Read(randToken)

	ue.RandToken = randToken

	authReq := ngap.NASAuthRequestMsg{SecHeader: 0, Rand: ue.RandToken}

	authReqbuf, err := ngap.EncodeMsg(ngap.NASAuthRequest, &authReq)
	if err != nil {
		return errEncode
	}

	uv4, _ := uuid.NewV4()
	amfueid := ngap.AmfUeNgapIdType(uv4)
	amfg.AmfUEs = make(map[ngap.AmfUeNgapIdType]AmfUE)
	amfg.AmfUEs[amfueid] = ue
	ue.AmfUeNgapId = amfueid

	downTrans := ngap.DownNASTransMsg{AmfUeNgapId: ue.AmfUeNgapId, RanUeNgapId: ue.RanUeNgapId, NasPdu: authReqbuf}

	downBuf, err := ngap.EncodeMsg(ngap.DownNASTrans, &downTrans)
	if err != nil {
		return errEncode
	}

	return SendMsg(c, downBuf)
}

func handleNASAuthResponse(c net.Conn, buf []byte, amfg *AmfGNB, ue *AmfUE) error {
	var msg ngap.NASAuthResponseMsg
	err := ngap.DecodeMsg(buf, &msg)
	if err != nil {
		return errDecode
	}

	hkres := crypto.ComputeHash(crypto.IA2(ue.RandToken))
	hres := crypto.ComputeHash(msg.Res)

	if hkres != hres {
		return errAuth
	}
	fmt.Println("AUTHENTICATION SUCCESSFULL")
	ue.Authenticated = true

	// TODO choose best EA/IA
	ue.EaAlg = ue.SecCap.EA
	ue.IaAlg = ue.SecCap.IA
	secModeCmd := ngap.NASSecurityModeCommandMsg{SecHeader: 1, EaAlg: ue.EaAlg,
		IaAlg: ue.IaAlg, SecCap: ue.SecCap,
	}

	pdu, _ := ngap.EncodeMsg(ngap.NASSecurityModeCommand, &secModeCmd)

	downTrans := ngap.DownNASTransMsg{AmfUeNgapId: ue.AmfUeNgapId, RanUeNgapId: ue.RanUeNgapId, NasPdu: pdu}
	downTransBuf, _ := ngap.EncodeMsg(ngap.DownNASTrans, &downTrans)

	return SendMsg(c, downTransBuf)
}
