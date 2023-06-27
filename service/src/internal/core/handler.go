package core

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"phreaking/internal/crypto"
	"phreaking/internal/io"
	"phreaking/pkg/ngap"
	"time"

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
	log := amf.Logger.Sugar()
	log.Infof("Serving %s", c.RemoteAddr().String())

	timeout := time.NewTimer(time.Minute)
	defer func() {
		timeout.Stop()
		c.Close()
		log.Infof("Closed connection for remote: %s", c.RemoteAddr().String())
	}()

	var amfg *AmfGNB

	for {
		select {
		case <-timeout.C:
			log.Infof("HandleConnection timeout for remote: %s", c.RemoteAddr().String())
			return
		default:
			buf, err := io.RecvMsg(c)
			if err != nil {
				if !errors.Is(err, io.EOF) {
					log.Errorf("Error reading: %w", err)
				}
				return
			}

			msgType := ngap.MsgType(buf[0])
			if msgType == ngap.NGSetupRequest && amfg == nil {
				amfg, err = amf.handleNGSetupRequest(c, buf[1:])
				if err != nil {
					log.Errorf("Error creating gNB %w", err)
					return
				}
			} else if amfg != nil {
				err = amf.HandleNGAP(c, buf, amfg)
				if err != nil {
					log.Errorf("Error NGAP: %w", err)
					return
				}
			} else {
				log.Errorln("Error gNB connection")
				return
			}
		}
	}
}

func (amf *Amf) handleNGSetupRequest(c net.Conn, buf []byte) (*AmfGNB, error) {
	var msg ngap.NGSetupRequestMsg
	err := ngap.DecodeMsg(buf, &msg)
	if err != nil {
		return nil, errDecode
	}

	amfg := &AmfGNB{GranId: msg.GranId, Tac: msg.Tac, Plmn: msg.Plmn, AmfUEs: make(map[ngap.AmfUeNgapIdType]AmfUE)}

	// 0x00ff10 = MCC 001, MNC 01
	res := ngap.NGSetupResponseMsg{AmfName: amf.AmfName, GuamPlmn: 0x00ff10,
		AmfRegionId: amf.AmfRegionId, AmfSetId: amf.AmfSetId, AmfPtr: amf.AmfPtr,
		AmfCap: amf.AmfCap, Plmn: msg.Plmn}

	bytesRes, err := ngap.EncodeMsg(ngap.NGSetupResponse, &res)
	if err != nil {
		return nil, errEncode
	}

	return amfg, io.SendMsg(c, []byte(bytesRes))
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
		return fmt.Errorf("invalid message type (%d) for NGAP (non NAS-PDU)", msgType)
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
		err = amf.handleNASPDU(c, msg.NasPdu, amfg, &ue)
		if err != nil {
			return err
		}
		amfg.AmfUEs[msg.AmfUeNgapId] = ue
		return nil
	}
	return errors.New("cannot find NG for AmfUeNgapId")
}

func (amf *Amf) handleNASPDU(c net.Conn, buf []byte, amfg *AmfGNB, ue *AmfUE) error {
	msgType := ngap.MsgType(buf[0])

	switch msgType {
	case ngap.NASAuthResponse:
		err := amf.handleNASAuthResponse(c, buf[1:], amfg, ue)
		if err != nil {
			return err
		}
	case ngap.PDUSessionEstRequest:
		err := amf.handlePDUSessionEstRequest(c, buf[1:], amfg, ue)
		if err != nil {
			return err
		}
	case ngap.LocationUpdate:
		err := amf.handleLocationUpdate(c, buf[1:], amfg, ue)
		if err != nil {
			return err
		}
	case ngap.PDUReq:
		err := amf.handlePDUReq(c, buf[1:], amfg, ue)
		if err != nil {
			return err
		}
	default:
		return errors.New("invalid message type for NAS-PDU")
	}
	return nil
}

func (amf *Amf) handlePDUReq(c net.Conn, buf []byte, amfg *AmfGNB, ue *AmfUE) error {
	var msg ngap.PDUReqMsg

	if !ue.Authenticated {
		return errNotAuth
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

	if ue.EaAlg == 1 {
		buf = crypto.DecryptAES(buf)
	}

	err := ngap.DecodeMsg(buf, &msg)
	if err != nil {
		return errDecode
	}

	pduType, ok := ue.PDUs[msg.PduSesId]
	if !ok {
		return errors.New("pdu session id not found")
	}

	switch pduType {
	case 0:
		res, err := http.Get(string(msg.Request))
		if err != nil {
			return err
		}
		response, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return err
		}
		resMsg := ngap.PDUResMsg{PduSesId: msg.PduSesId, Response: []byte(response)}

		pdu, err := ngap.EncodeMsgBytes(&resMsg)
		if err != nil {
			return err
		}

		if ue.EaAlg == 1 {
			pdu = crypto.EncryptAES(pdu)
		}

		mac = crypto.IAalg[ue.IaAlg](pdu)[:8]

		var b bytes.Buffer
		b.WriteByte(byte(ngap.PDURes))
		b.Write(mac)
		b.Write(pdu)

		pdu = b.Bytes()

		down := ngap.DownNASTransMsg{NasPdu: pdu, RanUeNgapId: ue.RanUeNgapId, AmfUeNgapId: ue.AmfUeNgapId}
		buf, err = ngap.EncodeMsg(ngap.DownNASTrans, &down)
		if err != nil {
			return err
		}

		return io.SendMsg(c, buf)
	default:
		return errors.New("pdu type not supported")
	}
}

func (amf *Amf) handleLocationUpdate(c net.Conn, buf []byte, amfg *AmfGNB, ue *AmfUE) error {
	var msg ngap.LocationUpdateMsg

	if !ue.Authenticated {
		return errNotAuth
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

	if ue.EaAlg == 1 {
		buf = crypto.DecryptAES(buf)
	}

	err := ngap.DecodeMsg(buf, &msg)
	if err != nil {
		return errDecode
	}

	ue.Locations = append(ue.Locations, msg.Location)
	return nil
}

func (amf *Amf) handlePDUSessionEstRequest(c net.Conn, buf []byte, amfg *AmfGNB, ue *AmfUE) error {
	var msg ngap.PDUSessionEstRequestMsg

	if !ue.Authenticated {
		return errNotAuth
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

	if ue.EaAlg == 1 {
		buf = crypto.DecryptAES(buf)
	}

	err := ngap.DecodeMsg(buf, &msg)
	if err != nil {
		return errDecode
	}

	ue.PDUs[msg.PduSesId] = msg.PduSesType

	pduAcc := ngap.PDUSessionEstAcceptMsg{PduSesId: msg.PduSesId}

	pdu, err := ngap.EncodeMsgBytes(&pduAcc)
	if err != nil {
		return err
	}

	if ue.EaAlg == 1 {
		pdu = crypto.EncryptAES(pdu)
	}

	mac = crypto.IAalg[ue.IaAlg](pdu)[:8]

	var b bytes.Buffer
	b.WriteByte(byte(ngap.PDUSessionEstAccept))
	b.Write(mac)
	b.Write(pdu)

	pdu = b.Bytes()

	down := ngap.DownNASTransMsg{NasPdu: pdu, RanUeNgapId: ue.RanUeNgapId, AmfUeNgapId: ue.AmfUeNgapId}
	buf, err = ngap.EncodeMsg(ngap.DownNASTrans, &down)
	if err != nil {
		return err
	}

	return io.SendMsg(c, buf)
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

	ue := AmfUE{RanUeNgapId: initmsg.RanUeNgapId, PDUs: make(map[uint8]uint8)}

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

	authRand := make([]byte, 32)
	rand.Read(authRand)

	auth := crypto.IA2(authRand)

	ue.RandToken = randToken

	authReq := ngap.NASAuthRequestMsg{SecHeader: 0, Rand: ue.RandToken, AuthRand: authRand, Auth: auth}

	authReqbuf, err := ngap.EncodeMsg(ngap.NASAuthRequest, &authReq)
	if err != nil {
		return errEncode
	}

	uv4, _ := uuid.NewV4()
	amfueid := ngap.AmfUeNgapIdType(uv4)
	ue.AmfUeNgapId = amfueid

	downTrans := ngap.DownNASTransMsg{AmfUeNgapId: ue.AmfUeNgapId, RanUeNgapId: ue.RanUeNgapId, NasPdu: authReqbuf}

	downBuf, err := ngap.EncodeMsg(ngap.DownNASTrans, &downTrans)
	if err != nil {
		return errEncode
	}

	amfg.AmfUEs[amfueid] = ue
	return io.SendMsg(c, downBuf)
}

func (amf *Amf) handleNASAuthResponse(c net.Conn, buf []byte, amfg *AmfGNB, ue *AmfUE) error {
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

	amf.Logger.Sugar().Infoln("AUTHENTICATION SUCCESSFULL")
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

	return io.SendMsg(c, downTransBuf)
}
