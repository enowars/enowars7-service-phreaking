package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"phreaking/internal/core/crypto"
	"phreaking/internal/ue/pb"
	"phreaking/pkg/ngap"
	"phreaking/pkg/state"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

var (
	errDecode        = errors.New("cannot decode message")
	errIntegrity     = errors.New("integrity check failed")
	errNullIntegrity = errors.New("null integrity is not allowed")
	errIntegrityImp  = errors.New("integrity not implemented")
)

func handleConnection(c state.Connection) {
	err := sendRegistrationRequest(c)
	if err != nil {
		fmt.Printf("Error: %s", err)
	}

	for {
		buf := make([]byte, 1024)

		//len, err := c.Read(buf)
		_, err := c.Read(buf)
		if err != nil {
			fmt.Printf("Error reading: %#v\n", err)
			return
		}

		msgType := ngap.MsgType(buf[0])
		currState := c.Ctx.Value(state.StateKey).(state.State)

		switch {
		case msgType == ngap.NASAuthRequest && currState == state.RegReqDone:
			err := handleNASAuthRequest(c, buf[1:])
			if err != nil {
				fmt.Printf("Error: %s", err)
			}
		case msgType == ngap.NASSecurityModeCommand:
			err := handleNASSecurityModeCommand(c, buf[1:])
			if err != nil {
				fmt.Printf("Error: %s", err)
			}
		case msgType == ngap.PDUSessionEstAccept:
			err := handlePDUSessionEstRequest(c, buf[1:])
			if err != nil {
				fmt.Printf("Error: %s", err)
			}
		default:
			fmt.Println("invalid message type for UE")
		}
	}
	c.Close()
}

func sendRegistrationRequest(c state.Connection) error {
	fmt.Printf("Serving %s\n", c.RemoteAddr().String())

	c.Ctx = context.WithValue(c.Ctx, state.StateKey, state.Init)

	regMsg := ngap.NASRegRequestMsg{SecHeader: 0,
		MobileId: ngap.MobileIdType{Mcc: 0, Mnc: 0, ProtecScheme: 0, HomeNetPki: 0, Msin: 0},
		SecCap:   ngap.SecCapType{EA: 1, IA: 1},
	}

	pdu, _ := ngap.EncodeMsg(ngap.NASRegRequest, &regMsg)
	_, err := c.Write(pdu)
	if err != nil {
		return err
	}
	c.Ctx = context.WithValue(c.Ctx, state.StateKey, state.RegReqDone)
	return nil
}

func handlePDUSessionEstRequest(c state.Connection, buf []byte) error {
	var msg ngap.PDUSessionEstAcceptMsg

	if c.Ctx.Value(state.EA).(int) == 1 {
		buf = crypto.DecryptAES(buf)
	}

	mac := buf[:8]
	buf = buf[8:]

	switch {
	case c.Ctx.Value(state.IA) == 0:
		return errNullIntegrity
	case c.Ctx.Value(state.IA).(int) < 5:
		alg, ok := crypto.IAalg[int8(c.Ctx.Value(state.IA).(int))]
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

	return nil

	/*
		locreq := ngap.LocationReportRequestMsg{AmfUeNgapId: 1, RanUeNgapId: 1}
		buf, err = ngap.EncodeMsg(ngap.LocationReportRequest, &locreq)
		if err != nil {
			fmt.Println(err)
		}

		_, err = c.Write(buf)
		return err
	*/
}

func handleNASSecurityModeCommand(c state.Connection, buf []byte) error {
	var msg ngap.NASSecurityModeCommandMsg
	err := ngap.DecodeMsg(buf, &msg)
	if err != nil {
		return errors.New("cannot decode!")
	}

	c.Ctx = context.WithValue(c.Ctx, state.EA, msg.EaAlg)
	c.Ctx = context.WithValue(c.Ctx, state.IA, msg.IaAlg)

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

	mac := crypto.IAalg[int8(c.Ctx.Value(state.IA).(int))](pdu)[:8]

	if c.Ctx.Value(state.EA).(int) == 1 {
		pdu = crypto.EncryptAES(pdu)
	}

	var b bytes.Buffer
	b.WriteByte(byte(ngap.LocationUpdate))
	b.Write(mac)
	b.Write(pdu)

	pdu = b.Bytes()

	c.Write(pdu)

	b.Reset()

	time.Sleep(500 * time.Millisecond)

	// PDUSessionEstRequestMsg

	pduReq := ngap.PDUSessionEstRequestMsg{PduSesId: 0, PduSesType: 2}

	pdu, err = ngap.EncodeMsgBytes(&pduReq)
	if err != nil {
		fmt.Println(err)
	}

	mac = crypto.IAalg[int8(c.Ctx.Value(state.IA).(int))](pdu)[:8]

	if c.Ctx.Value(state.EA).(int) == 1 {
		pdu = crypto.EncryptAES(pdu)
	}

	b.WriteByte(byte(ngap.PDUSessionEstRequest))
	b.Write(mac)
	b.Write(pdu)

	pdu = b.Bytes()

	c.Write(pdu)
	return nil
}

func handleNASAuthRequest(c state.Connection, buf []byte) error {
	var msg ngap.NASAuthRequestMsg
	err := ngap.DecodeMsg(buf, &msg)
	if err != nil {
		return errors.New("cannot decode!")
	}

	res := crypto.IA2(msg.Rand)

	authRes := ngap.NASAuthResponseMsg{SecHeader: 0, Res: res}
	pdu, _ := ngap.EncodeMsg(ngap.NASAuthResponse, &authRes)

	c.Write(pdu)
	return nil
}

func main() {
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", 9933))
	if err != nil {
		log.Fatalf("grpc server failed to listen: %v", err)
	}
	defer lis.Close()

	s := pb.Server{}

	grpcServer := grpc.NewServer(grpc.UnaryInterceptor(pb.AuthInterceptor))

	pb.RegisterLocationServer(grpcServer, &s)
	reflection.Register(grpcServer)

	go func() {
		if err := grpcServer.Serve(lis); err != nil {
			log.Fatalf("failed to serve: %s", err)
		}
	}()

	l, err := net.Listen("tcp4", ":6060")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer l.Close()

	for {
		c, err := l.Accept()
		connection := state.Connection{Conn: c, Ctx: context.Background()}
		if err != nil {
			fmt.Println(err)
			return
		}
		go handleConnection(connection)
	}
}
