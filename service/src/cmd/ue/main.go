package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"phreaking/internal/core/crypto"
	"phreaking/internal/ue/pb"
	"phreaking/pkg/ngap"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

var ea = make(map[net.Conn]uint8)
var ia = make(map[net.Conn]uint8)

var (
	errDecode        = errors.New("cannot decode message")
	errIntegrity     = errors.New("integrity check failed")
	errNullIntegrity = errors.New("null integrity is not allowed")
	errIntegrityImp  = errors.New("integrity not implemented")
)

func handleConnection(c net.Conn) {
	timeout := time.NewTimer(time.Minute)
	defer func() {
		timeout.Stop()
		c.Close()
	}()

	err := sendRegistrationRequest(c)
	if err != nil {
		fmt.Printf("Error: %s", err)
	}

	for {
		select {
		case <-timeout.C:
			log.Println("handleConnection run for more than a minute.")
			return
		default:

			buf := make([]byte, 1024)

			_, err = c.Read(buf)
			if err != nil {
				fmt.Printf("Error reading: %#v\n", err)
				return
			}

			msgType := ngap.MsgType(buf[0])

			switch {
			case msgType == ngap.NASAuthRequest:
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
	}

}

func sendRegistrationRequest(c net.Conn) error {
	fmt.Printf("Serving %s\n", c.RemoteAddr().String())

	//c.Ctx = context.WithValue(c.Ctx, state.StateKey, state.Init)

	regMsg := ngap.NASRegRequestMsg{SecHeader: 0,
		MobileId: ngap.MobileIdType{Mcc: 0, Mnc: 0, ProtecScheme: 0, HomeNetPki: 0, Msin: 0},
		SecCap:   ngap.SecCapType{EA: 1, IA: 1},
	}

	pdu, _ := ngap.EncodeMsg(ngap.NASRegRequest, &regMsg)
	_, err := c.Write(pdu)
	if err != nil {
		return err
	}
	//c.Ctx = context.WithValue(c.Ctx, state.StateKey, state.RegReqDone)
	return nil
}

func handlePDUSessionEstRequest(c net.Conn, buf []byte) error {
	var msg ngap.PDUSessionEstAcceptMsg

	if ea[c] == 1 {
		buf = crypto.DecryptAES(buf)
	}

	mac := buf[:8]
	buf = buf[8:]

	switch {
	case ia[c] == 0:
		return errNullIntegrity
	case ia[c] < 5:
		alg, ok := crypto.IAalg[int8(ia[c])]
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

func handleNASSecurityModeCommand(c net.Conn, buf []byte) error {
	var msg ngap.NASSecurityModeCommandMsg
	err := ngap.DecodeMsg(buf, &msg)
	if err != nil {
		return errors.New("cannot decode!")
	}

	ea[c] = msg.EaAlg
	ia[c] = msg.IaAlg

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

	mac := crypto.IAalg[int8(ia[c])](pdu)[:8]

	if ea[c] == 1 {
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

	mac = crypto.IAalg[int8(ia[c])](pdu)[:8]

	if ea[c] == 1 {
		pdu = crypto.EncryptAES(pdu)
	}

	b.WriteByte(byte(ngap.PDUSessionEstRequest))
	b.Write(mac)
	b.Write(pdu)

	pdu = b.Bytes()

	c.Write(pdu)
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
		if err != nil {
			fmt.Println(err)
			return
		}
		go handleConnection(c)
	}
}
