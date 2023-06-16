package main

import (
	"fmt"
	"log"
	"net"
	"phreaking/internal/io"
	"phreaking/internal/ue"
	"phreaking/internal/ue/pb"
	"phreaking/pkg/ngap"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

func handleConnection(c net.Conn) {
	u := *ue.NewUE()

	timeout := time.NewTimer(time.Minute)
	defer func() {
		timeout.Stop()
		c.Close()
	}()

	err := sendRegistrationRequest(c)
	if err != nil {
		fmt.Printf("Error: %s", err)
	}

	u.ToState(ue.RegistrationInitiated)

	for {
		select {
		case <-timeout.C:
			log.Println("handleConnection run for more than a minute.")
			return
		default:
			buf, err := io.RecvMsg(c)
			if err != nil {
				fmt.Printf("Error reading: %#v\n", err)
				return
			}

			msgType := ngap.MsgType(buf[0])

			switch {
			case msgType == ngap.NASAuthRequest && u.InState(ue.RegistrationInitiated):
				err := u.HandleNASAuthRequest(c, buf[1:])
				if err != nil {
					fmt.Printf("Error: %s", err)
					return
				}
				u.ToState(ue.Authentication)
			case msgType == ngap.NASSecurityModeCommand && u.InState(ue.Authentication):
				err := u.HandleNASSecurityModeCommand(c, buf[1:])
				if err != nil {
					fmt.Printf("Error: %s", err)
					return
				}
				u.ToState(ue.SecurityMode)
			case msgType == ngap.PDUSessionEstAccept && u.InState(ue.SecurityMode):
				err := u.HandlePDUSessionEstAccept(c, buf[1:])
				if err != nil {
					fmt.Printf("Error: %s", err)
					return
				}
				u.ToState(ue.Registered)
			case msgType == ngap.PDURes && u.InState(ue.Registered):
				err := u.HandlePDURes(c, buf[1:])
				if err != nil {
					fmt.Printf("Error: %s", err)
					return
				}
			default:
				fmt.Println("invalid message type for UE")
			}
		}
	}

}

func sendRegistrationRequest(c net.Conn) error {
	fmt.Printf("Serving %s\n", c.RemoteAddr().String())

	regMsg := ngap.NASRegRequestMsg{SecHeader: 0,
		MobileId: ngap.MobileIdType{Mcc: 0, Mnc: 0, ProtecScheme: 0, HomeNetPki: 0, Msin: 0},
		SecCap:   ngap.SecCapType{EA: 1, IA: 1},
	}

	pdu, _ := ngap.EncodeMsg(ngap.NASRegRequest, &regMsg)
	err := io.SendMsg(c, pdu)
	return err
}

func main() {
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", 9930))
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
