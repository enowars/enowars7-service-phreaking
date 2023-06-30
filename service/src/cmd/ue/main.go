package main

import (
	"errors"
	"fmt"
	"net"
	"phreaking/internal/crypto"
	"phreaking/internal/io"
	"phreaking/internal/ue"
	"phreaking/internal/ue/pb"
	"phreaking/pkg/ngap"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

func handleConnection(logger *zap.Logger, c net.Conn) {
	log := logger.Sugar()
	log.Infof("Serving %s", c.RemoteAddr().String())

	timeout := time.NewTimer(time.Minute)
	defer func() {
		timeout.Stop()
		c.Close()
		log.Infof("Closed connection for remote: %s", c.RemoteAddr().String())
	}()

	u := *ue.NewUE(logger)

	err := sendRegistrationRequest(u, c)
	if err != nil {
		log.Error(err)
		return
	}

	u.ToState(ue.RegistrationInitiated)

	for {
		select {
		case <-timeout.C:
			log.Infof("handleConnection timeout for remote: %s", c.RemoteAddr().String())
			return
		default:
			buf, err := io.Recv(c)
			if err != nil {
				if !errors.Is(err, io.EOF) {
					log.Errorf("Error reading: %w", err)
				}
				return
			}

			var gmm ngap.GmmPacket
			err = ngap.DecodeMsg(buf, &gmm)
			if err != nil {
				log.Warnf("Cannot decode Gmm Header")
				return
			}

			msgbuf := gmm.Message

			if gmm.Security {
				err = crypto.CheckIntegrity(u.IaAlg, msgbuf, gmm.Mac)
				if err != nil {
					log.Error(err)
					return
				}

				msgbuf, err = crypto.Decrypt(u.EaAlg, msgbuf)
				if err != nil {
					log.Error(err)
					return
				}
			}

			msgType := gmm.MessageType

			switch {
			case msgType == ngap.NASAuthRequest && u.InState(ue.RegistrationInitiated):
				err := u.HandleNASAuthRequest(c, msgbuf)
				if err != nil {
					log.Errorf("Error NASAuthRequest: %w", err)
					return
				}
				u.ToState(ue.Authentication)
			case msgType == ngap.NASSecurityModeCommand && u.InState(ue.Authentication):
				err := u.HandleNASSecurityModeCommand(c, msgbuf)
				if err != nil {
					log.Errorf("Error NASSecurityModeCommand: %w", err)
					return
				}
				u.ToState(ue.SecurityMode)
			case msgType == ngap.PDUSessionEstAccept && u.InState(ue.SecurityMode):
				err := u.HandlePDUSessionEstAccept(c, msgbuf)
				if err != nil {
					log.Errorf("Error PDUSessionEstAccept: %w", err)
					return
				}
				u.ToState(ue.Registered)
			case msgType == ngap.PDURes && u.InState(ue.Registered):
				err := u.HandlePDURes(c, msgbuf)
				if err != nil {
					log.Errorf("Error PDURes: %w", err)
					return
				}
			default:
				log.Warnf("invalid message type (%d) for UE ", msgType)
			}
		}
	}

}

func sendRegistrationRequest(u ue.UE, c net.Conn) error {
	regMsg := ngap.NASRegRequestMsg{SecHeader: 0,
		MobileId: ngap.MobileIdType{Mcc: 0, Mnc: 0, ProtecScheme: 0, HomeNetPki: 0, Msin: 0},
		SecCap:   ngap.SecCapType{EA: 1, IA: 1},
	}

	msg, err := ngap.EncodeMsg(&regMsg)
	if err != nil {
		return err
	}

	gmm := ngap.GmmPacket{Security: false, Mac: [8]byte{}, MessageType: ngap.NASAuthRequest, Message: msg}
	return io.SendGmm(c, gmm)
}

func main() {
	logger := zap.Must(zap.NewDevelopment())
	defer logger.Sync()
	log := logger.Sugar()

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
			log.Fatalf("grpc failed to serve: %s", err)
		}
	}()

	l, err := net.Listen("tcp4", ":6060")
	if err != nil {
		log.Fatalf("tcp server failed to listen: %v", err)
		return
	}
	defer l.Close()

	for {
		c, err := l.Accept()
		if err != nil {
			log.Warnf("connection for listener failed: %v", err)
			return
		}
		go handleConnection(logger, c)
	}
}
