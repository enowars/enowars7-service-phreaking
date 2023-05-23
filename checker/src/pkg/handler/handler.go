package handler

import (
	"context"
	"errors"
	"log"
	"net"
	"time"

	"checker/pkg/crypto"
	"checker/pkg/ngap"
	"checker/pkg/pb"

	"github.com/enowars/enochecker-go"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

var serviceInfo = &enochecker.InfoMessage{
	ServiceName:     "phreaking",
	FlagVariants:    1,
	NoiseVariants:   1,
	HavocVariants:   1,
	ExploitVariants: 1,
}

var ErrVariantNotFound = errors.New("variant not found")

type Handler struct {
	log *logrus.Logger
}

func New(log *logrus.Logger) *Handler {
	return &Handler{
		log: log,
	}
}

func (h *Handler) PutFlag(ctx context.Context, message *enochecker.TaskMessage) (*enochecker.HandlerInfo, error) {
	var conn *grpc.ClientConn
	conn, err := grpc.Dial(":9000", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("did not connect: %s", err)
	}
	defer conn.Close()

	c := pb.NewLocationClient(conn)

	md := metadata.Pairs("auth", "password")
	ctx_grpc := metadata.NewOutgoingContext(context.Background(), md)
	response, err := c.UpdateLocation(ctx_grpc, &pb.Loc{Position: message.Flag})
	if err != nil {
		return nil, err
	}
	log.Printf("Response from server: %s", response)
	return nil, nil
}

func (h *Handler) getFlagLocation(ctx context.Context, message *enochecker.TaskMessage) error {
	coretcpAddr, err := net.ResolveTCPAddr("tcp", "localhost:3399")
	if err != nil {
		return err
	}

	coreConn, err := net.DialTCP("tcp", nil, coretcpAddr)
	if err != nil {
		return err
	}

	uetcpAddr, err := net.ResolveTCPAddr("tcp", "localhost:3000")
	if err != nil {
		return err
	}

	ueConn, err := net.DialTCP("tcp", nil, uetcpAddr)
	if err != nil {
		return err
	}

	reply := make([]byte, 512)
	_, err = ueConn.Read(reply)
	if err != nil {
		return err
	}

	initUeMsg := ngap.InitUEMessageMsg{NasPdu: reply, RanUeNgapId: 1}
	buf, _ := ngap.EncodeMsg(ngap.InitUEMessage, &initUeMsg)

	_, err = coreConn.Write(buf)
	if err != nil {
		return err
	}

	time.Sleep(500 * time.Millisecond)
	reply = make([]byte, 512)

	// AuthReq
	_, err = coreConn.Read(reply)
	if err != nil {
		return err
	}

	var down ngap.DownNASTransMsg
	err = ngap.DecodeMsg(reply[1:], &down)
	if err != nil {
		return errors.New("cannot decode")
	}

	_, err = ueConn.Write(down.NasPdu)
	if err != nil {
		return err
	}

	time.Sleep(500 * time.Millisecond)
	reply = make([]byte, 512)

	_, err = ueConn.Read(reply)
	if err != nil {
		return err
	}

	// AuthRes
	up := ngap.UpNASTransMsg{NasPdu: reply, RanUeNgapId: 1, AmfUeNgapId: 1}
	buf, _ = ngap.EncodeMsg(ngap.UpNASTrans, &up)

	_, err = coreConn.Write(buf)
	if err != nil {
		return err
	}

	reply = make([]byte, 512)
	// SecModeCmd
	_, err = coreConn.Read(reply)
	if err != nil {
		return err
	}

	logrus.Println(reply)
	down = ngap.DownNASTransMsg{}

	err = ngap.DecodeMsg(reply[1:], &down)
	if err != nil {
		return errors.New("cannot decode")
	}

	_, err = ueConn.Write(down.NasPdu)
	if err != nil {
		return err
	}

	time.Sleep(500 * time.Millisecond)
	reply = make([]byte, 512)

	// LocationUpdate
	_, err = ueConn.Read(reply)
	if err != nil {
		return err
	}

	logrus.Println(reply)

	for i, b := range reply {
		if (b == 0x00) && (reply[i+1] == 0x00) && (reply[i+2] == 0x00) {
			reply = reply[:i]
			break
		}
	}

	dec := crypto.DecryptAES(reply[9:])

	var loc ngap.LocationUpdateMsg
	err = ngap.DecodeMsg(dec, &loc)
	if err != nil {
		return errors.New("cannot decode")
	}
	if loc.Location == message.Flag {
		return nil
	}
	return enochecker.ErrFlagNotFound

	/*

		var authReq ngap.NASAuthRequestMsg
		err = ngap.DecodeMsg(down.NasPdu[1:], &authReq)
		if err != nil {
			return errors.New("cannot decode")
		}
		_, err = coreConn.Write(down.NasPdu)
		if err != nil {
			return err
		}

		res := crypto.IA2(authReq.Rand)

		authRes := ngap.NASAuthResponseMsg{SecHeader: 0, Res: res}
		pdu, _ = ngap.EncodeMsg(ngap.NASAuthResponse, &authRes)

		up := ngap.UpNASTransMsg{NasPdu: pdu, RanUeNgapId: 1}
		buf, _ = ngap.EncodeMsg(ngap.UpNASTrans, &up)

		_, err = conn.Write(buf)
		if err != nil {
			return err
		}

		time.Sleep(500 * time.Millisecond)

		locreq := ngap.LocationReportRequestMsg{AmfUeNgapId: 1, RanUeNgapId: 1}
		buf, err = ngap.EncodeMsg(ngap.LocationReportRequest, &locreq)
		if err != nil {
			return err
		}

		_, err = conn.Write(buf)
		if err != nil {
			return err
		}

		reply = make([]byte, 1024)

		_, err = conn.Read(reply)
		if err != nil {
			return err
		}

		var report ngap.LocationReportResponseMsg
		err = ngap.DecodeMsg(reply[1:], &report)
		if err != nil {
			return errors.New("cannot decode")
		}

		logrus.Println(report.Locations)

		for _, s := range report.Locations {
			if s == message.Flag {
				return nil
			}
		}

		return enochecker.ErrFlagNotFound
	*/
}

func (h *Handler) GetFlag(ctx context.Context, message *enochecker.TaskMessage) error {
	switch message.VariantId {
	case 0:
		return h.getFlagLocation(ctx, message)
	}

	return ErrVariantNotFound
}

func (h *Handler) GetServiceInfo() *enochecker.InfoMessage {
	return serviceInfo
}

func (h *Handler) Exploit(ctx context.Context, message *enochecker.TaskMessage) (*enochecker.HandlerInfo, error) {
	return nil, nil
}

func (h *Handler) PutNoise(ctx context.Context, message *enochecker.TaskMessage) error {
	return nil
}

func (h *Handler) GetNoise(ctx context.Context, message *enochecker.TaskMessage) error {
	return nil
}

func (h *Handler) Havoc(ctx context.Context, message *enochecker.TaskMessage) error {
	return nil
}
