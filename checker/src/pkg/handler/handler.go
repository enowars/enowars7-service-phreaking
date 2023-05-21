package handler

import (
	"context"
	"errors"
	"log"

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

func (h *Handler) getFlagPdu(ctx context.Context, message *enochecker.TaskMessage) error {
	/*
		err = h.sendMessageAndCheckResponse(ctx, sessionIO, joinCmd, message.Flag)
		if err != nil {
			h.log.Error(err)
			return enochecker.ErrFlagNotFound
		}
	*/
	return nil
}

func (h *Handler) GetFlag(ctx context.Context, message *enochecker.TaskMessage) error {
	switch message.VariantId {
	case 0:
		return h.getFlagPdu(ctx, message)
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
