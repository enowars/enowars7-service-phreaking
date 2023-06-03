package state

import (
	"context"
	"net"
	"phreaking/pkg/ngap"
	"strconv"
)

type Connection struct {
	net.Conn
	Ctx context.Context
}

type ContextKey string

const EA ContextKey = "EA"
const IA ContextKey = "IA"

const StateKey ContextKey = "STATE"

type State int

const (
	Init State = iota
	RegReqDone
	AuthResDone
	PduEstReqDone
)

type StateType string

func RecvEvent(msgtype ngap.MsgType) string {
	return "Recv" + strconv.Itoa(int(msgtype))
}

func SendEvent(msgtype ngap.MsgType) string {
	return "Send" + strconv.Itoa(int(msgtype))
}

// state for UE
const (
	Deregistered          StateType = "Deregistered"
	RegistrationInitiated StateType = "RegistrationInitiated"
	Authentication        StateType = "Authentication"
	SecurityMode          StateType = "SecurityMode"
	ContextSetup          StateType = "ContextSetup"
	Registered            StateType = "Registered"
)
