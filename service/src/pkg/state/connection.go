package state

import (
	"context"
	"net"
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
)
