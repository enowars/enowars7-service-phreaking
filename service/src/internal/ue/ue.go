package ue

import (
	"fmt"

	"go.uber.org/zap"
)

type UE struct {
	Logger *zap.Logger
	state  StateType
	//MobileId ngap.MobileIdType
	//SecCap   ngap.SecCapType
	EaAlg       uint8
	IaAlg       uint8
	ActivePduId uint8
}

func NewUE(logger *zap.Logger) *UE {
	return &UE{Logger: logger, state: Deregistered}
}

func (u *UE) GetState(s StateType) StateType {
	return u.state
}

func (u *UE) ToState(s StateType) {
	fmt.Println("To state: ", s)
	u.state = s
}

func (u *UE) InState(s StateType) bool {
	return (u.state == s)
}

type StateType string

// state for UE
const (
	Deregistered          StateType = "Deregistered"
	RegistrationInitiated StateType = "RegistrationInitiated"
	Authentication        StateType = "Authentication"
	SecurityMode          StateType = "SecurityMode"
	ContextSetup          StateType = "ContextSetup"
	Registered            StateType = "Registered"
)
