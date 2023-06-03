package ue

type UE struct {
	state StateType
	//MobileId ngap.MobileIdType
	//SecCap   ngap.SecCapType
	EaAlg uint8
	IaAlg uint8
}

func NewUE() *UE {
	return &UE{state: Deregistered}
}

func (u *UE) GetState(s StateType) StateType {
	return u.state
}

func (u *UE) ToState(s StateType) {
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
