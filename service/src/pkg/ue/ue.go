package ue

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
