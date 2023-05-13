package ngap

type msgType int

const (
	NGSetupRequest msgType = iota
	NGSetupResponse
	NGSetupFailure
	InitUERegRequest
	NASIdRequest
	NASIdResponse
	NASAuthRequest
	NASAuthResponse
	NASSecurityModeCommand
	NASSecurityModeComplete
	InitialContextSetupRequestRegAccept
	UECapInfoIndication
	InitialContextSetupResponse
	RegisterComplete
	PDUSessionResourceSetupRequest
	PDUSessionResourceSetupResponse
	PDUSessionResourceReleaseCommand
)

/*
type baseMsg struct {
	Type msgType
}
*/

type NGSetupRequestMsg struct {
	//	baseMsg
	GRANid int32
	Tac    int32
	Plmn   int32
}

/*
func (msg NGSetupRequestMsg) isCool() bool {
	return (msg.Tac == 69)
}
*/
