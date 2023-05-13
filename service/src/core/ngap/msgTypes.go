package ngap

const (
	NGSetupRequest int = iota
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

type NGSetupRequestMsg struct {
	GRANid int32
	Tac    int32
	Plmn   int32
}
