package ngap

type MsgType int

const (
	NGSetupRequest MsgType = iota
	NGSetupResponse
	NGSetupFailure
	InitUEMessage
	NASRegRequest
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
	GranId uint32
	Tac    uint32
	Plmn   uint32
}

type NGSetupResponseMsg struct {
	AmfName     string
	GuamPlmn    uint32
	AmfRegionId uint16
	AmfSetId    uint32
	AmfPtr      uint32
	AmfCap      uint8
	Plmn        uint32
}

type InitUEMessageMsg struct {
	NasPdu      []byte
	RanUeNgapId uint32
	// Location
}

type MobileIdType struct {
	// SupiFormat uint8
	// IdType
	Mcc uint8
	Mnc uint8
	// Routing indicator
	ProtecScheme uint8
	HomeNetPki   uint8
	Msin         uint
}

type SecCapType struct {
	// 	8  |  7  | .. |  1
	// EA0 | EA1 | .. | EA7
	EA uint8
	// 	8  |  7  | .. |  1
	// IA0 | IA1 | .. | IA7
	IA uint8
}

type NASRegRequestMsg struct {
	// Extended protocol discriminator
	SecHeader uint8
	// 5GS registration type
	// ngKsi
	MobileId MobileIdType
	SecCap   SecCapType
}

/*
func (msg NGSetupRequestMsg) isCool() bool {
	return (msg.Tac == 69)
}
*/
