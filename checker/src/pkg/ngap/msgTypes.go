package ngap

type MsgType int

const (
	// Interface Management Messages
	NGSetupRequest MsgType = iota
	NGSetupResponse
	NGSetupFailure
	// NAS Transport
	InitUEMessage
	DownNASTrans
	UpNASTrans
	// NAS-PDU (GMMM)
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
	PDUSessionEstRequest
	PDUSessionEstAccept
	PDUSessionResourceReleaseCommand
	LocationUpdate
	LocationReportRequest
	LocationReportResponse
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
	RanUeNgapId uint32
	NasPdu      []byte
	// Location
}

type DownNASTransMsg struct {
	AmfUeNgapId uint32
	RanUeNgapId uint32
	NasPdu      []byte
}

type UpNASTransMsg struct {
	AmfUeNgapId uint32
	RanUeNgapId uint32
	NasPdu      []byte
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

type NASAuthRequestMsg struct {
	SecHeader uint8
	Rand      []byte
}

type NASAuthResponseMsg struct {
	SecHeader uint8
	Res       []byte
}

type NASSecurityModeCommandMsg struct {
	SecHeader uint8
	// TODO: encode more efficently
	EaAlg  uint8
	IaAlg  uint8
	SecCap SecCapType
}

type PDUSessionEstRequestMsg struct {
	PduSesId uint8
	// 0 = IPv4, 1 = IPv6, 2 = Flag ;)
	PduSesType uint8
	// add integrity protetion maximum data rate
}

type PDUSessionEstAcceptMsg struct {
	PduSesId   uint8
	PduAddress []byte
	// SSC
	// QoS
	// AMBR
}

type LocationUpdateMsg struct {
	Location string
}

type LocationReportRequestMsg struct {
	AmfUeNgapId uint32
	RanUeNgapId uint32
}

type LocationReportResponseMsg struct {
	AmfUeNgapId uint32
	RanUeNgapId uint32
	Locations   []string
}
