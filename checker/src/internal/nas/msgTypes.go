package nas

import "github.com/gofrs/uuid"

type NasMsgType int
type AmfUeNgapIdType uuid.UUID

const (
	NASRegRequest NasMsgType = iota
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
	PDUReq
	PDURes
	PDUSessionResourceReleaseCommand
	// Location
	LocationUpdate
	LocationReportRequest
	LocationReportResponse
)

type GmmHeader struct {
	// MobileId MobileIdType
	Security    bool
	Mac         [8]byte
	MessageType NasMsgType
	Message     []byte
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
	AuthRand  []byte
	Auth      []byte
}

type NASAuthResponseMsg struct {
	SecHeader uint8
	Res       []byte
}

type NASSecurityModeCommandMsg struct {
	SecHeader uint8
	EaAlg     uint8
	IaAlg     uint8
	SecCap    SecCapType
}

type PDUSessionEstRequestMsg struct {
	PduSesId   uint8
	PduSesType uint8
	// add integrity protetion maximum data rate
}

type PDUSessionEstAcceptMsg struct {
	PduSesId uint8
	// PduAddress []byte
	// SSC
	// QoS
	// AMBR
}

type LocationUpdateMsg struct {
	Location string
}

type LocationReportRequestMsg struct {
	AmfUeNgapId AmfUeNgapIdType
	RanUeNgapId uint32
}

type LocationReportResponseMsg struct {
	AmfUeNgapId AmfUeNgapIdType
	RanUeNgapId uint32
	Locations   []string
}

type PDUReqMsg struct {
	PduSesId uint8
	Request  []byte
}
type PDUResMsg struct {
	PduSesId uint8
	Response []byte
}