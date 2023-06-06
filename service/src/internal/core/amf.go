package core

import (
	"phreaking/pkg/ngap"
)

type Amf struct {
	AmfName     string
	GuamPlmn    uint32
	AmfRegionId uint16
	AmfSetId    uint32
	AmfPtr      uint32
	AmfCap      uint8
}

type AmfGNB struct {
	GranId uint32
	Tac    uint32
	Plmn   uint32
	AmfUEs map[ngap.AmfUeNgapIdType]AmfUE
}

type AmfUE struct {
	RanUeNgapId   uint32
	AmfUeNgapId   ngap.AmfUeNgapIdType
	SecCap        ngap.SecCapType
	EaAlg         uint8
	IaAlg         uint8
	Authenticated bool
	RandToken     []byte
	Locations     []string
}
