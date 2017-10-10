package core

import (
	"encoding/binary"
	"math"
	"math/big"
	"strconv"
	"strings"

	"github.com/samkumar/hibe"
)

/* ID Component Interface */

type IDComponentType int

const (
	URIComponentType IDComponentType = iota
	TimeComponentType
)

type IDComponent interface {
	Type() IDComponentType
	Representation() []byte
	String() string
}

/* URI Component */

const MaxURIComponentPosition = math.MaxUint8

type URIComponentPosition uint8

type URIComponent []byte

func NewURIComponent(name string, position URIComponentPosition) URIComponent {
	uclength := 1 + len(name)
	uc := make([]byte, uclength, uclength)
	uc[0] = byte(position)
	copy(uc[1:], name)
	return uc
}

func (uc URIComponent) Type() IDComponentType {
	return URIComponentType
}

func (uc URIComponent) Representation() []byte {
	return uc
}

func (uc URIComponent) String() string {
	return uc.Name()
}

func (uc URIComponent) Name() string {
	return string(uc[1:])
}

func (uc URIComponent) Position() URIComponentPosition {
	return URIComponentPosition(uc[0])
}

/* Time Component */

const MaxTimeComponentPosition = 3

type TimeComponentPosition uint8

const (
	TimeComponentPositionYear TimeComponentPosition = iota
	TimeComponentPositionMonth
	TimeComponentPositionDay
	TimeComponentPositionHour
)

type TimeComponent []byte

func NewTimeComponent(quantity uint16, position TimeComponentPosition) TimeComponent {
	ec := []byte{uint8(position), 0, 0}
	binary.LittleEndian.PutUint16(ec[1:3], quantity)
	return ec
}

func (ec TimeComponent) Type() IDComponentType {
	return TimeComponentType
}

func (ec TimeComponent) Representation() []byte {
	return ec
}

func (ec TimeComponent) String() string {
	return strconv.FormatInt(int64(ec.Quantity()), 10)
}

func (ec TimeComponent) Quantity() uint16 {
	return binary.LittleEndian.Uint16(ec[1:3])
}

func (ec TimeComponent) Position() TimeComponentPosition {
	return TimeComponentPosition(ec[0])
}

/* ID */

type ID []IDComponent

func (id ID) HashToZp() []*big.Int {
	hashed := make([]*big.Int, len(id), len(id))
	for i := 0; i != len(id); i++ {
		hashed[i] = hibe.HashToZp(id[i].Representation())
	}
	return hashed
}

func (id ID) String() string {
	components := make([]string, len(id), len(id))
	for i := 0; i != len(components); i++ {
		components[i] = id[i].String()
	}
	return strings.Join(components, "/")
}
