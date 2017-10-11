package core

import (
	"encoding/binary"
	"math"
	"math/big"
	"strconv"
	"strings"
	"time"

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

	// These functions are useful if you don't want to use a type assertion
	// but know what the underlying type is.
	Name() string
	Quantity() uint16
}

/* URI Component */

type URIComponentPosition uint8

const MaxURIComponentPosition = math.MaxUint8

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

func (uc URIComponent) Quantity() uint16 {
	panic("Quantity() is not a valid method for a URI component")
}

func (uc URIComponent) Position() URIComponentPosition {
	return URIComponentPosition(uc[0])
}

/* Time Component */

type TimeComponentPosition uint8

const MaxTimeComponentPosition = 3

const (
	TimeComponentPositionYear TimeComponentPosition = iota
	TimeComponentPositionMonth
	TimeComponentPositionDay
	TimeComponentPositionHour
)

const MinYear = 2015
const MaxYear = 2050

const MinMonth = 1
const MaxMonth = 12

const MinDay = 1
const MaxDay = 31
const MaxDayShortMonth = 30
const MaxDayFebruary = 28
const MaxDayFebruaryLeapYear = 29

const MinHour = 0
const MaxHour = 23

func TimeComponentBounds(prefix ID, position TimeComponentPosition) (uint16, uint16) {
	switch position {
	case TimeComponentPositionYear:
		return MinYear, MaxYear
	case TimeComponentPositionMonth:
		return MinMonth, MaxMonth
	case TimeComponentPositionDay:
		switch time.Month(prefix[TimeComponentPositionMonth].Quantity()) {
		case time.January:
			fallthrough
		case time.March:
			fallthrough
		case time.May:
			fallthrough
		case time.July:
			fallthrough
		case time.August:
			fallthrough
		case time.October:
			fallthrough
		case time.December:
			return MinDay, MaxDay
		case time.April:
			fallthrough
		case time.June:
			fallthrough
		case time.September:
			fallthrough
		case time.November:
			return MinDay, MaxDayShortMonth
		case time.February:
			year := prefix[TimeComponentPositionYear].Quantity()
			if year%4 == 0 && (year%100 != 0 || (year%400 == 0)) {
				return MinDay, MaxDayFebruaryLeapYear
			}
			return MinDay, MaxDayFebruary
		}
		return MinDay, MaxDay
	case TimeComponentPositionHour:
		return MinHour, MaxHour
	default:
		panic("Invalid position")
	}
}

type TimeComponent []byte

func NewTimeComponent(quantity uint16, position TimeComponentPosition) TimeComponent {
	tc := []byte{uint8(position), 0, 0}
	binary.LittleEndian.PutUint16(tc[1:3], quantity)
	return tc
}

func (tc TimeComponent) Type() IDComponentType {
	return TimeComponentType
}

func (tc TimeComponent) Representation() []byte {
	return tc
}

func (tc TimeComponent) String() string {
	return strconv.FormatInt(int64(tc.Quantity()), 10)
}

func (tc TimeComponent) Name() string {
	panic("Name() is not a valid method for a Time component")
}

func (tc TimeComponent) Quantity() uint16 {
	return binary.LittleEndian.Uint16(tc[1:3])
}

func (tc TimeComponent) Position() TimeComponentPosition {
	return TimeComponentPosition(tc[0])
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
