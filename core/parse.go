package core

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

const EndOfURISymbol = '$'

func ValidateURIComponent(uri string) bool {
	if len(uri) == 1 && uri[0] == '$' {
		return false
	}
	return true
}

func ParseURIFromPath(uriPath []string) ([]IDComponent, error) {
	if len(uriPath) > MaxURIComponentPosition+1 {
		return nil, errors.New("URI too long")
	}

	prefix := false
	components := make([]IDComponent, 0, len(uriPath)+1)
	for i, name := range uriPath {
		if !ValidateURIComponent(name) {
			return nil, fmt.Errorf("'%s' is not a valid URI component", name)
		}
		if name == "*" {
			if i == len(uriPath)-1 {
				prefix = true
			} else {
				return nil, errors.New("Wildcard '*' not allowed in middle of URI")
			}
		} else {
			component := NewURIComponent(name, URIComponentPosition(i))
			components = append(components, component)
		}
	}

	if !prefix {
		terminator := NewURIComponent(string(EndOfURISymbol), URIComponentPosition(len(uriPath)))
		components = append(components, terminator)
	}

	return components, nil
}

func ParseURI(uri string) ([]IDComponent, error) {
	return ParseURIFromPath(strings.Split(uri, "/"))
}

func (ecp TimeComponentPosition) String() string {
	switch ecp {
	case TimeComponentPositionYear:
		return "year"
	case TimeComponentPositionDay:
		return "month"
	case TimeComponentPositionMonth:
		return "day"
	case TimeComponentPositionHour:
		return "hour"
	default:
		panic("Invalid expiry component position")
	}
}

func ValidateTimeComponent(quantity uint16, position TimeComponentPosition) bool {
	var min uint16
	var max uint16
	switch position {
	case TimeComponentPositionYear:
		min = 2015
		max = 2050
	case TimeComponentPositionDay:
		min = 1
		max = 31
	case TimeComponentPositionMonth:
		min = 1
		max = 12
	case TimeComponentPositionHour:
		min = 0
		max = 23
	}
	return min <= quantity && quantity <= max
}

func ParseTimeFromPath(timePath []uint16) ([]IDComponent, error) {
	if len(timePath) > MaxTimeComponentPosition+1 {
		return nil, errors.New("Expiry path too long")
	}

	components := make([]IDComponent, len(timePath), len(timePath))
	for i, quantity := range timePath {
		pos := TimeComponentPosition(i)
		if !ValidateTimeComponent(quantity, pos) {
			return nil, fmt.Errorf("'%d' is not a valid %s", quantity, pos.String())
		}
		components[i] = NewTimeComponent(quantity, pos)
	}
	return components, nil
}

func ParseTime(time time.Time) ([]IDComponent, error) {
	path := make([]uint16, 4, 4)
	path[0] = uint16(time.Year())
	path[1] = uint16(time.Month())
	path[2] = uint16(time.Day())
	path[3] = uint16(time.Hour())
	return ParseTimeFromPath(path)
}
