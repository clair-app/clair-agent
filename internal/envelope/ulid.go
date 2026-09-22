package envelope

import (
	"encoding/binary"
	"fmt"
	"io"
	"time"
)

// crockford is the ULID alphabet: base32 without I, L, O and U.
const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// maxTimestamp is the largest millisecond timestamp 48 bits can hold.
const maxTimestamp = 1<<48 - 1

// NewID mints a ULID (§5.4): 48 bits of millisecond timestamp followed by 80
// random bits, encoded as 26 characters of Crockford base32. The clock and the
// entropy are parameters so a test can pin the result.
func NewID(now time.Time, entropy io.Reader) (string, error) {
	ms := now.UnixMilli()
	if ms < 0 || ms > maxTimestamp {
		return "", fmt.Errorf("envelope: time %v is outside the ULID range", now)
	}
	var raw [16]byte
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(ms))
	copy(raw[:6], ts[2:])
	if _, err := io.ReadFull(entropy, raw[6:]); err != nil {
		return "", fmt.Errorf("envelope: read id entropy: %w", err)
	}
	// Big-endian base32 from the low end: 128 bits are 25 characters plus a
	// 3-bit remainder, which becomes the first character.
	var out [IDLength]byte
	pos := IDLength - 1
	var acc uint64
	bits := 0
	for i := len(raw) - 1; i >= 0; i-- {
		acc |= uint64(raw[i]) << bits
		bits += 8
		for bits >= 5 {
			out[pos] = crockford[acc&31]
			pos--
			acc >>= 5
			bits -= 5
		}
	}
	out[pos] = crockford[acc&31]
	return string(out[:]), nil
}

// ValidID reports whether id has the shape the relay validates,
// `^[0-9A-HJKMNP-TV-Z]{26}$`.
func ValidID(id string) bool {
	if len(id) != IDLength {
		return false
	}
	for i := range len(id) {
		c := id[i]
		switch {
		case '0' <= c && c <= '9':
		case 'A' <= c && c <= 'H':
		case c == 'J' || c == 'K' || c == 'M' || c == 'N':
		case 'P' <= c && c <= 'T':
		case 'V' <= c && c <= 'Z':
		default:
			return false
		}
	}
	return true
}
