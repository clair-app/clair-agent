package relay

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strconv"
	"time"
)

// maxSSEEventName caps an `event:` name; the relay's are single words.
const maxSSEEventName = 64

// sseReader parses a text/event-stream body (the WHATWG algorithm) into
// events. It remembers the last event id and the retry hint across blocks,
// because the relay's closing block carries an `id:` and a `retry:` and no
// data (its plan, "Streams are bounded").
type sseReader struct {
	sc     *bufio.Scanner
	onLine func()
	// skipLF is set after a line ended in a bare CR: a LF that follows is
	// the second half of a CRLF, not an empty line.
	skipLF bool
	lastID string
	retry  time.Duration
}

// sseEvent is one dispatched event: a block that carried data. Its data is
// the reader's own copy, so a caller may keep or decode it without copying.
type sseEvent struct {
	name string
	id   string
	data []byte
}

func newSSEReader(r io.Reader, onLine func()) *sseReader {
	s := &sseReader{onLine: onLine}
	s.sc = bufio.NewScanner(r)
	s.sc.Buffer(make([]byte, 0, 64<<10), MaxSSELineBytes)
	s.sc.Split(s.splitLine)
	return s
}

// next returns the next event with data. Blocks without data — the relay's
// keepalive comments and its closing `id:`/`retry:` block — only update the
// reader's state. An io.EOF is a clean end; a block cut off by EOF is
// discarded, and so is a final line without its line end.
func (s *sseReader) next() (sseEvent, error) {
	var (
		name    string
		data    []byte
		hasData bool
	)
	for {
		line, err := s.readLine()
		if err != nil {
			return sseEvent{}, err
		}
		if s.onLine != nil {
			s.onLine()
		}
		if len(line) == 0 {
			if hasData {
				return sseEvent{name: name, id: s.lastID, data: data}, nil
			}
			name, data, hasData = "", nil, false
			continue
		}
		if line[0] == ':' {
			continue
		}
		field, value, _ := bytes.Cut(line, []byte(":"))
		value = bytes.TrimPrefix(value, []byte(" "))
		switch string(field) {
		case "event":
			if len(value) > maxSSEEventName {
				return sseEvent{}, fmt.Errorf("%w: sse event name over %d bytes", ErrProtocol, maxSSEEventName)
			}
			name = string(value)
		case "data":
			// The cap is on the event, not the line: many short lines join
			// into one event, and each join is a copy (AG-4).
			size := len(data) + len(value)
			if hasData {
				size++
			}
			if size > MaxSSEEventBytes {
				return sseEvent{}, fmt.Errorf("%w: sse event over %d bytes", ErrProtocol, MaxSSEEventBytes)
			}
			if hasData {
				data = append(data, '\n')
			}
			data = append(data, value...)
			hasData = true
		case "id":
			// The id is the mailbox cursor we resume and ack from: anything
			// but a decimal the relay could have minted is dropped, so one bad
			// id cannot break every later reconnect (AG-18).
			if len(value) == 0 || isCursor(value) {
				s.lastID = string(value)
			}
		case "retry":
			if ms, err := strconv.Atoi(string(value)); err == nil && ms >= 0 {
				s.retry = time.Duration(ms) * time.Millisecond
			}
		}
	}
}

// readLine returns the next complete line without its terminator. The
// result aliases the scanner's buffer and is valid until the next call.
func (s *sseReader) readLine() ([]byte, error) {
	if s.sc.Scan() {
		return s.sc.Bytes(), nil
	}
	err := s.sc.Err()
	switch {
	case err == nil:
		return nil, io.EOF
	case errors.Is(err, bufio.ErrTooLong):
		return nil, fmt.Errorf("%w: sse line over %d bytes", ErrProtocol, MaxSSELineBytes)
	default:
		return nil, err
	}
}

// splitLine splits on CRLF, LF or a bare CR, as the event-stream grammar
// has it. It never waits for the byte after a CR, so a stream that ends its
// lines with CR alone is not held up by its own framing. At EOF a partial
// line is dropped rather than returned.
func (s *sseReader) splitLine(data []byte, _ bool) (advance int, token []byte, err error) {
	if s.skipLF && len(data) > 0 {
		s.skipLF = false
		if data[0] == '\n' {
			return 1, nil, nil
		}
	}
	i := bytes.IndexAny(data, "\r\n")
	if i < 0 {
		return 0, nil, nil
	}
	if data[i] == '\r' {
		if i+1 < len(data) {
			if data[i+1] == '\n' {
				return i + 2, data[:i], nil
			}
		} else {
			s.skipLF = true
		}
	}
	return i + 1, data[:i], nil
}

// isCursor reports whether b is a mailbox cursor: a non-negative decimal
// that fits an int64, as the relay's bigint identity column mints them.
func isCursor(b []byte) bool {
	if len(b) == 0 || len(b) > 19 {
		return false
	}
	for _, c := range b {
		if c < '0' || c > '9' {
			return false
		}
	}
	_, err := strconv.ParseInt(string(b), 10, 64)
	return err == nil
}
