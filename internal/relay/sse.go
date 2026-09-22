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

// sseReader parses a text/event-stream body (the WHATWG algorithm) into
// events. It remembers the last event id and the retry hint across blocks,
// because the relay's closing block carries an `id:` and a `retry:` and no
// data (its plan, "Streams are bounded").
type sseReader struct {
	r      *bufio.Reader
	line   []byte
	onLine func()
	lastID string
	retry  time.Duration
}

// sseEvent is one dispatched event: a block that carried data.
type sseEvent struct {
	name string
	id   string
	data string
}

func newSSEReader(r io.Reader, onLine func()) *sseReader {
	return &sseReader{r: bufio.NewReaderSize(r, 64<<10), onLine: onLine}
}

// next returns the next event with data. Blocks without data — the relay's
// keepalive comments and its closing `id:`/`retry:` block — only update the
// reader's state. An io.EOF is a clean end; a block cut off by EOF is discarded.
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
				return sseEvent{name: name, id: s.lastID, data: string(data)}, nil
			}
			name, data, hasData = "", data[:0], false
			continue
		}
		if line[0] == ':' {
			continue
		}
		field, value, _ := bytes.Cut(line, []byte(":"))
		value = bytes.TrimPrefix(value, []byte(" "))
		switch string(field) {
		case "event":
			name = string(value)
		case "data":
			if hasData {
				data = append(data, '\n')
			}
			data = append(data, value...)
			hasData = true
		case "id":
			if !bytes.ContainsRune(value, 0) {
				s.lastID = string(value)
			}
		case "retry":
			if ms, err := strconv.Atoi(string(value)); err == nil && ms >= 0 {
				s.retry = time.Duration(ms) * time.Millisecond
			}
		}
	}
}

// readLine reads one line without its terminator, accumulating past the
// buffer size up to MaxSSELineBytes. The result aliases the reader's scratch
// space and is valid until the next call.
func (s *sseReader) readLine() ([]byte, error) {
	s.line = s.line[:0]
	for {
		chunk, err := s.r.ReadSlice('\n')
		s.line = append(s.line, chunk...)
		if len(s.line) > MaxSSELineBytes {
			return nil, fmt.Errorf("%w: sse line over %d bytes", ErrProtocol, MaxSSELineBytes)
		}
		switch {
		case err == nil:
			return bytes.TrimSuffix(bytes.TrimSuffix(s.line, []byte("\n")), []byte("\r")), nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case errors.Is(err, io.EOF) && len(s.line) > 0:
			// A final line without its newline still counts; the next call
			// sees a clean EOF.
			return bytes.TrimSuffix(s.line, []byte("\r")), nil
		default:
			return nil, err
		}
	}
}
