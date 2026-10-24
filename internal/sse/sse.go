// Package sse reads and writes Server-Sent Events (the WHATWG event-stream
// format used by OpenAI-compatible streaming APIs).
package sse

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"strings"
)

// Event is one dispatched event. Comment lines are ignored.
type Event struct {
	Name string // "event:" field; empty means "message"
	Data string // "data:" lines joined with "\n"
	ID   string
}

// ErrEventTooLarge is returned when an event exceeds the reader's limit.
var ErrEventTooLarge = errors.New("sse: event exceeds size limit")

// Reader parses an event stream. Lines may end in "\n", "\r\n" or "\r", and
// the underlying reader may split bytes anywhere (including inside a line).
type Reader struct {
	br      *bufio.Reader
	max     int
	pending bool // a lone '\r' was consumed; swallow a following '\n'
}

// NewReader returns a Reader that rejects events larger than maxEvent bytes.
func NewReader(r io.Reader, maxEvent int) *Reader {
	return &Reader{br: bufio.NewReaderSize(r, 32*1024), max: maxEvent}
}

// Next returns the next event. At end of input it returns io.EOF; an
// unterminated trailing event is discarded, as the specification requires.
func (r *Reader) Next() (Event, error) {
	var ev Event
	var data []string
	size := 0
	have := false
	for {
		line, err := r.readLine()
		if err != nil {
			return Event{}, err
		}
		if line == "" {
			if !have {
				continue
			}
			ev.Data = strings.Join(data, "\n")
			return ev, nil
		}
		size += len(line)
		if size > r.max {
			return Event{}, ErrEventTooLarge
		}
		if line[0] == ':' {
			continue
		}
		field, value, _ := strings.Cut(line, ":")
		value = strings.TrimPrefix(value, " ")
		switch field {
		case "data":
			data = append(data, value)
			have = true
		case "event":
			ev.Name = value
			have = true
		case "id":
			ev.ID = value
			have = true
		}
	}
}

// readLine returns one line without its terminator.
func (r *Reader) readLine() (string, error) {
	var buf bytes.Buffer
	for {
		b, err := r.br.ReadByte()
		if err != nil {
			if err == io.EOF && buf.Len() > 0 {
				return "", io.ErrUnexpectedEOF
			}
			return "", err
		}
		if r.pending {
			r.pending = false
			if b == '\n' {
				continue
			}
		}
		switch b {
		case '\n':
			return buf.String(), nil
		case '\r':
			r.pending = true
			return buf.String(), nil
		}
		if buf.Len() >= r.max {
			return "", ErrEventTooLarge
		}
		buf.WriteByte(b)
	}
}

// Write encodes ev in canonical form ("event:", "id:", one "data:" per line,
// blank line).
func Write(w io.Writer, ev Event) error {
	var b strings.Builder
	if ev.Name != "" {
		b.WriteString("event: " + ev.Name + "\n")
	}
	if ev.ID != "" {
		b.WriteString("id: " + ev.ID + "\n")
	}
	for _, line := range strings.Split(ev.Data, "\n") {
		b.WriteString("data: " + line + "\n")
	}
	b.WriteString("\n")
	_, err := io.WriteString(w, b.String())
	return err
}
