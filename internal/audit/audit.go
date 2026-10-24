// Package audit writes a hash-chained JSON Lines audit log.
//
// Each line is a JSON object whose last member is "hash": the hex SHA-256 of
// the line's bytes without that member (i.e. the object up to and excluding
// `,"hash":...`, closed with `}`). Every record also carries "prev", the
// previous record's hash, so deleting, reordering or editing any line breaks
// verification. Raw sensitive values are never written: findings carry a
// keyed HMAC of the value so repeated leaks can be correlated.
package audit

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// Finding is one detector hit as stored in the log.
type Finding struct {
	Direction string `json:"direction"` // request | response
	Location  string `json:"location"`  // e.g. "messages[2]" or "choices[0]"
	Kind      string `json:"kind"`
	Category  string `json:"category"`
	Action    string `json:"action"`
	Start     int    `json:"start"`
	End       int    `json:"end"`
	ValueHMAC string `json:"value_hmac"`
}

// Injection summarizes the injection scorer verdict.
type Injection struct {
	Score   float64  `json:"score"`
	Signals []string `json:"signals,omitempty"`
	Action  string   `json:"action"`
}

// Record is one audit entry (one gateway request).
type Record struct {
	Seq        uint64     `json:"seq"`
	Time       time.Time  `json:"time"`
	RequestID  string     `json:"request_id"`
	Key        string     `json:"key,omitempty"`
	Policy     string     `json:"policy,omitempty"`
	Model      string     `json:"model,omitempty"`
	Stream     bool       `json:"stream"`
	Decision   string     `json:"decision"`
	Reason     string     `json:"reason,omitempty"`
	Status     int        `json:"status"`
	Findings   []Finding  `json:"findings,omitempty"`
	Injection  *Injection `json:"injection,omitempty"`
	DurationMS float64    `json:"duration_ms"`
	UpstreamMS float64    `json:"upstream_ms,omitempty"`
	Prev       string     `json:"prev"`
}

// Decisions recorded in the log.
const (
	DecisionAllowed         = "allowed"
	DecisionRedacted        = "redacted"
	DecisionBlockedRequest  = "blocked_request"
	DecisionBlockedResponse = "blocked_response"
	DecisionRateLimited     = "rate_limited"
	DecisionUnauthorized    = "unauthorized"
	DecisionBadRequest      = "bad_request"
	DecisionUpstreamError   = "upstream_error"
)

const hashMember = `,"hash":"`

// genesis is the "prev" value of the first record.
const genesis = "0000000000000000000000000000000000000000000000000000000000000000"

// Log appends records to a writer, maintaining the hash chain.
type Log struct {
	mu   sync.Mutex
	w    io.Writer
	c    io.Closer
	prev string
	seq  uint64
	now  func() time.Time
}

// Open opens (or creates) the log file at path, verifying the existing chain
// and resuming it.
func Open(path string) (*Log, error) {
	var prev = genesis
	var seq uint64
	if f, err := os.Open(path); err == nil {
		n, last, verr := verify(f)
		_ = f.Close()
		if verr != nil {
			return nil, fmt.Errorf("audit log %s: existing chain invalid: %w", path, verr)
		}
		seq, prev = n, last
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	return &Log{w: f, c: f, prev: prev, seq: seq, now: time.Now}, nil
}

// New returns a log that writes to w starting a fresh chain.
func New(w io.Writer) *Log { return &Log{w: w, prev: genesis, now: time.Now} }

// Append assigns Seq, Time (if zero) and Prev, then writes the record.
func (l *Log) Append(r Record) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.seq++
	r.Seq = l.seq
	r.Prev = l.prev
	if r.Time.IsZero() {
		r.Time = l.now().UTC()
	}
	body, err := json.Marshal(r)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(body)
	h := hex.EncodeToString(sum[:])
	line := make([]byte, 0, len(body)+len(hashMember)+len(h)+3)
	line = append(line, body[:len(body)-1]...)
	line = append(line, hashMember...)
	line = append(line, h...)
	line = append(line, "\"}\n"...)
	if _, err := l.w.Write(line); err != nil {
		l.seq--
		return err
	}
	l.prev = h
	return nil
}

// Close closes the underlying file, if any.
func (l *Log) Close() error {
	if l.c == nil {
		return nil
	}
	return l.c.Close()
}

// Verify checks the chain in r and returns the number of valid records.
func Verify(r io.Reader) (int, error) {
	n, _, err := verify(r)
	return int(n), err
}

func verify(r io.Reader) (uint64, string, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 16<<20)
	prev := genesis
	var n uint64
	for sc.Scan() {
		line := sc.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		i := bytes.LastIndex(line, []byte(hashMember))
		if i < 0 || !bytes.HasSuffix(line, []byte(`"}`)) {
			return n, prev, fmt.Errorf("record %d: missing hash", n+1)
		}
		got := string(line[i+len(hashMember) : len(line)-2])
		body := append(append([]byte{}, line[:i]...), '}')
		sum := sha256.Sum256(body)
		if hex.EncodeToString(sum[:]) != got {
			return n, prev, fmt.Errorf("record %d: hash mismatch (record was modified)", n+1)
		}
		var hdr struct {
			Seq  uint64 `json:"seq"`
			Prev string `json:"prev"`
		}
		if err := json.Unmarshal(body, &hdr); err != nil {
			return n, prev, fmt.Errorf("record %d: %w", n+1, err)
		}
		if hdr.Prev != prev {
			return n, prev, fmt.Errorf("record %d: chain broken (record removed or reordered)", n+1)
		}
		if hdr.Seq != n+1 {
			return n, prev, fmt.Errorf("record %d: sequence %d out of order", n+1, hdr.Seq)
		}
		prev = got
		n++
	}
	return n, prev, sc.Err()
}

// Hasher computes keyed digests of sensitive values for correlation.
type Hasher struct{ key []byte }

// NewHasher uses key, or a random per-process key when key is empty (digests
// are then only comparable within one process lifetime).
func NewHasher(key []byte) (*Hasher, bool) {
	if len(key) > 0 {
		return &Hasher{key: key}, true
	}
	k := make([]byte, 32)
	_, _ = rand.Read(k) // crypto/rand.Read never returns an error
	return &Hasher{key: k}, false
}

// Digest returns a truncated HMAC-SHA256 of kind and value.
func (h *Hasher) Digest(kind, value string) string {
	m := hmac.New(sha256.New, h.key)
	m.Write([]byte(kind))
	m.Write([]byte{0})
	m.Write([]byte(value))
	return hex.EncodeToString(m.Sum(nil)[:12])
}
