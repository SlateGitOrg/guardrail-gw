// Package policy maps detector findings and injection scores to actions.
package policy

import (
	"fmt"
	"strings"

	"github.com/archit2501/guardrail-gw/internal/detect"
)

// Action is what the gateway does with a finding. Actions are ordered by
// severity so that the strongest action wins when findings overlap.
type Action int

// Actions in increasing severity.
const (
	Allow  Action = iota // ignore: the detector is not even run
	Log                  // record in the audit log, pass text through
	Redact               // replace the span with a typed placeholder
	Block                // reject the request / terminate the stream
)

var actionNames = [...]string{"allow", "log", "redact", "block"}

func (a Action) String() string {
	if a < Allow || a > Block {
		return fmt.Sprintf("action(%d)", int(a))
	}
	return actionNames[a]
}

// ParseAction parses "allow", "log", "redact" or "block" (case-insensitive).
func ParseAction(s string) (Action, error) {
	for i, n := range actionNames {
		if strings.EqualFold(s, n) {
			return Action(i), nil
		}
	}
	return Allow, fmt.Errorf("unknown action %q (want allow|log|redact|block)", s)
}

// MarshalText implements encoding.TextMarshaler.
func (a Action) MarshalText() ([]byte, error) { return []byte(a.String()), nil }

// UnmarshalText implements encoding.TextUnmarshaler.
func (a *Action) UnmarshalText(b []byte) error {
	v, err := ParseAction(string(b))
	if err != nil {
		return err
	}
	*a = v
	return nil
}

// Rules resolve the action for a detector kind in one direction.
// A kind-specific rule overrides its category rule.
type Rules struct {
	Categories map[detect.Category]Action
	Kinds      map[detect.Kind]Action
}

// For returns the action for kind k in category c.
func (r Rules) For(k detect.Kind, c detect.Category) Action {
	if a, ok := r.Kinds[k]; ok {
		return a
	}
	return r.Categories[c]
}

// Active returns the detectors whose action is stronger than Allow.
func (r Rules) Active(set *detect.Set) []detect.Detector {
	return set.Select(func(d detect.Detector) bool { return r.For(d.Kind(), d.Category()) > Allow })
}

// InjectionRule governs prompt-injection scoring on requests.
type InjectionRule struct {
	// Threshold in [0,1]; scores at or above it trigger Action.
	Threshold float64
	Action    Action
}

// Profile is a named policy assigned to API keys.
type Profile struct {
	Name      string
	Request   Rules
	Response  Rules
	Injection InjectionRule
}
