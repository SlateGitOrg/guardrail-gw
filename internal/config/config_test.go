package config

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/archit2501/guardrail-gw/internal/detect"
	"github.com/archit2501/guardrail-gw/internal/policy"
)

const valid = `
listen: "127.0.0.1:9000"
upstream:
  base_url: "http://127.0.0.1:11434/"
  timeout: 30s
detectors:
  disabled: [cn_ric]
  entropy: {min_bits: 4.2}
policies:
  default:
    request: {pii: redact, secret: block, kinds: {phone: log}}
    response: {pii: redact, secret: redact}
    injection: {threshold: 0.6, action: block}
  audit-only:
    request: {pii: log, secret: log}
    response: {pii: log, secret: log}
    injection: {action: log}
keys:
  - name: team-a
    key_sha256: "` + "2bb80d537b1da3e38bd30361aa855686bde0eacd7162fef6a25fe97bf527a25b" + `"
    policy: default
    rate_limit: {requests_per_minute: 60, burst: 5}
reload:
  interval: 500ms
`

func TestParseValid(t *testing.T) {
	c, err := Parse([]byte(valid))
	if err != nil {
		t.Fatal(err)
	}
	if c.Raw.Upstream.BaseURL != "http://127.0.0.1:11434" || c.Raw.Upstream.Timeout != 30*time.Second {
		t.Errorf("upstream %+v", c.Raw.Upstream)
	}
	if c.Raw.Reload.Interval != 500*time.Millisecond || c.Raw.Limits.MaxRequestBytes != DefaultMaxRequestBytes {
		t.Errorf("defaults not applied: %+v %+v", c.Raw.Reload, c.Raw.Limits)
	}
	if _, ok := c.Detectors.Get(detect.KindChineseRIC); ok {
		t.Error("cn_ric should be disabled")
	}
	k, ok := c.Keys[HashKey("secret")]
	if !ok || k.Name != "team-a" || k.Profile.Name != "default" {
		t.Fatalf("key lookup failed: %+v", c.Keys)
	}
	p := k.Profile
	if p.Request.For(detect.KindPhone, detect.CategoryPII) != policy.Log ||
		p.Request.For(detect.KindEmail, detect.CategoryPII) != policy.Redact ||
		p.Request.For(detect.KindJWT, detect.CategorySecret) != policy.Block {
		t.Error("request rules wrong")
	}
	if p.Injection.Threshold != 0.6 || p.Injection.Action != policy.Block {
		t.Errorf("injection %+v", p.Injection)
	}
	if ao := c.Profiles["audit-only"]; ao.Injection.Threshold != DefaultInjection || ao.Injection.Action != policy.Log {
		t.Errorf("audit-only injection %+v", ao.Injection)
	}
	if len(c.Hash) != 64 {
		t.Error("hash missing")
	}
	if n := len(p.Request.Active(c.Detectors)); n != len(c.Detectors.Detectors()) {
		t.Errorf("active detectors %d", n)
	}
}

func TestParseErrors(t *testing.T) {
	cases := map[string]string{
		"unknown field":   strings.Replace(valid, "listen:", "lisen:", 1),
		"bad url":         strings.Replace(valid, "http://127.0.0.1:11434/", "ftp://x", 1),
		"bad action":      strings.Replace(valid, "pii: redact, secret: block", "pii: shred, secret: block", 1),
		"bad kind":        strings.Replace(valid, "phone: log", "fax: log", 1),
		"bad disabled":    strings.Replace(valid, "[cn_ric]", "[nope]", 1),
		"unknown policy":  strings.Replace(valid, "policy: default", "policy: nope", 1),
		"bad hash":        strings.Replace(valid, "2bb80d53", "zzz", 1),
		"bad rate":        strings.Replace(valid, "burst: 5", "burst: 0", 1),
		"bad threshold":   strings.Replace(valid, "threshold: 0.6", "threshold: 1.5", 1),
		"redact inj":      strings.Replace(valid, "{threshold: 0.6, action: block}", "{action: redact}", 1),
		"entropy max":     strings.Replace(valid, "{min_bits: 4.2}", "{max_len: 9000}", 1),
		"entropy bounds":  strings.Replace(valid, "{min_bits: 4.2}", "{min_len: 50, max_len: 40}", 1),
		"no keys":         noKeys(),
		"bad yaml":        "listen: [",
		"neg timeout":     strings.Replace(valid, "timeout: 30s", "timeout: -1s", 1),
		"no policies":     "keys: []\n",
		"duplicate names": valid + "  - name: team-a\n    key_sha256: \"" + HashKey("other") + "\"\n    policy: default\n    rate_limit: {requests_per_minute: 1, burst: 1}\n",
	}
	for name, src := range cases {
		if _, err := Parse([]byte(src)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	// Duplicate key hash across different names.
	dup := strings.Replace(valid, "reload:", "  - name: team-b\n    key_sha256: \"2bb80d537b1da3e38bd30361aa855686bde0eacd7162fef6a25fe97bf527a25b\"\n    policy: default\n    rate_limit: {requests_per_minute: 1, burst: 1}\nreload:", 1)
	if _, err := Parse([]byte(dup)); err == nil || !strings.Contains(err.Error(), "duplicate key hash") {
		t.Errorf("duplicate hash: %v", err)
	}
}

func TestLoadAndWatcher(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gw.yaml")
	if err := os.WriteFile(path, []byte(valid), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Load(filepath.Join(dir, "missing.yaml")); err == nil {
		t.Fatal("expected missing-file error")
	}
	var logs bytes.Buffer
	var applied []*Compiled
	var failures int
	w := NewWatcher(path, c, slog.New(slog.NewTextHandler(&logs, nil)), func(n *Compiled) { applied = append(applied, n) })
	w.OnError = func(error) { failures++ }

	if w.Check() {
		t.Fatal("unchanged file must not reload")
	}
	// A broken edit is rejected and the old snapshot stays.
	_ = os.WriteFile(path, []byte("listen: ["), 0o600)
	if w.Check() || failures != 1 || len(applied) != 0 {
		t.Fatalf("broken config applied (failures=%d)", failures)
	}
	if w.Check() || failures != 1 {
		t.Fatal("same broken content should be reported once")
	}
	// A valid edit is applied.
	_ = os.WriteFile(path, []byte(strings.Replace(valid, "burst: 5", "burst: 9", 1)), 0o600)
	if !w.Check() || len(applied) != 1 {
		t.Fatal("valid edit not applied")
	}
	if applied[0].Keys[HashKey("secret")].Rate.Burst != 9 {
		t.Fatal("new rate not visible")
	}
	_ = os.Remove(path)
	if w.Check() || failures != 2 {
		t.Fatal("missing file should fail")
	}
	if !strings.Contains(logs.String(), "keeping previous config") {
		t.Error("expected rejection log")
	}
}

func TestWatcherRunTrigger(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gw.yaml")
	_ = os.WriteFile(path, []byte(valid), 0o600)
	c, _ := Load(path)
	got := make(chan *Compiled, 1)
	w := NewWatcher(path, c, slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)), func(n *Compiled) { got <- n })
	w.Interval = time.Hour // only the trigger can fire
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { w.Run(ctx); close(done) }()
	_ = os.WriteFile(path, []byte(strings.Replace(valid, "burst: 5", "burst: 7", 1)), 0o600)
	w.Trigger()
	w.Trigger() // never blocks
	select {
	case n := <-got:
		if n.Keys[HashKey("secret")].Rate.Burst != 7 {
			t.Fatal("wrong snapshot")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("trigger did not reload")
	}
	cancel()
	<-done
}

func noKeys() string {
	before, _, _ := strings.Cut(valid, "keys:")
	return before
}
