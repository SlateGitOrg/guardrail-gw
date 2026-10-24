// Package config loads, validates and compiles the gateway configuration.
// A compiled configuration is immutable; hot reload swaps whole snapshots.
package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/archit2501/guardrail-gw/internal/detect"
	"github.com/archit2501/guardrail-gw/internal/policy"
)

// Config mirrors the YAML file.
type Config struct {
	Listen    string                   `yaml:"listen"`
	Upstream  Upstream                 `yaml:"upstream"`
	Limits    Limits                   `yaml:"limits"`
	Detectors Detectors                `yaml:"detectors"`
	Policies  map[string]PolicyConfig  `yaml:"policies"`
	Keys      []KeyConfig              `yaml:"keys"`
	Audit     Audit                    `yaml:"audit"`
	Reload    Reload                   `yaml:"reload"`
}

// Upstream is the OpenAI-compatible backend (Ollama by default).
type Upstream struct {
	BaseURL   string        `yaml:"base_url"`
	APIKeyEnv string        `yaml:"api_key_env"`
	Timeout   time.Duration `yaml:"timeout"`
}

// Limits bounds request and response sizes.
type Limits struct {
	MaxRequestBytes  int64 `yaml:"max_request_bytes"`
	MaxResponseBytes int64 `yaml:"max_response_bytes"`
}

// Detectors tunes detection.
type Detectors struct {
	Disabled []string      `yaml:"disabled"`
	Entropy  EntropyConfig `yaml:"entropy"`
}

// EntropyConfig mirrors detect.EntropyConfig.
type EntropyConfig struct {
	MinLen      int     `yaml:"min_len"`
	MaxLen      int     `yaml:"max_len"`
	MinBits     float64 `yaml:"min_bits"`
	KeywordBits float64 `yaml:"keyword_bits"`
}

// RulesConfig maps categories (pii, secret) and kinds to actions.
type RulesConfig struct {
	PII    string            `yaml:"pii"`
	Secret string            `yaml:"secret"`
	Kinds  map[string]string `yaml:"kinds"`
}

// InjectionConfig configures the injection scorer for a policy.
type InjectionConfig struct {
	Threshold float64 `yaml:"threshold"`
	Action    string  `yaml:"action"`
}

// PolicyConfig is one named policy profile.
type PolicyConfig struct {
	Request   RulesConfig     `yaml:"request"`
	Response  RulesConfig     `yaml:"response"`
	Injection InjectionConfig `yaml:"injection"`
}

// RateLimit is a token bucket: sustained requests per minute plus burst.
type RateLimit struct {
	RequestsPerMinute float64 `yaml:"requests_per_minute"`
	Burst             int     `yaml:"burst"`
}

// KeyConfig is one client API key, stored only as its SHA-256 hash.
type KeyConfig struct {
	Name      string    `yaml:"name"`
	KeySHA256 string    `yaml:"key_sha256"`
	Policy    string    `yaml:"policy"`
	RateLimit RateLimit `yaml:"rate_limit"`
}

// Audit configures the hash-chained audit log.
type Audit struct {
	Path       string `yaml:"path"`
	HMACKeyEnv string `yaml:"hmac_key_env"`
}

// Reload configures config-file polling.
type Reload struct {
	Interval time.Duration `yaml:"interval"`
}

// Key is a compiled client key.
type Key struct {
	Name    string
	Profile *policy.Profile
	Rate    RateLimit
}

// Compiled is an immutable, validated snapshot used by the gateway.
type Compiled struct {
	Raw       Config
	Hash      string // SHA-256 of the source bytes
	Detectors *detect.Set
	Profiles  map[string]*policy.Profile
	Keys      map[string]Key // by lowercase hex SHA-256 of the API key
}

// Defaults applied to omitted fields.
const (
	DefaultListen           = "127.0.0.1:8080"
	DefaultUpstream         = "http://127.0.0.1:11434"
	DefaultTimeout          = 120 * time.Second
	DefaultMaxRequestBytes  = 1 << 20
	DefaultMaxResponseBytes = 8 << 20
	DefaultReloadInterval   = 2 * time.Second
	DefaultInjection        = 0.75
)

// Load reads and compiles the file at path.
func Load(path string) (*Compiled, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(b)
}

// Parse decodes YAML strictly (unknown fields are errors) and compiles it.
func Parse(b []byte) (*Compiled, error) {
	var c Config
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	sum := sha256.Sum256(b)
	comp, err := Compile(c)
	if err != nil {
		return nil, err
	}
	comp.Hash = hex.EncodeToString(sum[:])
	return comp, nil
}

// HashKey returns the lowercase hex SHA-256 of a client API key.
func HashKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

func (c *Config) applyDefaults() {
	if c.Listen == "" {
		c.Listen = DefaultListen
	}
	if c.Upstream.BaseURL == "" {
		c.Upstream.BaseURL = DefaultUpstream
	}
	c.Upstream.BaseURL = strings.TrimRight(c.Upstream.BaseURL, "/")
	if c.Upstream.Timeout == 0 {
		c.Upstream.Timeout = DefaultTimeout
	}
	if c.Limits.MaxRequestBytes == 0 {
		c.Limits.MaxRequestBytes = DefaultMaxRequestBytes
	}
	if c.Limits.MaxResponseBytes == 0 {
		c.Limits.MaxResponseBytes = DefaultMaxResponseBytes
	}
	if c.Reload.Interval == 0 {
		c.Reload.Interval = DefaultReloadInterval
	}
}

// Compile validates c and builds the runtime snapshot. All errors are
// collected so an operator sees every problem at once.
func Compile(c Config) (*Compiled, error) {
	c.applyDefaults()
	var errs []error
	bad := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	if u, err := url.Parse(c.Upstream.BaseURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		bad("upstream.base_url %q must be an http(s) URL", c.Upstream.BaseURL)
	}
	if c.Upstream.Timeout < 0 || c.Limits.MaxRequestBytes < 0 || c.Limits.MaxResponseBytes < 0 || c.Reload.Interval < 0 {
		bad("timeouts, limits and intervals must be positive")
	}

	opts := detect.Options{Disabled: map[detect.Kind]bool{}}
	for _, k := range c.Detectors.Disabled {
		if _, ok := detect.CategoryOf(detect.Kind(k)); !ok {
			bad("detectors.disabled: unknown kind %q", k)
		}
		opts.Disabled[detect.Kind(k)] = true
	}
	if e := c.Detectors.Entropy; e != (EntropyConfig{}) {
		def := detect.DefaultEntropyConfig()
		opts.Entropy = detect.EntropyConfig{
			MinLen: orInt(e.MinLen, def.MinLen), MaxLen: orInt(e.MaxLen, def.MaxLen),
			MinBits: orFloat(e.MinBits, def.MinBits), KeywordBits: orFloat(e.KeywordBits, def.KeywordBits),
		}
		if opts.Entropy.MaxLen > 4096 {
			bad("detectors.entropy.max_len %d exceeds 4096", opts.Entropy.MaxLen)
		}
	}
	set, err := detect.NewSet(opts)
	if err != nil {
		bad("detectors: %v", err)
	}

	if len(c.Policies) == 0 {
		bad("at least one policy is required")
	}
	profiles := map[string]*policy.Profile{}
	for name, pc := range c.Policies {
		p, perrs := compilePolicy(name, pc)
		errs = append(errs, perrs...)
		profiles[name] = p
	}

	keys := map[string]Key{}
	names := map[string]bool{}
	for i, k := range c.Keys {
		where := fmt.Sprintf("keys[%d]", i)
		switch {
		case k.Name == "":
			bad("%s: name is required", where)
		case names[k.Name]:
			bad("%s: duplicate name %q", where, k.Name)
		}
		names[k.Name] = true
		h := strings.ToLower(k.KeySHA256)
		if b, err := hex.DecodeString(h); err != nil || len(b) != sha256.Size {
			bad("%s (%s): key_sha256 must be 64 hex chars (use `guardrail-gw hash-key`)", where, k.Name)
		} else if _, dup := keys[h]; dup {
			bad("%s (%s): duplicate key hash", where, k.Name)
		}
		p, ok := profiles[k.Policy]
		if !ok {
			bad("%s (%s): unknown policy %q", where, k.Name, k.Policy)
		}
		if k.RateLimit.RequestsPerMinute <= 0 || k.RateLimit.Burst < 1 {
			bad("%s (%s): rate_limit needs requests_per_minute > 0 and burst >= 1", where, k.Name)
		}
		keys[h] = Key{Name: k.Name, Profile: p, Rate: k.RateLimit}
	}
	if len(c.Keys) == 0 {
		bad("at least one key is required")
	}
	if err := errors.Join(errs...); err != nil {
		return nil, fmt.Errorf("config invalid:\n%w", err)
	}
	return &Compiled{Raw: c, Detectors: set, Profiles: profiles, Keys: keys}, nil
}

func compilePolicy(name string, pc PolicyConfig) (*policy.Profile, []error) {
	var errs []error
	p := &policy.Profile{Name: name}
	var err error
	if p.Request, err = compileRules(pc.Request, policy.Redact, policy.Block); err != nil {
		errs = append(errs, fmt.Errorf("policies.%s.request: %w", name, err))
	}
	if p.Response, err = compileRules(pc.Response, policy.Redact, policy.Redact); err != nil {
		errs = append(errs, fmt.Errorf("policies.%s.response: %w", name, err))
	}
	p.Injection.Threshold = orFloat(pc.Injection.Threshold, DefaultInjection)
	if p.Injection.Threshold <= 0 || p.Injection.Threshold > 1 {
		errs = append(errs, fmt.Errorf("policies.%s.injection.threshold must be in (0,1]", name))
	}
	p.Injection.Action = policy.Block
	if pc.Injection.Action != "" {
		a, err := policy.ParseAction(pc.Injection.Action)
		if err != nil || a == policy.Redact {
			errs = append(errs, fmt.Errorf("policies.%s.injection.action must be allow, log or block", name))
		}
		p.Injection.Action = a
	}
	return p, errs
}

func compileRules(rc RulesConfig, defPII, defSecret policy.Action) (policy.Rules, error) {
	r := policy.Rules{
		Categories: map[detect.Category]policy.Action{detect.CategoryPII: defPII, detect.CategorySecret: defSecret},
		Kinds:      map[detect.Kind]policy.Action{},
	}
	var errs []error
	set := func(dst *policy.Action, s string) {
		if s == "" {
			return
		}
		a, err := policy.ParseAction(s)
		if err != nil {
			errs = append(errs, err)
			return
		}
		*dst = a
	}
	pii, secret := r.Categories[detect.CategoryPII], r.Categories[detect.CategorySecret]
	set(&pii, rc.PII)
	set(&secret, rc.Secret)
	r.Categories[detect.CategoryPII], r.Categories[detect.CategorySecret] = pii, secret
	for k, v := range rc.Kinds {
		if _, ok := detect.CategoryOf(detect.Kind(k)); !ok {
			errs = append(errs, fmt.Errorf("unknown kind %q", k))
			continue
		}
		var a policy.Action
		set(&a, v)
		r.Kinds[detect.Kind(k)] = a
	}
	return r, errors.Join(errs...)
}

func orInt(v, def int) int {
	if v == 0 {
		return def
	}
	return v
}

func orFloat(v, def float64) float64 {
	if v == 0 {
		return def
	}
	return v
}
