// Command guardrail-gw is an OpenAI-compatible LLM gateway that redacts PII,
// blocks secrets and prompt-injection attempts, and filters streamed
// responses chunk-boundary-exactly.
//
// Usage:
//
//	guardrail-gw serve -config guardrail-gw.yaml
//	guardrail-gw scan -config guardrail-gw.yaml [-policy default] [-direction request] < file
//	guardrail-gw hash-key <api-key>
//	guardrail-gw audit-verify -file audit.jsonl
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/archit2501/guardrail-gw/internal/audit"
	"github.com/archit2501/guardrail-gw/internal/config"
	"github.com/archit2501/guardrail-gw/internal/filter"
	"github.com/archit2501/guardrail-gw/internal/gateway"
	"github.com/archit2501/guardrail-gw/internal/injection"
	"github.com/archit2501/guardrail-gw/internal/policy"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

func usage(w io.Writer) {
	fmt.Fprintln(w, `usage: guardrail-gw <command> [flags]

commands:
  serve         run the gateway
  scan          filter stdin with a policy (prints redacted text; exit 2 if blocked)
  hash-key      print the SHA-256 to put in keys[].key_sha256
  audit-verify  verify an audit log's hash chain
  version       print the version`)
}

func run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	var err error
	switch args[0] {
	case "serve":
		err = cmdServe(ctx, args[1:], stderr, nil)
	case "scan":
		var blocked bool
		blocked, err = cmdScan(args[1:], stdin, stdout, stderr)
		if err == nil && blocked {
			return 2
		}
	case "hash-key":
		if len(args) != 2 {
			err = errors.New("usage: guardrail-gw hash-key <api-key>")
			break
		}
		fmt.Fprintln(stdout, config.HashKey(args[1]))
	case "audit-verify":
		err = cmdVerify(args[1:], stdout)
	case "version":
		fmt.Fprintln(stdout, version)
	case "-h", "--help", "help":
		usage(stdout)
	default:
		usage(stderr)
		return 2
	}
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	return 0
}

// cmdServe runs the gateway until ctx is cancelled. If ready is non-nil it
// receives the bound address once listening (used by tests and the demo).
func cmdServe(ctx context.Context, args []string, stderr io.Writer, ready chan<- string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("config", envOr("GW_CONFIG", "guardrail-gw.yaml"), "config file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	logger := slog.New(slog.NewJSONHandler(stderr, nil))
	cfg, err := config.Load(*path)
	if err != nil {
		return err
	}
	var auditLog *audit.Log
	if p := cfg.Raw.Audit.Path; p != "" {
		if auditLog, err = audit.Open(p); err != nil {
			return err
		}
		defer func() {
			if err := auditLog.Close(); err != nil {
				logger.Error("closing audit log", "err", err)
			}
		}()
	} else {
		logger.Warn("audit.path is empty: audit logging disabled")
	}
	var hmacKey []byte
	if env := cfg.Raw.Audit.HMACKeyEnv; env != "" {
		hmacKey = []byte(os.Getenv(env))
	}
	hasher, keyed := audit.NewHasher(hmacKey)
	if !keyed {
		logger.Warn("no audit HMAC key configured: value digests are only comparable within this process")
	}
	srv := gateway.New(cfg, gateway.Options{Logger: logger, Audit: auditLog, Hasher: hasher})
	watcher := config.NewWatcher(*path, cfg, logger, srv.Apply)
	watcher.OnError = srv.ReloadFailed
	go watcher.Run(ctx)

	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-hup:
				watcher.Trigger()
			}
		}
	}()

	ln, err := net.Listen("tcp", cfg.Raw.Listen)
	if err != nil {
		return err
	}
	hs := &http.Server{Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 120 * time.Second}
	logger.Info("guardrail-gw listening", "addr", ln.Addr().String(), "upstream", cfg.Raw.Upstream.BaseURL, "version", version)
	if ready != nil {
		ready <- ln.Addr().String()
	}
	errc := make(chan error, 1)
	go func() { errc <- hs.Serve(ln) }()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	logger.Info("shutting down")
	return hs.Shutdown(shutdownCtx)
}

type scanReport struct {
	Kind        string           `json:"kind"`
	Category    string           `json:"category"`
	Action      string           `json:"action"`
	Start       int              `json:"start"`
	End         int              `json:"end"`
	Placeholder string           `json:"placeholder,omitempty"`
	Injection   *injection.Score `json:"injection,omitempty"`
}

func cmdScan(args []string, stdin io.Reader, stdout, stderr io.Writer) (bool, error) {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("config", envOr("GW_CONFIG", "guardrail-gw.yaml"), "config file")
	pol := fs.String("policy", "default", "policy name")
	dir := fs.String("direction", "request", "request or response rules")
	if err := fs.Parse(args); err != nil {
		return false, err
	}
	cfg, err := config.Load(*path)
	if err != nil {
		return false, err
	}
	p, ok := cfg.Profiles[*pol]
	if !ok {
		return false, fmt.Errorf("unknown policy %q", *pol)
	}
	rules := p.Request
	switch *dir {
	case "request":
	case "response":
		rules = p.Response
	default:
		return false, fmt.Errorf("direction must be request or response")
	}
	in, err := io.ReadAll(stdin)
	if err != nil {
		return false, err
	}
	res := filter.Apply(rules.Active(cfg.Detectors), rules.For, filter.NewNamer(), string(in))
	enc := json.NewEncoder(stderr)
	for _, f := range res.Findings {
		_ = enc.Encode(scanReport{Kind: string(f.Kind), Category: string(f.Category), Action: f.Action.String(),
			Start: f.Start, End: f.End, Placeholder: f.Placeholder})
	}
	blocked := res.Blocked != nil
	if *dir == "request" && p.Injection.Action > policy.Allow {
		if sc := injection.Evaluate(string(in)); sc.Value >= p.Injection.Threshold {
			_ = enc.Encode(scanReport{Kind: "prompt_injection", Action: p.Injection.Action.String(), Injection: &sc})
			blocked = blocked || p.Injection.Action == policy.Block
		}
	}
	_, err = io.WriteString(stdout, res.Text)
	return blocked, err
}

func cmdVerify(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("audit-verify", flag.ContinueOnError)
	file := fs.String("file", "audit.jsonl", "audit log path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	f, err := os.Open(*file)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	n, err := audit.Verify(f)
	if err != nil {
		return fmt.Errorf("%s: %w (after %d valid records)", *file, err, n)
	}
	fmt.Fprintf(stdout, "ok: %d records, hash chain intact\n", n)
	return nil
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
