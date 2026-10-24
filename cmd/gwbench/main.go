// Command gwbench measures the latency the gateway adds on top of an
// upstream. It starts the deterministic fake upstream and the gateway
// in-process on loopback, then replays the same workload directly against
// the upstream and through the gateway, reporting p50/p99 for both.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"runtime/pprof"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/archit2501/guardrail-gw/internal/config"
	"github.com/archit2501/guardrail-gw/internal/corpus"
	"github.com/archit2501/guardrail-gw/internal/fakeupstream"
	"github.com/archit2501/guardrail-gw/internal/gateway"
)

const benchKey = "gw-bench-key"

type options struct {
	n, c, warmup int
	piece        int
	out          string
	cpuprofile   string
}

func main() {
	var o options
	flag.IntVar(&o.n, "n", 2000, "measured requests per scenario")
	flag.IntVar(&o.c, "c", 4, "concurrent clients")
	flag.IntVar(&o.warmup, "warmup", 200, "unmeasured warm-up requests per scenario")
	flag.IntVar(&o.piece, "piece", 4, "bytes per streamed content delta (~1 token)")
	flag.StringVar(&o.out, "out", "", "also write the Markdown report to this file")
	flag.StringVar(&o.cpuprofile, "cpuprofile", "", "write a CPU profile of the whole run to this file")
	flag.Parse()
	if o.cpuprofile != "" {
		f, err := os.Create(o.cpuprofile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "gwbench:", err)
			os.Exit(1)
		}
		if err := pprof.StartCPUProfile(f); err != nil {
			fmt.Fprintln(os.Stderr, "gwbench:", err)
			os.Exit(1)
		}
		defer pprof.StopCPUProfile()
	}
	if err := run(o, os.Stdout); err != nil {
		pprof.StopCPUProfile()
		fmt.Fprintln(os.Stderr, "gwbench:", err)
		os.Exit(1)
	}
}

type result struct {
	name             string
	direct, through  []time.Duration
	reqBytes, rspLen int
}

func run(o options, stdout io.Writer) error {
	g := corpus.NewGen("heldout", 7)
	prompt := "Please review this support thread and draft a reply. " + g.NoisyText(120)
	reply := "Here is a draft reply for the customer. " + g.NoisyText(180)

	up := &fakeupstream.Server{Reply: func(string) string { return reply }, Pieces: fakeupstream.FixedPieces(o.piece)}
	upSrv := httptest.NewServer(up)
	defer upSrv.Close()
	cfg, err := config.Parse([]byte(fmt.Sprintf(`
upstream: {base_url: %q, timeout: 30s}
policies:
  default:
    request: {pii: redact, secret: redact}
    response: {pii: redact, secret: redact}
    injection: {action: log}
keys:
  - name: bench
    key_sha256: %q
    policy: default
    rate_limit: {requests_per_minute: 100000000, burst: 1000000}
`, upSrv.URL, config.HashKey(benchKey))))
	if err != nil {
		return err
	}
	gw := gateway.New(cfg, gateway.Options{})
	gwSrv := httptest.NewServer(gw.Handler())
	defer gwSrv.Close()

	client := &http.Client{Transport: &http.Transport{MaxIdleConnsPerHost: o.c * 2}}
	var results []result
	for _, stream := range []bool{false, true} {
		body, _ := json.Marshal(map[string]any{"model": "fake", "stream": stream,
			"messages": []any{map[string]any{"role": "user", "content": prompt}}})
		name := "buffered"
		if stream {
			name = fmt.Sprintf("streaming (%d-byte deltas)", o.piece)
		}
		r := result{name: name, reqBytes: len(body), rspLen: len(reply)}
		// Interleave direct and gateway phases so drift affects both equally.
		for _, target := range []string{upSrv.URL, gwSrv.URL} {
			if _, err := load(client, target, body, o.warmup, o.c); err != nil {
				return err
			}
		}
		if r.direct, err = load(client, upSrv.URL, body, o.n, o.c); err != nil {
			return err
		}
		if r.through, err = load(client, gwSrv.URL, body, o.n, o.c); err != nil {
			return err
		}
		results = append(results, r)
	}
	var md bytes.Buffer
	report(&md, o, results)
	if _, err := stdout.Write(md.Bytes()); err != nil {
		return err
	}
	if o.out != "" {
		return os.WriteFile(o.out, md.Bytes(), 0o644)
	}
	return nil
}

// load sends n requests with c workers and returns per-request latencies
// (time until the full response body has been read).
func load(client *http.Client, base string, body []byte, n, c int) ([]time.Duration, error) {
	lat := make([]time.Duration, n)
	jobs := make(chan int)
	errc := make(chan error, c)
	var wg sync.WaitGroup
	for w := 0; w < c; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				req, _ := http.NewRequest(http.MethodPost, base+"/v1/chat/completions", bytes.NewReader(body))
				req.Header.Set("Authorization", "Bearer "+benchKey)
				req.Header.Set("Content-Type", "application/json")
				t0 := time.Now()
				resp, err := client.Do(req)
				if err != nil {
					errc <- err
					return
				}
				_, err = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				if err != nil || resp.StatusCode != http.StatusOK {
					errc <- fmt.Errorf("status %d: %v", resp.StatusCode, err)
					return
				}
				lat[i] = time.Since(t0)
			}
		}()
	}
	for i := 0; i < n; i++ {
		select {
		case jobs <- i:
		case err := <-errc:
			close(jobs)
			wg.Wait()
			return nil, err
		}
	}
	close(jobs)
	wg.Wait()
	select {
	case err := <-errc:
		return nil, err
	default:
	}
	return lat, nil
}

// percentile uses the nearest-rank method on a sorted copy.
func percentile(d []time.Duration, p float64) time.Duration {
	s := append([]time.Duration(nil), d...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	idx := int(float64(len(s))*p+0.999999) - 1
	return s[max(0, min(idx, len(s)-1))]
}

func ms(d time.Duration) string { return fmt.Sprintf("%.3f", float64(d.Microseconds())/1000) }

func report(w io.Writer, o options, rs []result) {
	fmt.Fprintf(w, "| scenario | requests | clients | direct p50 ms | direct p99 ms | gateway p50 ms | gateway p99 ms | overhead p50 ms | overhead p99 ms |\n")
	fmt.Fprintf(w, "|---|---:|---:|---:|---:|---:|---:|---:|---:|\n")
	for _, r := range rs {
		d50, d99 := percentile(r.direct, 0.50), percentile(r.direct, 0.99)
		g50, g99 := percentile(r.through, 0.50), percentile(r.through, 0.99)
		fmt.Fprintf(w, "| %s | %d | %d | %s | %s | %s | %s | %s | %s |\n",
			r.name, o.n, o.c, ms(d50), ms(d99), ms(g50), ms(g99), ms(g50-d50), ms(g99-d99))
	}
	fmt.Fprintf(w, "\nRequest body %d bytes, response text %d bytes; %s/%s, %d CPUs, %s; upstream, gateway and load generator share one process on loopback.\n",
		rs[0].reqBytes, rs[0].rspLen, runtime.GOOS, runtime.GOARCH, runtime.NumCPU(), strings.TrimPrefix(runtime.Version(), "go"))
}
