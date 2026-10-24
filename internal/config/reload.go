package config

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"os"
	"time"
)

// Watcher polls a config file and calls Apply with each new valid snapshot.
// Invalid edits are logged and ignored, so the previous snapshot stays live.
// Polling (rather than fsnotify) is deliberate: it survives editors that
// replace files atomically, works on every platform, and needs no dependency.
type Watcher struct {
	Path     string
	Interval time.Duration
	Logger   *slog.Logger
	// Apply installs a new snapshot. It is called from the watcher goroutine.
	Apply func(*Compiled)
	// OnError observes failed reloads (for metrics); optional.
	OnError func(error)

	trigger  chan struct{}
	lastHash string
}

// NewWatcher creates a watcher whose baseline is the currently loaded hash.
func NewWatcher(path string, current *Compiled, logger *slog.Logger, apply func(*Compiled)) *Watcher {
	return &Watcher{
		Path: path, Interval: current.Raw.Reload.Interval, Logger: logger, Apply: apply,
		trigger: make(chan struct{}, 1), lastHash: current.Hash,
	}
}

// Trigger requests an immediate check (e.g. on SIGHUP). It never blocks.
func (w *Watcher) Trigger() {
	select {
	case w.trigger <- struct{}{}:
	default:
	}
}

// Run polls until ctx is done.
func (w *Watcher) Run(ctx context.Context) {
	t := time.NewTicker(w.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-w.trigger:
		}
		w.Check()
	}
}

// Check reloads the file if its content changed. It reports whether a new
// snapshot was applied.
func (w *Watcher) Check() bool {
	b, err := os.ReadFile(w.Path)
	if err != nil {
		w.fail(err)
		return false
	}
	sum := sha256.Sum256(b)
	h := hex.EncodeToString(sum[:])
	if h == w.lastHash {
		return false
	}
	w.lastHash = h // do not re-log the same broken content every tick
	c, err := Parse(b)
	if err != nil {
		w.fail(err)
		return false
	}
	w.Apply(c)
	w.Logger.Info("config reloaded", "hash", h[:12], "keys", len(c.Keys), "policies", len(c.Profiles))
	return true
}

func (w *Watcher) fail(err error) {
	w.Logger.Error("config reload rejected; keeping previous config", "err", err)
	if w.OnError != nil {
		w.OnError(err)
	}
}
