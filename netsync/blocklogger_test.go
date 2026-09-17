// Copyright (c) 2024-2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package netsync

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/btcsuite/btclog"
)

type recordingLogger struct {
	mu      sync.Mutex
	entries []string
}

func (l *recordingLogger) append(format string, params ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = append(l.entries, fmt.Sprintf(format, params...))
}

func (l *recordingLogger) last() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.entries) == 0 {
		return ""
	}
	return l.entries[len(l.entries)-1]
}

func (l *recordingLogger) Tracef(string, ...any) {}
func (l *recordingLogger) Debugf(string, ...any) {}
func (l *recordingLogger) Infof(format string, params ...any) {
	l.append(format, params...)
}
func (l *recordingLogger) Warnf(string, ...any)     {}
func (l *recordingLogger) Errorf(string, ...any)    {}
func (l *recordingLogger) Criticalf(string, ...any) {}
func (l *recordingLogger) Trace(...any)             {}
func (l *recordingLogger) Debug(...any)             {}
func (l *recordingLogger) Info(v ...any) {
	l.append(strings.Repeat("%v ", len(v)), v...)
}
func (l *recordingLogger) Warn(...any)           {}
func (l *recordingLogger) Error(...any)          {}
func (l *recordingLogger) Critical(...any)       {}
func (l *recordingLogger) Level() btclog.Level   { return btclog.LevelInfo }
func (l *recordingLogger) SetLevel(btclog.Level) {}

func TestLogHeaderProgressIncludesIBDStats(t *testing.T) {
	logger := &recordingLogger{}
	progress := newBlockProgressLogger("Processed", logger)
	progress.lastHeaderLogTime = time.Now().Add(-20 * time.Second)

	progress.LogHeaderProgress(20, 50, 100)

	got := logger.last()
	for _, want := range []string{
		"Downloaded 20 headers",
		"headers/s",
		"height 50 of 100",
		"50.00%",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("header progress log = %q, want substring %q",
				got, want)
		}
	}
}
