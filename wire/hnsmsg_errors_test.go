// Copyright (c) 2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"errors"
	"testing"
)

func TestUnsupportedHnsMsgTypeIsUnknown(t *testing.T) {
	err := UnsupportedHnsMsgTypeError{MessageType: HnsMsgType(31)}
	if !errors.Is(err, ErrUnknownMessage) {
		t.Fatalf("errors.Is(%v, ErrUnknownMessage) = false", err)
	}
}
