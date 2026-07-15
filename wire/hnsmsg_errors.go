// Copyright (c) 2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

// Is identifies unsupported Handshake packet types as unknown messages. This
// lets peer loops ignore future packet types after consuming their bounded
// payload, matching hsd's UnknownPacket behavior.
func (e UnsupportedHnsMsgTypeError) Is(target error) bool {
	return target == ErrUnknownMessage
}
