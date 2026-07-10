// Copyright (c) 2024-2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

//go:build !openbsd

package ossec

func Unveil(path string, perms string) error {
	return nil
}

func Pledge(promises, execpromises string) error {
	return nil
}

func PledgePromises(promises string) error {
	return nil
}
