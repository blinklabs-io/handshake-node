// Copyright (c) 2015-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package txscript

const (
	// LockTimeFlag marks an absolute locktime as time-based.  Handshake
	// uses the high bit rather than Bitcoin's 500,000,000 threshold.
	LockTimeFlag = 1 << 31

	// LockTimeMask extracts the absolute locktime value.
	LockTimeMask = LockTimeFlag - 1

	// LockTimeGranularity is the shift used by time-based locktimes.
	LockTimeGranularity = 9

	// LockTimeMultiplier converts time-based absolute locktimes to seconds.
	LockTimeMultiplier = 1 << LockTimeGranularity

	// LockTimeThreshold is the Bitcoin threshold retained for legacy callers
	// and tests. Handshake consensus uses LockTimeFlag instead.
	LockTimeThreshold = 5e8 // Tue Nov 5 00:53:20 1985 UTC
)
