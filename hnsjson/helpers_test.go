// Copyright (c) 2014 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package hnsjson_test

import (
	"reflect"
	"testing"

	"github.com/blinklabs-io/handshake-node/hnsjson"
)

// TestHelpers tests the various helper functions which create pointers to
// primitive types.
func TestHelpers(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		f        func() any
		expected any
	}{
		{
			name: "bool",
			f: func() any {
				return hnsjson.Bool(true)
			},
			expected: func() any {
				val := true
				return &val
			}(),
		},
		{
			name: "int",
			f: func() any {
				return hnsjson.Int(5)
			},
			expected: func() any {
				val := int(5)
				return &val
			}(),
		},
		{
			name: "uint",
			f: func() any {
				return hnsjson.Uint(5)
			},
			expected: func() any {
				val := uint(5)
				return &val
			}(),
		},
		{
			name: "int32",
			f: func() any {
				return hnsjson.Int32(5)
			},
			expected: func() any {
				val := int32(5)
				return &val
			}(),
		},
		{
			name: "uint32",
			f: func() any {
				return hnsjson.Uint32(5)
			},
			expected: func() any {
				val := uint32(5)
				return &val
			}(),
		},
		{
			name: "int64",
			f: func() any {
				return hnsjson.Int64(5)
			},
			expected: func() any {
				val := int64(5)
				return &val
			}(),
		},
		{
			name: "uint64",
			f: func() any {
				return hnsjson.Uint64(5)
			},
			expected: func() any {
				val := uint64(5)
				return &val
			}(),
		},
		{
			name: "string",
			f: func() any {
				return hnsjson.String("abc")
			},
			expected: func() any {
				val := "abc"
				return &val
			}(),
		},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		result := test.f()
		if !reflect.DeepEqual(result, test.expected) {
			t.Errorf("Test #%d (%s) unexpected value - got %v, "+
				"want %v", i, test.name, result, test.expected)
			continue
		}
	}
}
