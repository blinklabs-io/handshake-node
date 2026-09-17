// Copyright (c) 2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"slices"
	"testing"
)

func TestReadCommandParams(t *testing.T) {
	got, err := readCommandParams([]string{"first", "-", "last"},
		bytes.NewBufferString("from stdin\n"))
	if err != nil {
		t.Fatalf("readCommandParams: %v", err)
	}
	want := []any{"first", "from stdin", "last"}
	if !slices.Equal(got, want) {
		t.Fatalf("readCommandParams: got %v, want %v", got, want)
	}
}

func TestReadCommandParamsRejectsMissingStdinValue(t *testing.T) {
	_, err := readCommandParams([]string{"-"}, bytes.NewReader(nil))
	if err == nil {
		t.Fatal("readCommandParams accepted missing stdin value")
	}
}

func TestPrintResult(t *testing.T) {
	tests := []struct {
		name   string
		result string
		want   string
	}{
		{
			name:   "object",
			result: `{"name":"handshake"}`,
			want:   "{\n  \"name\": \"handshake\"\n}\n",
		},
		{
			name:   "string",
			result: `"handshake"`,
			want:   "handshake\n",
		},
		{
			name:   "null",
			result: "null",
		},
		{
			name:   "leading whitespace",
			result: ` {"name":"handshake"}`,
			want:   " {\"name\":\"handshake\"}\n",
		},
		{
			name:   "surrounded null",
			result: " null ",
			want:   " null \n",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var output bytes.Buffer
			if err := printResult([]byte(test.result), &output); err != nil {
				t.Fatalf("printResult: %v", err)
			}
			if got := output.String(); got != test.want {
				t.Fatalf("printResult: got %q, want %q", got, test.want)
			}
		})
	}
}
