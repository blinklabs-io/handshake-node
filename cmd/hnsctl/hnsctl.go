// Copyright (c) 2024-2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/blinklabs-io/handshake-node/hnsjson"
)

const (
	showHelpMessage = "Specify -h to show available options"
	listCmdMessage  = "Specify -l to list available commands"
)

// commandUsage display the usage for a specific command.
func commandUsage(method string) {
	usage, err := hnsjson.MethodUsageText(method)
	if err != nil {
		// This should never happen since the method was already checked
		// before calling this function, but be safe.
		fmt.Fprintln(os.Stderr, "Failed to obtain command usage:", err)
		return
	}

	fmt.Fprintln(os.Stderr, "Usage:")
	fmt.Fprintf(os.Stderr, "  %s\n", usage)
}

// usage displays the general usage when the help flag is not displayed and
// and an invalid command was specified.  The commandUsage function is used
// instead when a valid command was specified.
func usage(errorMessage string) {
	appName := filepath.Base(os.Args[0])
	appName = strings.TrimSuffix(appName, filepath.Ext(appName))
	fmt.Fprintln(os.Stderr, errorMessage)
	fmt.Fprintln(os.Stderr, "Usage:")
	fmt.Fprintf(os.Stderr, "  %s [OPTIONS] <command> <args...>\n\n",
		appName)
	fmt.Fprintln(os.Stderr, showHelpMessage)
	fmt.Fprintln(os.Stderr, listCmdMessage)
}

//nolint:staticcheck // Preserve the command's established error text.
func readCommandParams(args []string, input io.Reader) ([]any, error) {
	reader := bufio.NewReader(input)
	params := make([]any, 0, len(args))
	for _, arg := range args {
		if arg != "-" {
			params = append(params, arg)
			continue
		}

		param, err := reader.ReadString('\n')
		if err != nil && err != io.EOF {
			return nil, fmt.Errorf("Failed to read data from stdin: %w", err)
		}
		if err == io.EOF && len(param) == 0 {
			return nil, errors.New("Not enough lines provided on stdin")
		}
		params = append(params, strings.TrimRight(param, "\r\n"))
	}
	return params, nil
}

//nolint:staticcheck // Preserve the command's established error text.
func printResult(result []byte, output io.Writer) error {
	resultString := string(result)
	switch {
	case strings.HasPrefix(resultString, "{") || strings.HasPrefix(resultString, "["):
		var formatted bytes.Buffer
		if err := json.Indent(&formatted, result, "", "  "); err != nil {
			return fmt.Errorf("Failed to format result: %w", err)
		}
		_, err := fmt.Fprintln(output, formatted.String())
		return err
	case strings.HasPrefix(resultString, `"`):
		var value string
		if err := json.Unmarshal(result, &value); err != nil {
			return fmt.Errorf("Failed to unmarshal result: %w", err)
		}
		_, err := fmt.Fprintln(output, value)
		return err
	case resultString != "null":
		_, err := fmt.Fprintln(output, resultString)
		return err
	}
	return nil
}

func main() {
	cfg, args, err := loadConfig()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to load config:", err)
		os.Exit(1)
	}
	if len(args) < 1 {
		usage("No command specified")
		os.Exit(1)
	}

	// Ensure the specified method identifies a valid registered command and
	// is one of the usable types.
	method := args[0]
	usageFlags, err := hnsjson.MethodUsageFlags(method)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unrecognized command '%s'\n", method)
		fmt.Fprintln(os.Stderr, listCmdMessage)
		os.Exit(1)
	}
	if usageFlags&unusableFlags != 0 {
		fmt.Fprintf(os.Stderr, "The '%s' command can only be used via "+
			"websockets\n", method)
		fmt.Fprintln(os.Stderr, listCmdMessage)
		os.Exit(1)
	}

	params, err := readCommandParams(args[1:], os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	// Attempt to create the appropriate command using the arguments
	// provided by the user.
	cmd, err := hnsjson.NewCmd(method, params...)
	if err != nil {
		// Show the error along with its error code when it's a
		// hnsjson.Error as it reallistcally will always be since the
		// NewCmd function is only supposed to return errors of that
		// type.
		if jerr, ok := err.(hnsjson.Error); ok {
			fmt.Fprintf(os.Stderr, "%s command: %v (code: %s)\n",
				method, err, jerr.ErrorCode)
			commandUsage(method)
			os.Exit(1)
		}

		// The error is not a hnsjson.Error and this really should not
		// happen.  Nevertheless, fallback to just showing the error
		// if it should happen due to a bug in the package.
		fmt.Fprintf(os.Stderr, "%s command: %v\n", method, err)
		commandUsage(method)
		os.Exit(1)
	}

	// Marshal the command into a JSON-RPC byte slice in preparation for
	// sending it to the RPC server.
	marshalledJSON, err := hnsjson.MarshalCmd(hnsjson.RpcVersion1, 1, cmd)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	// Send the JSON-RPC request to the server using the user-specified
	// connection configuration.
	result, err := sendPostRequest(marshalledJSON, cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if err := printResult(result, os.Stdout); err != nil {
		fmt.Fprint(os.Stderr, err)
		os.Exit(1)
	}
}
