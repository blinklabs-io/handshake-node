#!/bin/bash

# Copyright (c) 2024-2026 Blink Labs Software
# Use of this source code is governed by an ISC
# license that can be found in the LICENSE file.

SUBMODULES=$(find . -mindepth 2 -name "go.mod" | cut -d'/' -f2)


# Run 'go mod tidy' for root.
go mod tidy

# Run 'go mod tidy' for each module.
for submodule in $SUBMODULES
do
  pushd $submodule

  go mod tidy

  popd
done
