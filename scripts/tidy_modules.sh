#!/bin/bash

# Copyright (c) 2024-2026 Blink Labs Software
# Use of this source code is governed by an ISC
# license that can be found in the LICENSE file.

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

for module in . hnsutil chaincfg/chainhash; do
  (
    cd "$module"
    go mod tidy
  )
done
