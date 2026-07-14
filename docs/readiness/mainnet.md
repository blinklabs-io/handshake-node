# Mainnet readiness

Consensus parity is measured against hsd `v8.0.0`, source commit
`9f013c1cb7f92edf94db69fbd69daf34adf655fb`. Compact-block relay, wallet and
PSBT behavior, and optional Bitcoin RPC compatibility are outside the node
readiness gate.

## Automated gate

Run the bounded checks before beginning a manual sync:

```sh
go test ./...
go vet ./...
make unit-race
make lint workers=2
make integration
make hsd-interop
```

`make integration` includes the pruning scenario and is also run in normal CI.
The interoperability command currently verifies plaintext and Brontide
version/verack behavior with strict timeouts; full pinned-hsd relay, reorg, and
recovery orchestration remains a release blocker until its harness lands.

## Manual parity run

Run hsd `v8.0.0` and handshake-node on separate authenticated RPC ports. Start
handshake-node with a new datadir, then set credentials only through the
environment:

```sh
export HNSPARITY_NODE_URL=http://127.0.0.1:12037
export HNSPARITY_NODE_USER=node-user
export HNSPARITY_NODE_PASS=node-password
export HNSPARITY_HSD_URL=http://127.0.0.1:13037
export HNSPARITY_HSD_USER=hsd-user
export HNSPARITY_HSD_PASS=hsd-api-key

make hnsparity
./hnsparity \
  --target 0 \
  --sample-interval 1000 \
  --state hnsparity-state.json \
  --report hnsparity-report.json \
  --markdown docs/readiness/runs/rc-name.md \
  --restart '2026-07-14T12:00:00Z clean restart'
```

At startup, target `0` captures the hsd tip and its hash. The runner waits for
handshake-node to reach each height, compares every block hash and serialized
header, and compares serialized blocks, decoded block fields, and deployment
states at the sampling interval. Add repeatable `--name example` and
`--outpoint txid:index` options for release-specific name and UTXO samples.

The checkpoint is written atomically after every verified height. Re-running
the same `--target 0` command retains the originally captured target, resumes
at the next height, and rejects a state file whose
network, target height, or target hash differs. RPC credentials are neither
stored nor printed. JSON reports are operational artifacts; copy the concise
Markdown report into `docs/readiness/runs/` for a release candidate.

To exercise recovery, terminate handshake-node (including one forced
termination), restart it with the same datadir, and re-run the parity command.
Record restart timestamps with repeatable `--restart` options. Repeat once with a
pruned node and after rebuilding enabled indexes. A release also requires a
72-hour at-tip soak with resource usage and any recovery action documented.

## Current release blockers

- Handshake-native fixtures must replace inherited Bitcoin fixtures and skips
  in consensus, storage, mempool, script, and P2P integration packages.
- A deterministic hsd regtest harness must cover both transports, relay,
  competing branches, deep reorgs, malformed packets, restarts, pruning, index
  rebuilds, and database recovery in CI.
- A clean mainnet parity run, interrupted/resumed parity run, and 72-hour soak
  must complete with zero mismatch or corruption.

Do not describe a build as a mainnet release candidate until every blocker and
the complete automated and manual gates above have passed.
