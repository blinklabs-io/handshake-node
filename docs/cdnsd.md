# cdnsd Integration

`cdnsd` can index Handshake names from a local `handshake-node` peer over the
Handshake P2P protocol.  The current cdnsd indexer consumes full blocks and
derives name records from covenant outputs.

Run `handshake-node` with a reachable P2P listener:

```bash
handshake-node --listen=127.0.0.1:12038
```

Point cdnsd at that listener with either its YAML config:

```yaml
indexer:
  handshakeAddress: 127.0.0.1:12038
```

or the matching environment variable:

```bash
INDEXER_HANDSHAKE_ADDRESS=127.0.0.1:12038 cdnsd
```

Expose only the P2P listener needed by cdnsd.  cdnsd does not require
handshake-node wallet functionality, and wallet signing remains outside this
repository.
