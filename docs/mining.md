# Mining

handshake-node supports the `getblocktemplate` RPC.
The limited user cannot access this RPC.
It also includes an opt-in Handshake Stratum v1 MVP server for pool mining
experiments.

## Add the payment addresses with the `miningaddr` option

```bash
[Application Options]
rpcuser=myuser
rpcpass=SomeDecentp4ssw0rd
miningaddr=hs1qexampleaddress1
miningaddr=hs1qexampleaddress2
```

## Add handshake-node's RPC TLS certificate to system Certificate Authority list

`cgminer` uses [curl](http://curl.haxx.se/) to fetch data from the RPC server.
Since curl validates the certificate by default, we must install the handshake-node RPC
certificate into the default system Certificate Authority list.

## Ubuntu

1. Copy rpc.cert to /usr/share/ca-certificates: `cp /home/user/.handshake-node/rpc.cert /usr/share/ca-certificates/handshake-node.crt`
2. Add handshake-node.crt to /etc/ca-certificates.conf: `echo handshake-node.crt >> /etc/ca-certificates.conf`
3. Update the CA certificate list: `update-ca-certificates`

## Set your mining software url to use https

`cgminer -o https://127.0.0.1:12037 -u rpcuser -p rpcpassword`

## Handshake Stratum v1 MVP

The Stratum server is disabled by default. Enable it with `stratumlisten` and
at least one `miningaddr`:

```text
[Application Options]
miningaddr=hs1qexampleaddress1
stratumlisten=127.0.0.1:12040
stratumuser=worker
stratumpass=secret
stratumdifficulty=1
```

The server uses Stratum JSON line framing and the standard
`mining.subscribe`, `mining.authorize`, and `mining.submit` method names.
When authentication is configured, jobs are sent after successful
`mining.authorize`.
Because Handshake mining mutates the 236-byte Handshake header, `mining.notify`
uses this Handshake-specific parameter shape:

```json
[
  "job_id",
  "serialized_header_template_hex",
  "share_target_hex",
  12345,
  true
]
```

`mining.submit` parameters are:

```json
["worker", "job_id", "extranonce2_hex", "ntime_hex", "nonce_hex"]
```

`extranonce2_hex` must be 16 bytes. `ntime_hex` may be 4 or 8 bytes.
`nonce_hex` is 4 bytes. Time and nonce values are parsed as unsigned
big-endian hex strings before being written to the Handshake header fields. The
server reconstructs the candidate block, validates the Handshake PoW hash
against the configured share target, and only submits the block to normal node
validation when the hash also meets the network target.

Binding Stratum to non-loopback interfaces requires `stratumallowpublic=1`.
When public binding is enabled, `stratumuser` and `stratumpass` are required.
