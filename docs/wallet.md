# Wallet

handshake-node was intentionally developed without an integrated wallet for security
reasons.  Please see [bursa](https://github.com/blinklabs-io/bursa) for more
information.

## Bursa Integration Contract

Bursa owns keys, signing, account state, coin selection, and balance tracking.
handshake-node owns chain validation, UTXO lookup, mempool admission, block
notifications, name state, and block production.

The wallet should connect to handshake-node over authenticated JSON-RPC.  The
default node RPC endpoint is `localhost:12037` on mainnet and `localhost:18334`
on regtest.  TLS is enabled by default unless the node is explicitly configured
with `notls=1` on localhost.

Required chain RPCs:

| RPC | Purpose |
| --- | --- |
| `gettxout` | Query spendable UTXOs by outpoint. |
| `sendrawtransaction` | Submit signed transactions to the mempool. |
| `getrawtransaction` | Fetch transaction details when the tx index is enabled. |
| `getblock`, `getblockheader`, `getblockhash` | Track confirmations and chain reorganizations. |
| `getnameinfo`, `getnamebyhash`, `getnameresource`, `getauctioninfo` | Query current name lifecycle and resource state. |
| `getnameproof`, `verifynameproof` | Build and verify Urkel name proofs for light-client workflows. |

Covenant construction RPCs return unsigned transaction hex.  Bursa supplies
explicit inputs, signs the returned transaction, and broadcasts it with
`sendrawtransaction`.

| RPC | Covenant |
| --- | --- |
| `createopen` | OPEN |
| `createbid` | BID |
| `createreveal` | REVEAL |
| `createredeem` | REDEEM |
| `createregister` | REGISTER |
| `createupdate` | UPDATE |
| `createrenew` | RENEW |
| `createtransfer` | TRANSFER |
| `createfinalize` | FINALIZE |
| `createrevoke` | REVOKE |

Websocket subscriptions:

| RPC | Notification |
| --- | --- |
| `notifyblocks` | `blockconnected`, `blockdisconnected`, filtered block events. |
| `notifynewtransactions` | `txaccepted` or `txacceptedverbose`. |
| `notifynames` | `nameupdated` for matching name covenant activity. |

Handshake wallet derivation uses BIP-44 coin type `5353`:

```text
m/44'/5353'/account'/change/index
```
