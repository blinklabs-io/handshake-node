# Developer Resources

* [Code Contribution Guidelines](https://github.com/blinklabs-io/handshake-node/tree/master/docs/code_contribution_guidelines.md)

* [JSON-RPC Reference](https://github.com/blinklabs-io/handshake-node/tree/master/docs/json_rpc_api.md)
  * [RPC Examples](https://github.com/blinklabs-io/handshake-node/tree/master/docs/json_rpc_api.md#ExampleCode)

* The handshake-node Go Packages:
  * [rpcclient](https://github.com/blinklabs-io/handshake-node/tree/master/rpcclient) - Implements a
    robust and easy to use Websocket-enabled JSON-RPC client
  * [hnsjson](https://github.com/blinklabs-io/handshake-node/tree/master/hnsjson) - Provides an extensive API
    for the underlying JSON-RPC command and return values
  * [wire](https://github.com/blinklabs-io/handshake-node/tree/master/wire) - Implements the
    wire protocol
  * [peer](https://github.com/blinklabs-io/handshake-node/tree/master/peer) -
    Provides a common base for creating and managing network peers.
  * [blockchain](https://github.com/blinklabs-io/handshake-node/tree/master/blockchain) -
    Implements block handling and chain selection rules
  * [blockchain/fullblocktests](https://github.com/blinklabs-io/handshake-node/tree/master/blockchain/fullblocktests) -
    Provides a set of block tests for testing the consensus validation rules
  * [txscript](https://github.com/blinklabs-io/handshake-node/tree/master/txscript) -
    Implements the transaction scripting language
  * [btcec](https://github.com/btcsuite/btcd/tree/master/btcec) - Implements
    support for the elliptic curve cryptographic functions needed for the
    scripts
  * [database](https://github.com/blinklabs-io/handshake-node/tree/master/database) -
    Provides a database interface for the block chain
  * [mempool](https://github.com/blinklabs-io/handshake-node/tree/master/mempool) -
    Package mempool provides a policy-enforced pool of unmined
    transactions.
  * [hnsutil](https://github.com/blinklabs-io/handshake-node/tree/master/hnsutil) - Provides
    convenience functions and types
  * [chainhash](https://github.com/blinklabs-io/handshake-node/tree/master/chaincfg/chainhash) -
    Provides a generic hash type and associated functions that allows the
    specific hash algorithm to be abstracted.
  * [connmgr](https://github.com/blinklabs-io/handshake-node/tree/master/connmgr) -
    Package connmgr implements a generic network connection manager.
