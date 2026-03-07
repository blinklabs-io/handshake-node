# Mining

handshake-node supports the `getblocktemplate` RPC.
The limited user cannot access this RPC.

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
