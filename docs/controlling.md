# Controlling and querying handshake-node via hnsctl

hnsctl is a command line utility that can be used to both control and query handshake-node
via [RPC](http://www.wikipedia.org/wiki/Remote_procedure_call).  handshake-node enables
its RPC server when either admin credentials (`rpcuser` and `rpcpass`) or
limited credentials (`rpclimituser` and `rpclimitpass`) are configured.  The
default config generator writes random admin credentials into
`handshake-node.conf`; custom configs must include credentials explicitly or
the RPC server is disabled.

* handshake-node.conf configuration file

```bash
[Application Options]
rpcuser=myuser
rpcpass=SomeDecentp4ssw0rd
rpclimituser=mylimituser
rpclimitpass=Limitedp4ssw0rd
```

* hnsctl.conf configuration file

```bash
[Application Options]
rpcuser=myuser
rpcpass=SomeDecentp4ssw0rd
```

OR

```bash
[Application Options]
rpclimituser=mylimituser
rpclimitpass=Limitedp4ssw0rd
```

For a list of available options, run: `$ hnsctl --help`
