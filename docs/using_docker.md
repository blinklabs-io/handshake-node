# Using Docker

- [Using Docker](#using-docker)
  - [Introduction](#introduction)
  - [Docker volumes](#docker-volumes)
  - [Configurationless mainnet defaults](#configurationless-mainnet-defaults)
  - [Resource sizing and monitoring](#resource-sizing-and-monitoring)
  - [Diagnosing restart loops](#diagnosing-restart-loops)
  - [Examples](#examples)
    - [Preamble](#preamble)
    - [Full node without RPC port](#full-node-without-rpc-port)
    - [Full node with RPC port](#full-node-with-rpc-port)
    - [Full node with RPC port running on regtest](#full-node-with-rpc-port-running-on-regtest)

## Introduction

With Docker you can easily set up *handshake-node* to run your Handshake full node. You can find the official *handshake-node* Docker images on Docker Hub [blinklabs/handshake-node](https://hub.docker.com/r/blinklabs/handshake-node). The Docker source file of this image is located at [Dockerfile](https://github.com/blinklabs-io/handshake-node/blob/master/Dockerfile).

This documentation focuses on running Docker container with *docker-compose.yml* files. These files are better to read and you can use them as a template for your own use. For more information about Docker and Docker compose visit the official [Docker documentation](https://docs.docker.com/).

## Docker volumes

**Special diskspace hint**: The following examples are using a Docker managed volume. The volume is named *handshake-node-data* This will use a lot of disk space, because it contains the full Handshake blockchain. Please make yourself familiar with [Docker volumes](https://docs.docker.com/storage/volumes/).

The *handshake-node-data* volume will be reused, if you upgrade your *docker-compose.yml* file. Keep in mind, that it is not automatically removed by Docker, if you delete the handshake-node container. If you don't need the volume anymore, please delete it manually with the command:

```bash
docker volume ls
docker volume rm handshake-node-data
```

For binding a local folder to your *handshake-node* container please read the [Docker documentation](https://docs.docker.com/). The preferred way is to use a Docker managed volume.

## Configurationless mainnet defaults

The image does not require or ship a configuration file. With no arguments it
runs an archival mainnet full node, listens for P2P connections on port 12038,
uses DNS peer discovery and built-in checkpoints, enables Brontide, and stores
node state in the `/data` volume.

RPC remains disabled until both `HANDSHAKE_NODE_RPCUSER` and
`HANDSHAKE_NODE_RPCPASS` are set. To reach RPC through a published container
port, also set `HANDSHAKE_NODE_RPCLISTEN=0.0.0.0:12037`. RPC remains
authenticated and TLS-enabled. Publish the host-side RPC port only on a trusted
interface.

Operators who need non-default settings can place
`handshake-node.conf` at `/data/handshake-node.conf` or pass an explicit
`--configfile` argument.

The examples below use the rolling `main` image so they stay aligned with this
documentation. Pin a release tag instead for production deployments.

The process runs as non-root UID 100 and GID 101, matching other Blink Labs
node images. Docker-managed volumes inherit the correct ownership from the
image. For a bind mount, make the host directory writable by that identity
before starting the container:

```bash
sudo install -d -o 100 -g 101 /path/to/handshake-data
# For an existing directory:
sudo chown -R 100:101 /path/to/handshake-data
```

Existing deployments that mount
`/home/handshake/.handshake-node` remain compatible, but new deployments
should mount `/data`.

## Resource sizing and monitoring

Allocate four CPUs, 8 GiB of memory, and SSD-backed storage for initial mainnet
sync. Eight GiB is the supported container memory limit, not a Go heap target:
the defaults include a 250 MiB UTXO cache, a 100 MiB database cache, and up to
128 MiB of aggregate P2P queues. The mempool has a separate 100,000,000-byte
retained-memory estimate limit. The block index, Go runtime, database, file
cache, and transient validation allocations share the remaining container
memory.
The official image sets the Go runtime soft memory limit to `GOMEMLIMIT=7GiB` by
default. Treat the remaining approximately 1 GiB as a planning margin for
non-Go allocations; it is not reserved, and non-Go memory can consume or exceed
it. Override `GOMEMLIMIT` only when the container memory budget is sized
accordingly; it is a Go runtime target, not a hard limit on total container memory.
`GOMAXPROCS` or the container CPU limit controls CPU concurrency; it does not
limit memory.

Docker Compose can enforce the intended limits explicitly:

```yaml
services:
  handshake-node:
    cpus: 4.0
    mem_limit: 8g
    memswap_limit: 8g
```

Setting the memory and memory-plus-swap limits to the same value prevents the
node from exceeding the 8 GiB budget through swap.

Use `docker stats handshake-node` to observe total container CPU and resident
memory. For Go runtime detail, enable the Prometheus endpoint and scrape
`/metrics`. Keep the published metrics port on the host loopback unless it is
protected by a trusted network:

```yaml
services:
  handshake-node:
    ports:
      - 127.0.0.1:12039:12039
    environment:
      HANDSHAKE_NODE_METRICSLISTEN: "0.0.0.0:12039"
      HANDSHAKE_NODE_METRICSALLOWPUBLIC: "true"
```

The `handshake_go_*` metrics report Go heap, stack, runtime memory, goroutines,
GC cycles, `GOMAXPROCS`, and the Go soft memory limit.
`handshake_mempool_memory_usage_bytes` and
`handshake_mempool_memory_limit_bytes` report the mempool's retained-memory
estimate and configured bound. Container resident memory also includes non-Go
allocations and file-backed mappings, so alert on the container metric rather
than treating Go heap or the mempool estimate as total memory.

## Diagnosing restart loops

The examples use `restart: unless-stopped`, which can hide the exit that caused
a restart. Inspect the container state, Docker events, logs, and guest kernel
before deleting or replacing the data volume:

```bash
docker inspect handshake-node \
  --format 'status={{.State.Status}} exit={{.State.ExitCode}} oom={{.State.OOMKilled}} error={{.State.Error}} restarts={{.RestartCount}}'
docker inspect handshake-node \
  --format 'memory={{.HostConfig.Memory}} swap={{.HostConfig.MemorySwap}} cpus={{.HostConfig.NanoCpus}}'
docker logs --tail 300 handshake-node
docker events --since 30m --filter container=handshake-node
dmesg -T | grep -Ei 'oom|out of memory|killed process'
```

An OOM indication or exit code 137 means the process was killed for memory
pressure. Exit code 1 indicates a node error that should also appear in the
logs, 139 indicates a segmentation fault, and 143 indicates an external
`SIGTERM`. A restart followed by `Detected unclean shutdown` without a node
fatal or shutdown log usually indicates an external hard kill.

If the host becomes unresponsive while container CPU remains within its quota,
check storage latency and I/O wait with `vmstat 1` and `iostat -xz 1`. Initial
sync periodically performs synchronous UTXO and database flushes.

## Examples

### Preamble

All following examples uses some defaults:

- container_name: handshake-node
  Name of the docker container that is be shown by e.g. ```docker ps -a```

- hostname: handshake-node **(very important to set a fixed name before first start)**
  The internal hostname in the docker container. By default, docker is recreating the hostname every time you change the *docker-compose.yml* file. The default hostnames look like *ef00548d4fa5*. This is a problem when using the *handshake-node* RPC port. The RPC port is using a certificate to validate the hostname. If the hostname changes you need to recreate the certificate. To avoid this, you should set a fixed hostname before the first start. This ensures, that the docker volume is created with a certificate with this hostname.

- restart: unless-stopped
  Starts the *handshake-node* container when Docker starts, except that when the container is stopped (manually or otherwise), it is not restarted even after Docker restarts.

To use the following examples create an empty directory. In this directory create a file named *docker-compose.yml*, copy and paste the example into the *docker-compose.yml* file and run it.

```bash
mkdir ~/handshake-node-docker
cd ~/handshake-node-docker
touch docker-compose.yaml
nano docker-compose.yaml (use your favourite editor to edit the compose file)
docker-compose up (creates and starts a new handshake-node container)
```

With the following commands you can control *docker-compose*:

```docker-compose up -d``` (creates and starts the container in background)

```docker-compose down``` (stops and delete the container. **The docker volume handshake-node-data will not be deleted**)

```docker-compose stop``` (stops the container)

```docker-compose start``` (starts the container)

```docker ps -a``` (list all running and stopped container)

```docker volume ls``` (lists all docker volumes)

```docker logs handshake-node``` (shows the log )

```docker-compose help``` (brings up some helpful information)

### Full node without RPC port

Let's start with an easy example. If you just want to create a full node without the need of using the RPC port, you can use the following example. This example will launch *handshake-node* and exposes only the default p2p port 12038 to the outside world:

```yaml
version: "2"

services:
  handshake-node:
    container_name: handshake-node
    hostname: handshake-node
    image: blinklabs/handshake-node:main
    restart: unless-stopped
    volumes:
      - handshake-node-data:/data
    ports:
      - 12038:12038

volumes:
  handshake-node-data:
```

### Full node with RPC port

To use the RPC port of *handshake-node* you need to specify a *username* and a
very strong *password*. This example publishes RPC only on the host loopback
interface. Use a VPN or another trusted network path for remote access.

```yaml
version: "2"

services:
  handshake-node:
    container_name: handshake-node
    hostname: handshake-node
    image: blinklabs/handshake-node:main
    restart: unless-stopped
    volumes:
      - handshake-node-data:/data
    ports:
      - 12038:12038
      - 127.0.0.1:12037:12037
    environment:
      HANDSHAKE_NODE_RPCUSER: "[CHOOSE_A_USERNAME]"
      HANDSHAKE_NODE_RPCPASS: "[CREATE_A_VERY_HARD_PASSWORD]"
      HANDSHAKE_NODE_RPCLISTEN: "0.0.0.0:12037"

volumes:
  handshake-node-data:
```

### Full node with RPC port running on regtest

To run a node on regtest, provide the `--regtest` argument. The default ports
for regtest are 14038 (P2P) and 14037 (RPC):

```yaml
version: "2"

services:
  handshake-node:
    container_name: handshake-node
    hostname: handshake-node
    image: blinklabs/handshake-node:main
    restart: unless-stopped
    volumes:
      - handshake-node-data:/data
    ports:
      - 14038:14038
      - 127.0.0.1:14037:14037
    command: [
        "--regtest",
        "--listen=:14038",
        "--rpclisten=0.0.0.0:14037"
    ]
    environment:
      HANDSHAKE_NODE_RPCUSER: "[CHOOSE_A_USERNAME]"
      HANDSHAKE_NODE_RPCPASS: "[CREATE_A_VERY_HARD_PASSWORD]"

volumes:
  handshake-node-data:
```
