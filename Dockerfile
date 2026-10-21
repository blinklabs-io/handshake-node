FROM ghcr.io/blinklabs-io/go:1.27.3-1 AS build

ARG VERSION
ARG COMMIT_HASH
ENV VERSION=${VERSION}
ENV COMMIT_HASH=${COMMIT_HASH}

WORKDIR /code
COPY . .
RUN GOBIN=/out make release-install

FROM debian:bookworm-slim

ARG VERSION
ARG COMMIT_HASH

LABEL org.opencontainers.image.title="handshake-node" \
      org.opencontainers.image.description="Handshake blockchain full node" \
      org.opencontainers.image.source="https://github.com/blinklabs-io/handshake-node" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT_HASH}"

RUN apt-get update -y && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/* && \
    groupadd --system --gid 101 handshake && \
    useradd --system --uid 100 --gid handshake \
      --create-home --home-dir /home/handshake handshake && \
    mkdir -p /data && \
    ln -s /data /home/handshake/.handshake-node && \
    chown handshake:handshake /data

COPY --from=build /out/handshake-node /out/hnsctl /bin/

ENV HOME=/home/handshake
# Keep Go runtime-managed memory below the supported 8 GiB container budget
# while leaving room for the block index, database, file cache, and other
# non-Go allocations. Operators can override this for a different budget.
ENV GOMEMLIMIT=7GiB
WORKDIR /data
USER 100:101
VOLUME ["/data"]

EXPOSE 12038 12037

ENTRYPOINT ["/bin/handshake-node"]
