FROM ghcr.io/blinklabs-io/go:1.27.3-1@sha256:3e5e8c2d5b52421d1d54d49a607463deca214b27fb1b0378b1aa883d1e6cfe1e AS build

ARG VERSION
ARG COMMIT_HASH
ENV VERSION=${VERSION}
ENV COMMIT_HASH=${COMMIT_HASH}

WORKDIR /code
COPY . .
RUN GOBIN=/out make release-install

FROM alpine:3.24.3@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a

ARG VERSION
ARG COMMIT_HASH

LABEL org.opencontainers.image.title="handshake-node" \
      org.opencontainers.image.description="Handshake blockchain full node" \
      org.opencontainers.image.source="https://github.com/blinklabs-io/handshake-node" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT_HASH}"

# The base image predates openssl 3.5.8-r0, which fixes CVE-2026-14456.
RUN apk add --no-cache "libcrypto3>=3.5.8-r0" "libssl3>=3.5.8-r0"

RUN addgroup -S -g 101 handshake && \
    adduser -S -u 100 -G handshake -h /home/handshake handshake && \
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
