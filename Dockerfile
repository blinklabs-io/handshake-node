FROM golang:1.27.1-bookworm@sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195 AS build

ARG VERSION
ARG COMMIT_HASH
ENV VERSION=${VERSION}
ENV COMMIT_HASH=${COMMIT_HASH}

WORKDIR /code
COPY . .
RUN GOBIN=/out make release-install

FROM alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6

ARG VERSION
ARG COMMIT_HASH

LABEL org.opencontainers.image.title="handshake-node" \
      org.opencontainers.image.description="Handshake blockchain full node" \
      org.opencontainers.image.source="https://github.com/blinklabs-io/handshake-node" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT_HASH}"

# The alpine:3.24.1 image predates openssl 3.5.8-r0, which fixes
# CVE-2026-14456. Take the patched libcrypto3/libssl3 from the v3.24
# package repository.
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
