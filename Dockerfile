FROM golang:1.26.6-bookworm@sha256:116d58cbd88c1297624acc6e967a060012422bacf9930927e23fb719189c6f36 AS build

WORKDIR /code
COPY . .
RUN GOBIN=/out make release-install

FROM alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

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
