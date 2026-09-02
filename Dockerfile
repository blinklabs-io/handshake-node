FROM golang:1.27.0-bookworm@sha256:ded31c68586d2e49e760acc2e65a884b23d032e9bbbed0ae0c55abd3fcaf4452 AS build

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
