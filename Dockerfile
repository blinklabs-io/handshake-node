FROM golang:1.26.5-bookworm@sha256:1ecb7edf62a0408027bd5729dfd6b1b8766e578e8df93995b225dfd0944eb651 AS build

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

RUN addgroup -S handshake && \
    adduser -S -G handshake -h /home/handshake handshake && \
    mkdir -p /home/handshake/.handshake-node && \
    chown -R handshake:handshake /home/handshake

COPY --from=build /out/handshake-node /out/hnsctl /bin/

USER handshake
VOLUME ["/home/handshake/.handshake-node"]

EXPOSE 12038 12037

ENTRYPOINT ["/bin/handshake-node"]
