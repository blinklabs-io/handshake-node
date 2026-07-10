FROM ghcr.io/blinklabs-io/go:1.26.3-1 AS build

WORKDIR /code
COPY . .
RUN GOBIN=/out make release-install

FROM alpine:3.21

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
