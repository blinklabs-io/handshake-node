# This Dockerfile builds handshake-node from source and creates a small (55 MB) docker container based on alpine linux.
#
# Clone this repository and run the following command to build and tag a fresh handshake-node amd64 container:
#
# docker build . -t yourregistry/handshake-node
#
# You can use the following command to build an arm64v8 container:
#
# docker build . -t yourregistry/handshake-node --build-arg ARCH=arm64v8
#
# For more information how to use this docker image visit:
# https://github.com/blinklabs-io/handshake-node/tree/master/docs
#
# 12038  Mainnet Handshake peer-to-peer port
# 12037  Mainnet RPC port

ARG ARCH=amd64
# using the SHA256 instead of tags
# https://github.com/opencontainers/image-spec/blob/main/descriptor.md#digests
# https://cloud.google.com/architecture/using-container-images
# https://github.com/google/go-containerregistry/blob/main/cmd/crane/README.md
# ➜  ~ crane digest golang:1.23.12-alpine3.21
# sha256:4bb4be21ac98da06bc26437ee870c4973f8039f13e9a1a36971b4517632b0fc6
FROM golang@sha256:4bb4be21ac98da06bc26437ee870c4973f8039f13e9a1a36971b4517632b0fc6 AS build-container

ARG ARCH

ADD . /app
WORKDIR /app
RUN set -ex \
  && if [ "${ARCH}" = "amd64" ]; then export GOARCH=amd64; fi \
  && if [ "${ARCH}" = "arm32v7" ]; then export GOARCH=arm; fi \
  && if [ "${ARCH}" = "arm64v8" ]; then export GOARCH=arm64; fi \
  && echo "Compiling for $GOARCH" \
  && go install -v . ./cmd/...

FROM $ARCH/alpine:3.21

COPY --from=build-container /go/bin /bin

VOLUME ["/root/.handshake-node"]

EXPOSE 12038 12037

ENTRYPOINT ["handshake-node"]
