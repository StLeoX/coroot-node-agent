FROM golang:1.23-bullseye AS builder
RUN apt update && apt install -y libsystemd-dev
WORKDIR /tmp/src
COPY go.mod .
COPY go.sum .
RUN export GOPROXY='https://goproxy.cn' && go mod download
COPY . .
ARG VERSION=latest
RUN export NODE_AGENT_VERSION=$VERSION && make go-build

FROM debian:bullseye
RUN apt update && apt install -y ca-certificates

COPY --from=builder /tmp/src/coroot-node-agent /usr/bin/coroot-node-agent

ENTRYPOINT ["coroot-node-agent"]
