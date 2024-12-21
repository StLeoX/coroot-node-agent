NODE_AGENT_VERSION ?= latest

# 发版之前：1.格式化。2.重新编译eBPF程序。3.运行单测。
.PHONY: all
all: lint build test

.PHONY: lint
lint: go-mod go-vet go-fmt go-imports

.PHONY: build
build: ebpf-build go-build

.PHONY: build-fast
build-fast: go-build

.PHONY: test
test: go-test

##### Basics
.PHONY: docker
docker: ebpf-build
	docker build --build-arg VERSION=$(NODE_AGENT_VERSION) -t registry.cn-beijing.aliyuncs.com/obser/coroot-node-agent:$(NODE_AGENT_VERSION) .

.PHONY: ebpf-build
ebpf-build:
	# rm ./ebpftracer/ebpf.go
	make -C ./ebpftracer ebpf.go

.PHONY: go-build
go-build:
	CGO_ENABLED=1 go build -mod=readonly -ldflags "-X main.version=$(NODE_AGENT_VERSION)" -o coroot-node-agent .

.PHONY: go-mod
go-mod:
	go mod tidy

.PHONY: go-vet
go-vet:
	go vet ./...

.PHONY: go-fmt
go-fmt:
	gofmt -w .

.PHONY: go-imports
go-imports:
	go install golang.org/x/tools/cmd/goimports@latest
	goimports -w .

.PHONY: go-test
go-test:
	go test ./...
