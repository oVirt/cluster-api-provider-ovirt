GIT_HOST = github.com/ovirt
PWD := $(shell pwd)
BASE_DIR := $(shell basename $(PWD))
TESTARGS_DEFAULT := "-v"
export TESTARGS ?= $(TESTARGS_DEFAULT)

HAS_LINT := $(shell command -v golint;)
HAS_GOX := $(shell command -v gox;)
GOX_PARALLEL ?= 3
TARGETS ?= darwin/amd64 linux/amd64 linux/386 linux/arm linux/arm64 linux/ppc64le

GOOS ?= $(shell go env GOOS)
VERSION ?= $(shell git describe --exact-match 2> /dev/null || \
                 git describe --match=$(git rev-parse --short=8 HEAD) --always --dirty --abbrev=8)
GOFLAGS   += -mod vendor
TAGS      :=
LDFLAGS   := "-w -s -X 'main.version=${VERSION}'"
REGISTRY ?= quay.io/ovirt

VERSION?=$(shell git describe --tags --always --match "v[0-9]*" | awk -F'-' '{print substr($$1,2) }')
RELEASE?=$(shell git describe --tags --always --match "v[0-9]*" | awk -F'-' '{if ($$2 != "") {print $$2 "." $$3} else {print 1}}')
VERSION_RELEASE=$(VERSION)$(if $(RELEASE),-$(RELEASE))

CLUSTER_API ?= github.com/openshift/cluster-api

.PHONY: vendor
vendor:
	go mod tidy
	go mod vendor
	go mod verify

$(GOBIN):
	echo "create gobin"
	mkdir -p $(GOBIN)

work: $(GOBIN)

#build: export BUILDAH_LAYERS=true
build:
	CGO_ENABLED=0 GOOS=$(GOOS) go build \
		-ldflags $(LDFLAGS) \
		-o bin/manager \
		vendor/$(CLUSTER_API)/cmd/manager/main.go
	CGO_ENABLED=0 GOOS=$(GOOS) go build \
		-ldflags $(LDFLAGS) \
		-o bin/machine-controller-manager \
		cmd/manager/main.go

test: unit functional

check: depend fmt vet lint

unit: depend
	go test -tags=unit $(shell go list ./...) $(TESTARGS)

functional:
	@echo "$@ not yet implemented"

fmt:
	hack/verify-gofmt.sh

lint:
ifndef HAS_LINT
		go get -u golang.org/x/lint/golint
		echo "installing golint"
endif
	hack/verify-golint.sh

vet:
	go vet ./...

cover: depend
	go test -tags=unit $(shell go list ./...) -cover

docs:
	@echo "$@ not yet implemented"

godoc:
	@echo "$@ not yet implemented"

releasenotes:
	@echo "Reno not yet implemented for this repo"

translation:
	@echo "$@ not yet implemented"

# Do the work here

# Set up the development environment
env:
	@echo "PWD: $(PWD)"
	@echo "BASE_DIR: $(BASE_DIR)"
	@echo "GOPATH: $(GOPATH)"
	@echo "GOROOT: $(GOROOT)"
	@echo "DEST: $(DEST)"
	@echo "PKG: $(PKG)"
	go version
	go env

clean:
	rm -rf _dist bin/manager bin/clusterctl

realclean: clean
	rm -rf vendor
	if [ "$(GOPATH)" = "$(GOPATH_DEFAULT)" ]; then \
		rm -rf $(GOPATH); \
	fi

shell:
	$(SHELL) -i

# Generate code
generate:
	go generate ./pkg/... ./cmd/...

DOCKERFILE=Dockerfile
images:
	podman build \
		-t $(REGISTRY)/origin-ovirt-machine-controllers:$(VERSION_RELEASE) \
		--build-arg version=$(VERSION) \
		--build-arg release=$(RELEASE) \
		-f $(DOCKERFILE) \
		$(DIR)

ovirt-cluster-api-controller: manager

ifeq ($(GOOS),linux)
	cp bin/manager cmd/manager
	docker build -t $(REGISTRY)/ovirt-cluster-api-controller:$(VERSION) cmd/manager
	rm cmd/manager/manager
else
	$(error Please set GOOS=linux for building the image)
endif

upload-images: images
	@echo "push images to $(REGISTRY)"
	docker login -u="$(DOCKER_USERNAME)" -p="$(DOCKER_PASSWORD)";
	docker push $(REGISTRY)/ovirt-cluster-api-controller:$(VERSION)

version:
	@echo ${VERSION}

.PHONY: build-cross
build-cross: LDFLAGS += -extldflags "-static"
build-cross: depend
ifndef HAS_GOX
	go get -u github.com/mitchellh/gox
endif
	CGO_ENABLED=0 gox -parallel=$(GOX_PARALLEL) -output="_dist/{{.OS}}-{{.Arch}}/{{.Dir}}" -osarch='$(TARGETS)' $(GOFLAGS) $(if $(TAGS),-tags '$(TAGS)',) -ldflags '$(LDFLAGS)' $(GIT_HOST)/$(BASE_DIR)/cmd/ovirt-machine-controller/

.PHONY: dist
dist: build-cross
	( \
		cd _dist && \
		$(DIST_DIRS) cp ../LICENSE {} \; && \
		$(DIST_DIRS) cp ../README.md {} \; && \
		$(DIST_DIRS) tar -zcf cluster-api-provider-ovirt-$(VERSION)-{}.tar.gz {} \; && \
		$(DIST_DIRS) zip -r cluster-api-provider-ovirt-$(VERSION)-{}.zip {} \; \
	)

.PHONY: build clean cover depend docs fmt functional lint realclean \
	relnotes test translation version build-cross dist
