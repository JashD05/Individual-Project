.PHONY: build test lint clean tidy setup-cluster teardown-cluster integration-test docker-build kind-load docker-image

BINARY    := bin/chaos-sec
CMD       := ./cmd/chaos-sec/
IMAGE_TAG := chaos-sec:latest
CLUSTER   := chaos-sec

## build: Compile the chaos-sec binary
build:
	@mkdir -p bin
	go build -o $(BINARY) $(CMD)
	@echo "Built: $(BINARY)"

## docker-build: Build the chaos-sec Docker image
docker-build:
	docker build -t $(IMAGE_TAG) .
	@echo "Image built: $(IMAGE_TAG)"

## kind-load: Load the Docker image into the Kind cluster
kind-load:
	kind load docker-image $(IMAGE_TAG) --name $(CLUSTER)
	@echo "Image loaded into Kind cluster '$(CLUSTER)'"

## docker-image: Build and load image into Kind in one step
docker-image: docker-build kind-load

## test: Run all unit tests with race detector
test:
	go test ./... -v -race -count=1

## test-cover: Run tests and show coverage summary
test-cover:
	go test ./internal/... -race -count=1 -coverprofile=coverage.out
	go tool cover -func=coverage.out

## lint: Run go vet
lint:
	go vet ./...

## clean: Remove build artefacts
clean:
	rm -rf bin/ coverage.out

## tidy: Tidy go.mod and go.sum
tidy:
	go mod tidy

## setup-cluster: Create Kind cluster with Calico + Falco (Phase 2)
setup-cluster:
	./scripts/setup-cluster.sh

## teardown-cluster: Delete the Kind cluster
teardown-cluster:
	./scripts/teardown-cluster.sh

## integration-test: Full end-to-end cluster test (builds Docker image, loads into Kind)
integration-test: docker-image
	./scripts/integration-test.sh

## analyse: Run Phase 3 data analysis (requires results/ to be populated)
analyse:
	python3 scripts/analyse-results.py


	@grep -E '^## ' Makefile | sed 's/## //'
