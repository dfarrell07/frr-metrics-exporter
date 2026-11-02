.PHONY: check build smoke vuln
check:
	@unformatted=$$(gofmt -l .) || exit $$?; \
		test -z "$$unformatted" || { printf '%s\n' "$$unformatted"; exit 1; }
	go vet ./...
	go test -race ./...

build:
	CGO_ENABLED=0 go build -trimpath -o frr-metrics-exporter .

# Needs podman, openssl and curl; pulls an FRR image on first use.
smoke:
	hack/smoke.sh

# Needs network access to the Go vulnerability database.
vuln:
	go run golang.org/x/vuln/cmd/govulncheck@v1.1.4 ./...
