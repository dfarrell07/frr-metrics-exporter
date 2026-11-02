# Agent instructions

Prometheus exporter for an FRR running outside Kubernetes: BGP, BFD and EVPN metrics read through
`vtysh`, served over TLS 1.3 with optional mTLS. Read README.md first; this file is what it omits.

## Layout

- `collector/`: the whole FRR side (no HTTP, TLS or flags). `collector.go` has `Collector`, `Runner`,
  `Select`, `Gather`, `Snapshot`; `bgp.go`, `bfd.go`, `evpn.go` each read, parse and build one
  complete result; `vtysh.go` is the runner. Mirrors frr-k8s's `cmd/metrics/collector` so it can be
  ported by copying the directory. `collector/testdata/` is real FRR 10.4.3 output.
- Root package: `main.go` (flags, wiring, `run`), `exporter.go` (scrape handler: one deadline, scrape
  slots), `tls.go` (cert and CA reload).
- `hack/load.py`: complete binary/mTLS scrape qualification using expanded real fixtures, two
  scrapers, stalled readers, CPU/RSS measurements and recovery; needs Linux, Python 3 and openssl.
- `hack/smoke.sh` (`make smoke`): two real FRR containers with BGP, BFD, L2 and L3 VNIs. Needs podman,
  openssl, curl. `SMOKE_DUMP=file` saves the scrape; `FRR_IMAGE=` picks the image.

## Commands

`make check` (gofmt, vet, `go test -race`), `make smoke`, `make vuln`, `make build`.
Run all four before committing. Sign off commits (`git commit -s`).

## Rules that keep it small and correct

- Series names, types and BGP labels follow frr-k8s's exporter (`frrk8s_` prefix) so dashboards carry
  over. New series use the names in the EGA plan (`frrk8s_bgp_family_*`, `frrk8s_evpn_*`,
  `frrk8s_scrape_collector_*`). Do not rename.
- A field FRR does not report is omitted, never 0 (use pointers). A failed collector emits only its
  status. Never add an option, series or file without a test or fixture that needs it.
- New parsing assumptions need a real FRR capture in `collector/testdata/`, not hand-written JSON.
- Every new behavior needs a test, and the test must fail when the behavior is removed: mutate the
  code and check. Past misses: `limitBuffer` must not embed `bytes.Buffer` (`io.Copy` bypasses
  `Write`); a test client with a short timeout hid a missing `srv.Close()`.
- vtysh stdout only (stderr is error context). Use `Vtysh{Path: "/usr/bin/vtysh"}` (or the configured
  executable path); no package globals.
- Shell: this environment's zsh does not word-split `$var`; write flags out.

## Where the rest lives (EGA repo, github.com/openshift/evpn-gateway-appliance)

- `plans/context/evpn-aws/frr-metrics-plan.md` and `frr-metrics-details.md`: requirements, FRR JSON
  facts, slices and open asks; the details file maps the internal prototype's checks to signals.
- `plans/context/evpn-aws/kickoff-decisions.md`: decision 10 (preferred home for these metrics is the
  Red Hat-built `frr-metrics` image, so this repo is the fallback and a reference/fixture source) and 16.
- Branch `corenet-7504-monitoring-drafts`: alert rules, panels and promtool tests that read these
  series; `ega-alerts_exporter_test.yaml` feeds real exporter output through them.
- Upstream: metallb/frr-k8s issue 518 and PR 519 (`--disable-metrics-auth`); the 2026-11-02 reply
  accepts the flag's isolation but discourages further divergence. The delivery choice is open.
- Jira CORENET-7504 acceptance criteria are the requirements (via `acli jira workitem view`).

## Open

The EVPN collector includes per-VTEP membership and local ES operational/DF state. ES detail
fixtures and `make smoke` cover elected roles, down, bypass, remote-only, unready and pending
election states; raw `df` is not enough to emit a role. BFD RTT still needs a latency-source
decision (FRR's echo-window minimum is capped and zero can mean no samples). Appliance unit
and scrape wiring belong in the EGA collection and wait on decision 10 and the scrape-path choice.
