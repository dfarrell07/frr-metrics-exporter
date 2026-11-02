#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Linux end-to-end exporter qualification: make build && python3 hack/load.py.

Replay expanded real fixtures through subprocesses; includes collection, registry,
encoding and mTLS, but not FRR daemon query cost. No production options are added.
"""
import concurrent.futures
import gzip
import http.client
import ipaddress
import json
import math
import os
from pathlib import Path
import shlex
import signal
import socket
import ssl
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "collector/testdata"
CPUS = sorted(os.sched_getaffinity(0))[:2]


def fixture(name):
    return json.loads((FIXTURES / name).read_text())


def usage(pid):
    fields = Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()
    status = dict(line.split(":", 1) for line in Path(f"/proc/{pid}/status").read_text().splitlines())
    return {"cpu_s": sum(int(fields[i]) for i in (11, 12, 13, 14)) / os.sysconf("SC_CLK_TCK"),
            "rss_mib": int(status["VmRSS"].split()[0]) / 1024,
            "peak_rss_mib": int(status["VmHWM"].split()[0]) / 1024}


with tempfile.TemporaryDirectory(prefix="frr-load-") as directory:
    work = Path(directory)
    neighbor = fixture("bgp_neighbors.json")["default"]["10.78.0.3"]
    peers = {str(ipaddress.IPv4Address(int(ipaddress.IPv4Address("10.128.0.1")) + i)): neighbor
             for i in range(2000)}
    (work / "bgp").write_text(json.dumps({"default": peers}))
    vteps = [str(ipaddress.IPv4Address(int(ipaddress.IPv4Address("10.200.0.1")) + i)) for i in range(256)]
    vnis = {str(10001 + i): dict(fixture("evpn_vni_membership.json")["10100"],
            vni=10001 + i, vxlanIf=f"vxlan{10001+i}", numRemoteVteps=256, remoteVteps=vteps)
            for i in range(64)}
    (work / "evpn").write_text(json.dumps(vnis))
    commands = {"show bgp vrf all neighbors json": work / "bgp",
                "show evpn vni json": work / "evpn",
                "show evpn es detail json": FIXTURES / "evpn_es_df.json",
                "show bfd peers json": FIXTURES / "bfd_peers.json",
                "show bfd peers counters json": FIXTURES / "bfd_counters.json"}
    runner = work / "vtysh"
    calls = work / "calls"
    runner.write_text("#!/bin/sh\nprintf '%s\\n' \"$4\" >> " + shlex.quote(str(calls)) +
                      '\ncase "$4" in\n' + "".join(
                          f"{shlex.quote(command)}) exec cat {shlex.quote(str(path))};;\n"
                          for command, path in commands.items()) + "*) exit 1;;\nesac\n")
    runner.chmod(0o700)
    cert, key = work / "cert", work / "key"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                    "-nodes", "-keyout", str(key), "-out", str(cert), "-days", "1", "-subj", "/CN=load",
                    "-addext", "subjectAltName=IP:127.0.0.1", "-addext", "extendedKeyUsage=serverAuth,clientAuth"],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    context = ssl.create_default_context(cafile=str(cert))
    context.load_cert_chain(str(cert), str(key))
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    with (work / "server.log").open("w+") as log:
        server = subprocess.Popen([str(ROOT / "frr-metrics-exporter"), "--listen", f"127.0.0.1:{port}",
                                   "--tls-cert-file", str(cert), "--tls-key-file", str(key),
                                   "--tls-client-ca-file", str(cert), "--vtysh", str(runner)],
                                  env=dict(os.environ, GOMAXPROCS="2"), stderr=log,
                                  preexec_fn=lambda: os.sched_setaffinity(0, CPUS))
        held = []
        try:
            def scrape(client, encoding="identity", expected=200):
                start = time.monotonic()
                client.request("GET", "/metrics", headers={"Accept-Encoding": encoding,
                               "X-Prometheus-Scrape-Timeout-Seconds": "8"})
                response = client.getresponse()
                wire = response.read()
                assert response.status == expected, (response.status, wire[:200])
                if expected == 200:
                    body = gzip.decompress(wire) if response.getheader("Content-Encoding") == "gzip" else wire
                    for collector in ("bgp", "bfd", "evpn"):
                        assert f'frrk8s_scrape_collector_success{{collector="{collector}"}} 1\n'.encode() in body
                    samples = [line for line in body.splitlines() if line.startswith(b"frrk8s_")]
                    assert len(samples) == 50658, len(samples)
                return time.monotonic() - start, len(wire)

            def client():
                return http.client.HTTPSConnection("127.0.0.1", port, context=context, timeout=8)

            for _ in range(100):
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                        break
                except OSError:
                    assert server.poll() is None, "exporter exited"
                    time.sleep(0.05)
            print(json.dumps({"scale": {"bgp_peers": 2000, "l2_vnis": 64, "vteps_per_vni": 256,
                                       "bfd_sessions": 1, "local_es": 1, "frr_samples": 50658},
                              "cpus": CPUS, "gomaxprocs": 2,
                              "input_bytes": {name: path.stat().st_size for name, path in commands.items()}}), flush=True)

            def phase(name, encoding):
                before, started = usage(server.pid), time.monotonic()
                def worker():
                    connection = client()
                    try:
                        results = []
                        for _ in range(10):
                            tick = time.monotonic()
                            results.append(scrape(connection, encoding))
                            time.sleep(max(0, 1 - (time.monotonic() - tick)))
                        return results
                    finally:
                        connection.close()
                with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                    jobs = [pool.submit(worker) for _ in range(2)]
                    results = [sample for job in jobs for sample in job.result()]
                elapsed, after = time.monotonic() - started, usage(server.pid)
                times = sorted(sample[0] for sample in results)
                print(json.dumps({"phase": name, "scrapes": len(times), "wall_s": elapsed,
                                  "cpu_s": after["cpu_s"] - before["cpu_s"], "p50_s": times[len(times)//2],
                                  "p95_s": times[math.ceil(len(times)*0.95)-1], "max_s": max(times),
                                  "wire_bytes": results[0][1], **{k: v for k, v in after.items() if k != "cpu_s"}}), flush=True)

            def stall():
                raw = socket.socket()
                raw.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
                raw.settimeout(8)
                raw.connect(("127.0.0.1", port))
                connection = context.wrap_socket(raw, server_hostname="127.0.0.1")
                held.append(connection)
                connection.sendall(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\nAccept-Encoding: identity\r\n\r\n")
                header = b""
                while not header.endswith(b"\r\n\r\n"):
                    part = connection.recv(1)
                    assert part and len(header) < 16384, header
                    header += part
                assert header.startswith(b"HTTP/1.1 200"), header
                return connection

            phase("two_scrapers_identity", "identity")
            phase("two_scrapers_gzip", "gzip")
            stall()
            stall()
            phase("two_scrapers_gzip_plus_two_stalled_readers", "gzip")
            for connection in held:
                connection.close()
            held.clear()
            # Fill all response slots, then verify rejection starts no CLI work.
            for _ in range(8):
                stall()
            count = calls.read_text().count("\n")
            probe = client()
            scrape(probe, expected=503)
            assert calls.read_text().count("\n") == count, "rejected request started CLI work"
            start, before = time.monotonic(), usage(server.pid)
            while True:
                probe.request("GET", "/metrics")
                response = probe.getresponse()
                response.read()
                if response.status == 200:
                    break
                assert response.status == 503 and time.monotonic() - start < 20, "slots did not recover"
                time.sleep(0.25)
            recovery = time.monotonic() - start
            scrape(probe)  # Complete data, not merely a recovered HTTP status.
            probe.close()
            print(json.dumps({"phase": "eight_stalled_readers_then_recovery", "recovery_s": recovery,
                              "before": before, "after": usage(server.pid)}), flush=True)
            for connection in held:
                connection.close()
            held.clear()
            phase("two_scrapers_gzip_after_recovery", "gzip")
            time.sleep(5)
            print(json.dumps({"phase": "five_seconds_idle", **usage(server.pid)}), flush=True)
        finally:
            for connection in held:
                connection.close()
            server.send_signal(signal.SIGTERM)
            try:
                server.wait(timeout=8)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait()
            if server.returncode != 0:
                log.seek(0)
                raise RuntimeError(log.read())
