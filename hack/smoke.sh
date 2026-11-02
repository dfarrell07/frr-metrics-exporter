#!/usr/bin/env bash
# Run the exporter against two real FRR containers and check what a scraper sees:
# BGP (IPv4 unicast and EVPN) and BFD between them, an L2 VNI with a local MAC,
# an L3 VNI, and a peer that does not exist. Needs podman, openssl and curl.
# FRR_IMAGE overrides the image; SMOKE_DUMP=file saves the final scrape there.
set -euo pipefail
cd "$(dirname "$0")/.."
image=${FRR_IMAGE:-quay.io/frrouting/frr:10.4.3}
dump=${SMOKE_DUMP:-}
if [[ -n "$dump" && "$dump" != /* ]]; then dump="$PWD/$dump"; fi
tmp=$(mktemp -d)
lab=egasmoke-${tmp##*.}
network_created=false
cleanup() {
  if [ "$network_created" = true ]; then
    podman rm -f "${lab}-r1" "${lab}-r2" >/dev/null 2>&1 || true
    podman network rm -f "$lab" >/dev/null 2>&1 || true
  fi
  rm -rf "$tmp"
}
trap cleanup EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }

CGO_ENABLED=0 go build -trimpath -o "$tmp/exporter" .

# PKI: one CA, a server certificate for 127.0.0.1 and a scraper certificate.
cd "$tmp"; mkdir pki r1 r2
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout pki/ca.key -out pki/ca.crt -days 1 -subj /CN=ca 2>/dev/null
for n in server scraper; do
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout pki/$n.key -out pki/$n.csr -subj /CN=$n 2>/dev/null
  printf 'subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth,clientAuth\n' > pki/$n.ext
  openssl x509 -req -in pki/$n.csr -CA pki/ca.crt -CAkey pki/ca.key -CAcreateserial -out pki/$n.crt -days 1 -extfile pki/$n.ext 2>/dev/null
done

# FRR config: r1 (AS 65001, 10.77.0.2) and r2 (AS 65002, 10.77.0.3) peer for IPv4
# unicast, EVPN and BFD; r1 also has a peer at 10.77.0.9 that does not exist.
frr() { # name asn router-id peer peer-asn
  printf 'zebra=yes\nbgpd=yes\nbfdd=yes\nvtysh_enable=yes\nzebra_options="  -A 127.0.0.1 -s 90000000"\nbgpd_options="   -A 127.0.0.1"\nbfdd_options="   -A 127.0.0.1"\n' > "$1/daemons"
  echo 'service integrated-vtysh-config' > "$1/vtysh.conf"
  cat > "$1/frr.conf" <<CONF
vrf red
 vni 50001
exit-vrf
router bgp $2
 bgp router-id $3
 no bgp ebgp-requires-policy
 neighbor $4 remote-as $5
 neighbor $4 bfd
$( [ "$1" = r1 ] && echo " neighbor 10.77.0.9 remote-as 65003" )
 address-family ipv4 unicast
  network $3/32
 exit-address-family
 address-family l2vpn evpn
  neighbor $4 activate
  advertise-all-vni
 exit-address-family
router bgp $2 vrf red
 address-family ipv4 unicast
  redistribute connected
 exit-address-family
 address-family l2vpn evpn
  advertise ipv4 unicast
 exit-address-family
CONF
}
frr r1 65001 10.77.0.2 10.77.0.3 65002
frr r2 65002 10.77.0.3 10.77.0.2 65001
chmod -R a+rX .; chmod 666 r1/* r2/*

podman network create --subnet 10.77.0.0/24 "$lab" >/dev/null
network_created=true
run_frr() { # name ip extra-args...
  local name=$1 ip=$2; shift 2
  podman run -d --name "${lab}-$name" --network "$lab" --ip "$ip" \
    --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_ADMIN -v "$tmp/$name:/etc/frr:Z" "$@" "$image" >/dev/null
}
# The PKI and binary are shared read-only by the two exporter processes.
run_frr r2 10.77.0.3 -p 127.0.0.1:19142:9141 -v "$tmp/pki:/pki:ro,z" -v "$tmp/exporter:/exporter:ro,z"
run_frr r1 10.77.0.2 -p 127.0.0.1:19141:9141 -v "$tmp/pki:/pki:ro,z" -v "$tmp/exporter:/exporter:ro,z"
sleep 5

# An L2 VNI (VLAN 100 bridge), an L3 VNI in VRF red, and on r1 a local MAC.
for r in r1:10.77.0.2 r2:10.77.0.3; do
  podman exec "${lab}-${r%%:*}" sh -c "
    ip link add br100 type bridge && ip link set br100 up &&
    ip link add vxlan10100 type vxlan id 10100 dstport 4789 local ${r##*:} nolearning &&
    ip link set vxlan10100 master br100 && ip link set vxlan10100 up &&
    ip link add red type vrf table 1001 && ip link set red up &&
    ip link add br-red type bridge && ip link set br-red master red && ip link set br-red up &&
    ip link add vxlan50001 type vxlan id 50001 dstport 4789 local ${r##*:} nolearning &&
    ip link set vxlan50001 master br-red && ip link set vxlan50001 up"
done
podman exec "${lab}-r1" sh -c 'ip link add vm0 type dummy && ip link set vm0 master br100 && ip link set vm0 up &&
  bridge fdb add 02:aa:bb:cc:dd:01 dev vm0 master static'

for r in r1 r2; do
  podman exec -d --user frr "${lab}-$r" /exporter --listen 0.0.0.0:9141 \
    --tls-cert-file /pki/server.crt --tls-key-file /pki/server.key --tls-client-ca-file /pki/ca.crt
done

scrape_peer() { local port=$1; shift; curl -sf --max-time 12 --cacert pki/ca.crt --cert pki/scraper.crt --key pki/scraper.key "$@" "https://127.0.0.1:$port/metrics"; }
scrape() { scrape_peer 19141 "$@"; }
# value of the series whose name and labels contain every argument, or empty
val() { local pat="$1[ {]"; shift; for s in "$@"; do pat+=".*$s"; done; grep -E "^$pat" <<<"$out" | awk '{print $NF}' | head -1; }

# BGP, BFD and EVPN take a few seconds to converge; wait for the last signal.
for _ in $(seq 60); do
  out=$(scrape 2>/dev/null || true)
  [ "$(val 'frrk8s_evpn_remote_vteps' 'vni="10100"')" = 1 ] && [ "$(val 'frrk8s_evpn_macs' 'vni="10100"')" = 1 ] && break
  sleep 1
done

check() { [ "$(val "$1" "${@:3}")" = "$2" ] || fail "$1 ${*:3}: want $2, got '$(val "$1" "${@:3}")'"; }
wait_for() { # netlink and BGP updates can arrive after the configuration command
  for _ in $(seq 50); do
    out=$(scrape)
    [ "$(val "$1" "${@:3}")" = "$2" ] && return
    sleep 0.2
  done
  check "$@"
}
check frrk8s_bgp_session_up 1 'peer="10.77.0.3"'
check frrk8s_bgp_session_up 0 'peer="10.77.0.9"'
check frrk8s_bgp_family_received_prefixes 1 'afi="l2vpn"' 'peer="10.77.0.3"'
check frrk8s_bgp_family_received_prefixes 1 'afi="ipv4"' 'peer="10.77.0.3"'
check frrk8s_bfd_session_up 1 'interface="eth0"' 'multihop="false"' 'peer="10.77.0.3"'
check frrk8s_evpn_vni_info 1 'type="L2"' 'vni="10100"'
check frrk8s_evpn_vni_info 1 'type="L3"' 'vni="50001"' 'vrf="red"'
check frrk8s_evpn_remote_vteps 1 'vni="10100"'
check frrk8s_evpn_remote_vtep_present 1 'vni="10100"' 'vrf="default"' 'vtep="10.77.0.3"'
check frrk8s_evpn_macs 1 'vni="10100"'
check frrk8s_exporter_tls_config_current 1
for c in bgp bfd evpn; do check frrk8s_scrape_collector_success 1 "collector=\"$c\""; done
[ -z "$(val 'frrk8s_evpn_macs' 'vni="50001"')" ] || fail "an L3 VNI got an L2 occupancy series"
if curl -sf -o /dev/null --cacert pki/ca.crt https://127.0.0.1:19141/metrics 2>/dev/null; then fail "scrape without a client certificate was served"; fi
echo "ok: $(grep -c '^frrk8s' <<<"$out") frrk8s series from $image; all collectors succeeded; client certificate required"

# Each PE's access LAG negotiates LACP with a local virtual CE LAG. Both PEs
# advertise the same ESI, with different DF preferences, over the EVPN session.
# This exercises the control-plane observations, not shared-CE forwarding.
for r in r1 r2; do
  podman exec "${lab}-$r" sh -ec '
    ip link add bond0 type bond mode 802.3ad lacp_rate fast
    ip link add ce0 type bond mode 802.3ad lacp_rate fast
    ip link add acc0 type veth peer name ce-acc0
    ip link set acc0 master bond0
    ip link set ce-acc0 master ce0
    ip link set bond0 master br100
    ip link set acc0 up
    ip link set ce-acc0 up
    ip link set ce0 up
    ip link set bond0 up
    vtysh -c "configure terminal" -c "evpn mh startup-delay 0" -c "interface bond0" \
      -c "evpn mh es-id 1" -c "evpn mh es-sys-mac 44:38:39:ff:ff:01" -c "end"'
done
mh() { local r=$1; shift; podman exec "${lab}-$r" vtysh -c 'configure terminal' -c 'interface bond0' "$@" -c end; }
mh r1 -c 'evpn mh es-df-pref 50000'
mh r2 -c 'evpn mh es-df-pref 40000'
esi='esi="03:44:38:39:ff:ff:01:00:00:01"'
roles() { # wait for r1/r2's elected roles and verify both endpoints
  local first=$1 second=$2 left right
  for _ in $(seq 30); do
    out=$(scrape); left=$(val frrk8s_evpn_es_df "$esi" || true)
    out=$(scrape_peer 19142); right=$(val frrk8s_evpn_es_df "$esi" || true)
    [ "$left" = "$first" ] && [ "$right" = "$second" ] && break
    sleep 1
  done
  check frrk8s_evpn_es_df "$second" "$esi"
  check frrk8s_evpn_es_oper_up 1 "$esi"
  out=$(scrape)
  check frrk8s_evpn_es_df "$first" "$esi"
  check frrk8s_evpn_es_oper_up 1 "$esi"
}
roles 1 0
[ -z "$dump" ] || printf '%s\n' "$out" > "$dump"
mh r1 -c 'evpn mh es-df-pref 30000'
roles 0 1
echo 'ok: local DF and non-DF roles; preference change elected the other PE'

mh r1 -c 'evpn mh bypass'
wait_for frrk8s_evpn_es_df ''
check frrk8s_evpn_es_oper_up 1 "$esi"
[ -z "$(val frrk8s_evpn_es_df)" ] || fail 'bypassed ES was assigned a DF role'
mh r1 -c 'no evpn mh bypass'
podman exec "${lab}-r1" ip link set bond0 down
wait_for frrk8s_evpn_es_oper_up 0 "$esi"
[ -z "$(val frrk8s_evpn_es_df)" ] || fail 'down ES was assigned a DF role'
podman exec "${lab}-r1" ip link set bond0 up
roles 0 1
mh r1 -c 'no evpn mh es-id 1'
wait_for frrk8s_evpn_es_oper_up ''
check frrk8s_scrape_collector_success 1 'collector="evpn"'
[ -z "$(val frrk8s_evpn_es_oper_up)" ] || fail 'remote-only ES was assigned local state'
[ -z "$(val frrk8s_evpn_es_df)" ] || fail 'remote-only ES was assigned a DF role'
mh r1 -c 'evpn mh es-id 1'
out=$(scrape)
check frrk8s_evpn_es_oper_up 1 "$esi"
[ -z "$(val frrk8s_evpn_es_df)" ] || fail 'pending election was assigned a DF role'
podman exec "${lab}-r1" ip link del vxlan10100
wait_for frrk8s_evpn_vni_info '' 'vni="10100"'
check frrk8s_evpn_es_oper_up 1 "$esi"
[ -z "$(val frrk8s_evpn_es_df)" ] || fail 'unready ES was assigned a DF role'
[ -z "$(val frrk8s_evpn_remote_vtep_present)" ] || fail 'deleted VNI retained remote VTEP membership'
check frrk8s_scrape_collector_success 1 'collector="evpn"'
echo 'ok: bypass, port down, remote-only ES, pending election and VNI deletion never invent an elected DF'

# A stuck daemon must fail only its own collector, finish inside the scraper's
# budget and leave no vtysh behind. SIGSTOP keeps its socket open, unlike exit.
for pair in bfdd:bfd bgpd:bgp zebra:evpn; do
  daemon=${pair%:*} collector=${pair#*:}
  podman exec "${lab}-r1" sh -c 'kill -STOP "$(cat "/run/frr/$1.pid")"' sh "$daemon"
  out=$(scrape --max-time 3 -H 'X-Prometheus-Scrape-Timeout-Seconds: 3') || fail "scrape exceeded its budget or failed with $daemon stopped"
  for c in bgp bfd evpn; do
    want=1; [ "$c" != "$collector" ] || want=0
    check frrk8s_scrape_collector_success "$want" "collector=\"$c\""
  done
  if grep -q "^frrk8s_${collector}_" <<<"$out"; then fail "$collector emitted partial data"; fi
  if podman exec "${lab}-r1" pidof vtysh >/dev/null; then fail "vtysh survived the scrape deadline"; fi
  podman exec "${lab}-r1" sh -c 'kill -CONT "$(cat "/run/frr/$1.pid")"' sh "$daemon"
  out=$(scrape)
  for c in bgp bfd evpn; do check frrk8s_scrape_collector_success 1 "collector=\"$c\""; done
  echo "ok: $daemon hang isolated; deadline killed vtysh; collector recovered"
done
