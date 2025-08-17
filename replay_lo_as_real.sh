#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   sudo ./replay_lo_as_real.sh /path/to/loopback_capture.pcap
#
# Optional ENV overrides:
#   VETH_A=veth0          # client side
#   VETH_B=veth1          # server side
#   A_IP=192.168.100.1/24
#   B_IP=192.168.100.2/24
#   A_MAC=02:11:22:33:44:55
#   B_MAC=02:66:77:88:99:aa
#   MAP_ENDPOINTS=1       # remap all flows to A_IP <-> B_IP (good for loopback)
#   START_LISTENERS=1     # auto-listen on destination ports found in the PCAP
#   PORT_LIMIT=32         # max listeners to start (safety)
#
# What it does (high level):
#   1) Creates veth pair (A <-> B) with IPs/MACs
#   2) Rewrites loopback PCAP to Ethernet with new MACs
#   3) Optionally maps endpoints to A_IP <-> B_IP
#   4) Starts listeners on B_IP for server-side ports (optional)
#   5) Replays via tcplivereplay on interface VETH_A

PCAP_IN="${1:-}"
if [[ -z "${PCAP_IN}" || ! -f "${PCAP_IN}" ]]; then
  echo "ERROR: Provide a valid loopback PCAP file."
  echo "Usage: sudo $0 loopback_capture.pcap"
  exit 1
fi

# Defaults (override via env)
VETH_A="${VETH_A:-veth0}"
VETH_B="${VETH_B:-veth1}"
A_IP_CIDR="${A_IP:-192.168.100.1/24}"
B_IP_CIDR="${B_IP:-192.168.100.2/24}"
A_MAC="${A_MAC:-02:11:22:33:44:55}"
B_MAC="${B_MAC:-02:66:77:88:99:aa}"
MAP_ENDPOINTS="${MAP_ENDPOINTS:-1}"
START_LISTENERS="${START_LISTENERS:-1}"
PORT_LIMIT="${PORT_LIMIT:-32}"

A_IP="${A_IP_CIDR%%/*}"
B_IP="${B_IP_CIDR%%/*}"

workdir="$(mktemp -d)"
PCAP_ETH="$workdir/ethernet_ready.pcap"
PCAP_OUT="$workdir/replay_ready.pcap"

cleanup() {
  set +e
  echo "[*] Cleaning up…"
  ip link del "$VETH_A" 2>/dev/null || true
  rm -rf "$workdir"
}
trap cleanup EXIT

require() {
  command -v "$1" >/dev/null 2>&1 || { echo "Missing required tool: $1"; exit 1; }
}
require ip
require tcprewrite
require tshark
# require tcplivereplay

echo "[*] Creating veth pair: $VETH_A <-> $VETH_B"
sudo ip link del "$VETH_A" 2>/dev/null || true
sudo ip link add "$VETH_A" type veth peer name "$VETH_B"

echo "[*] Assigning MACs"
sudo ip link set dev "$VETH_A" address "$A_MAC"
sudo ip link set dev "$VETH_B" address "$B_MAC"

echo "[*] Assigning IPs"
sudo ip addr add "$A_IP_CIDR" dev "$VETH_A"
sudo ip addr add "$B_IP_CIDR" dev "$VETH_B"

sudo ip link set "$VETH_A" up
sudo ip link set "$VETH_B" up



echo "[*] Step 1: Convert Loopback PCAP -> Ethernet frames"
# Many loopback pcaps use DLT_NULL/DLT_LOOP. Convert to Ethernet and set MACs.
echo "tcprewrite --dlt=enet --enet-smac=\"$A_MAC\" --enet-dmac=\"$B_MAC\" --fixcsum --cachefile=\"$workdir/cache.txt\" --infile=\"$PCAP_IN\" --outfile=\"$PCAP_ETH\""
tcprewrite \
  --dlt=enet \
  --enet-smac="$A_MAC" \
  --enet-dmac="$B_MAC" \
  --fixcsum \
  --infile="$PCAP_IN" \
  --outfile="$PCAP_ETH"

# Decide whether to map endpoints (recommended for loopback captures).
if [[ "$MAP_ENDPOINTS" == "1" ]]; then
  echo "[*] Step 2: Force endpoints to $A_IP <-> $B_IP (client<->server)"

  tcpprep --auto=first --pcap="$PCAP_ETH" --cachefile="$workdir/cache.txt"

  # --endpoints rewrites src/dst IPs for each flow based on direction.
  # This is helpful when original src/dst were both 127.0.0.1.
  echo "tcprewrite --endpoints=\"${A_IP}:${B_IP}\" --cachefile=\"$workdir/cache.txt\" --fixcsum --infile=\"$PCAP_ETH\" --outfile=\"$PCAP_OUT\""
  tcprewrite \
    --endpoints="${A_IP}:${B_IP}" \
    --cachefile="$workdir/cache.txt" \
    --fixcsum \
    --infile="$PCAP_ETH" \
    --outfile="$PCAP_OUT"
else
  echo "[*] Skipping endpoint mapping; using $PCAP_ETH as output"
  PCAP_OUT="$PCAP_ETH"
fi

# (Optional) Show a quick summary of unique server ports (SYN packets’ dst ports)
echo "[*] Extracting candidate server-side TCP destination ports from PCAP…"
DST_PORTS=()
while IFS= read -r port; do
  DST_PORTS+=("$port")
done < <(tshark -r "$PCAP_OUT" -Y 'tcp.flags.syn==1 && tcp.flags.ack==0' -T fields -e tcp.dstport 2>/dev/null | sort -n | uniq)

if [[ "${#DST_PORTS[@]}" -eq 0 ]]; then
  echo "[!] No SYNs found; replay may still work if flows are midstream, but starting listeners won’t help."
fi

if [ "${START_LISTENERS:-1}" = "1" ] && [ "${#DST_PORTS[@]}" -gt 0 ]; then
  echo "[*] Step 3: Starting up to $PORT_LIMIT listeners on $B_IP for ports: ${DST_PORTS[*]}"
  count=0

  # Detect tools once
  HAVE_NCAT=0; HAVE_SOCAT=0
  command -v ncat >/dev/null 2>&1 && HAVE_NCAT=1
  command -v socat >/dev/null 2>&1 && HAVE_SOCAT=1

  if [ "$HAVE_NCAT" -eq 0 ] && [ "$HAVE_SOCAT" -eq 0 ]; then
    echo "[!] Neither ncat (nmap-ncat) nor socat found. Skipping listeners."
  else
    # Don’t die if one of the background commands fails
    set +e
    for p in "${DST_PORTS[@]}"; do
      count=$((count+1))
      if [ "$count" -gt "${PORT_LIMIT:-32}" ]; then
        echo "[!] Reached PORT_LIMIT=$PORT_LIMIT; not opening more listeners."
        break
      fi

      if [ "$HAVE_NCAT" -eq 1 ]; then
        # Portable ncat: -l (listen), -k (keep-open), -p (port), -s (bind IP)
        # Use -c cat (or --sh-exec "cat" on some builds)
        nohup ncat -l -k -p "$p" -s "$B_IP" -c cat >/dev/null 2>&1 &
        rc=$?
        [ $rc -ne 0 ] && echo "[!] ncat failed on $B_IP:$p (rc=$rc), trying socat…" 
        if [ $rc -eq 0 ]; then
          continue
        fi
      fi

      if [ "$HAVE_SOCAT" -eq 1 ]; then
        # socat echo server
        nohup socat -v TCP-LISTEN:"$p",bind="$B_IP",fork,reuseaddr - >/dev/null 2>&1 &
        rc=$?
        [ $rc -ne 0 ] && echo "[!] socat failed on $B_IP:$p (rc=$rc), continuing…"
      fi
    done
    # Re-enable -e for the rest of the script
    set -e
    sleep 1
  fi
fi

echo "[*] Step 4: Replaying via tcplivereplay on $VETH_A"
# tcplivereplay will establish NEW TCP connections to the dest in the pcaps.
# Since we mapped endpoints, dest is $B_IP and the server should be listening.
sudo tcpliveplay "$VETH_A" "$PCAP_OUT"
echo "[*] Done. You can inspect traffic with:  tcpdump -i $VETH_B -n"