#!/usr/bin/env bash
# Chạy nhanh các kịch bản kiểm thử chức năng cho luồng A (h1 -> s1).
#   ./scripts/30_scenarios.sh gonogo   # NGÀY 3: Suricata có thấy inner packet qua SRH không?
#   ./scripts/30_scenarios.sh fw       # chỉ FW: :80 OK, :8080 bị chặn
#   ./scripts/30_scenarios.sh fw-ips   # FW->IPS: tấn công web bị drop
#   ./scripts/30_scenarios.sh ips-fw   # đổi thứ tự
#   ./scripts/30_scenarios.sh fw2-fw-ips  # thêm SF3 + SYN flood
set -uo pipefail
cd "$(dirname "$0")"
LAB=${LAB:-SRv6-lab}
x(){ docker exec "clab-${LAB}-$1" sh -c "$2"; }
S1=2001:db8:100:43::10
web(){ # url nhãn kỳ_vọng
  local code; code=$(x h1 "curl -6 -s -o /dev/null -w '%{http_code}' -m 3 '$1'" 2>/dev/null); code=${code:-000}
  printf '  %-45s -> HTTP %s   (kỳ vọng: %s)\n' "$2" "$code" "$3"
}
alerts(){ x suricata1 "tail -n ${1:-5} /var/log/suricata/fast.log 2>/dev/null"; }

case ${1:?} in
  gonogo)
    ./20_chain.sh A ips
    x suricata1 ": > /var/log/suricata/fast.log"
    x h1 "ping -6 -c3 -i0.3 $S1 | tail -2"
    sleep 2; echo "--- fast.log (cần thấy sid 1000010 với địa chỉ INNER 41::10 -> 43::10) ---"; alerts 5
    web "http://[$S1]/attack-test" "GET /attack-test (qua IPS)" "000 = bị drop"
    sleep 1; alerts 3 ;;
  fw)
    ./20_chain.sh A fw
    web "http://[$S1]/"      "GET :80"   "200"
    web "http://[$S1]:8080/" "GET :8080" "000 = FW chặn"
    x fw1 "nft list ruleset | grep 8080-DROP" ;;
  fw-ips|ips-fw)
    ./20_chain.sh A "$1"
    web "http://[$S1]/"                                  "GET / (sạch)"        "200"
    web "http://[$S1]/attack-test"                       "GET /attack-test"     "000 = IPS drop"
    web "http://[$S1]/?id=1%20UNION%20SELECT%20pass"     "SQLi UNION SELECT"    "000 = IPS drop"
    web "http://[$S1]:8080/"                             "GET :8080"            "000 = FW chặn"
    sleep 1; alerts 5 ;;
  fw2-fw-ips)
    ./20_chain.sh A fw2-fw-ips
    web "http://[$S1]/" "GET / (sạch)" "200"
    echo "  SYN flood 2000 gói ~1000pps từ h1 (python raw socket)..."
    # nping tự chọn eth0 (mgmt) nên báo "Network unreachable" -> dùng raw socket bind nguồn 41::10
    x h1 "command -v python3 >/dev/null || apk add --no-cache python3 >/dev/null 2>&1"
    docker exec -i "clab-${LAB}-h1" python3 - "$S1" <<'PY'
import socket, struct, random, sys, time
dst = sys.argv[1]
s = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_TCP)
s.setsockopt(socket.IPPROTO_IPV6, 7, 16)          # IPV6_CHECKSUM: kernel tự tính checksum TCP
s.bind(("2001:db8:100:41::10", 0))
t = time.time()
for i in range(2000):
    hdr = struct.pack("!HHIIBBHHH", random.randint(1024, 65535), 80,
                      random.getrandbits(32), 0, 5 << 4, 0x02, 64240, 0, 0)   # chỉ cờ SYN
    s.sendto(hdr, (dst, 0))
    time.sleep(0.001)
print("  -> đã gửi 2000 SYN trong %.1f s" % (time.time() - t))
PY
    x fw2 "nft list ruleset | grep SYN-over" ;;
  *) echo "kịch bản không hợp lệ"; exit 1 ;;
esac
