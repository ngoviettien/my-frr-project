#!/usr/bin/env bash
# Demo SDN controller (Phase 4). Controller phải đang chạy ở terminal khác:
#   sudo docker exec -it clab-SRv6-lab-ctl python /app/sfc_controller.py run
#
#   ./scripts/40_controller_demo.sh state      # trạng thái flow/SF từ REST API
#   ./scripts/40_controller_demo.sh probe      # truy cập :8080 -> FW drop -> controller chèn IPS (fw-ips)
#   ./scripts/40_controller_demo.sh scan       # quét cổng -> IPS alert 1000004 -> thêm fw2 (fw2-fw-ips)
#   ./scripts/40_controller_demo.sh attack     # 3 lần /attack-test -> IPS drop -> quarantine
#   ./scripts/40_controller_demo.sh failover   # giết Suricata -> controller bypass IPS -> bật lại -> chèn lại
#   ./scripts/40_controller_demo.sh set A fw-ips | release A    # điều khiển tay qua REST API
#   ./scripts/40_controller_demo.sh events     # 50 sự kiện gần nhất (có thời gian áp dụng ms)
set -uo pipefail
LAB=${LAB:-SRv6-lab}
API=${API:-http://172.20.20.100:8000}
S1=2001:db8:100:43::10
x(){ docker exec "clab-${LAB}-$1" sh -c "$2"; }
api(){ curl -s -m 5 "$@" || echo '{"error":"không gọi được API - controller có đang chạy?"}'; }
pretty(){ python3 -m json.tool --no-ensure-ascii 2>/dev/null || cat; }
chainA(){ api "$API/state" | python3 -c 'import sys,json; f=json.load(sys.stdin)["flows"]["A"]; print("  flow A: chain=%s effective=%s hold_left=%s" % (f["chain"], f["effective"], f["hold_left"]))' 2>/dev/null || echo "  (không đọc được state)"; }
web(){ x h1 "curl -6 -s -o /dev/null -w '%{http_code}' -m 2 '$1'" 2>/dev/null || true; }

case ${1:-state} in
  state)  api "$API/state" | pretty ;;
  events) api "$API/events" | pretty ;;
  set)    api -X POST -d "{\"chain\":\"${3:?chain}\"}" "$API/flows/${2:?flow}/chain" | pretty ;;
  release) api -X POST "$API/flows/${2:?flow}/release" | pretty ;;
  probe)
    chainA
    echo "== h1 thử 5 lần vào cổng quản trị :8080 (fw1 drop)"
    for i in 1 2 3 4 5; do printf '  :8080 -> %s\n' "$(web "http://[$S1]:8080/")"; done
    sleep 3; chainA; echo "  (kỳ vọng: chain=fw-ips)" ;;
  scan)
    chainA
    echo "== h1 quét 60 cổng TCP của s1 (cần IPS trong chuỗi để thấy)"
    x h1 "for p in \$(seq 1000 1060); do curl -6 -s -o /dev/null -m 1 http://[$S1]:\$p/; done" >/dev/null 2>&1
    sleep 2; chainA; echo "  (kỳ vọng: chain=fw2-fw-ips)" ;;
  attack)
    chainA
    echo "== h1 gửi 3 request /attack-test (IPS drop)"
    for i in 1 2 3; do printf '  /attack-test -> %s\n' "$(web "http://[$S1]/attack-test")"; done
    sleep 2; chainA; echo "  (kỳ vọng: chain=quarantine)"
    x h1 "ping -6 -c2 -W1 $S1 | tail -2" ;;
  failover)
    api -X POST -d '{"chain":"fw-ips"}' "$API/flows/A/chain" >/dev/null; chainA
    echo "== ping 0.1s liên tục; sau 2s giết Suricata (NFQ không có bypass -> drop cho tới khi controller phản ứng)"
    x h1 "ping -6 -i0.1 -c150 -W1 $S1 | tail -2" &
    sleep 2; x suricata1 'kill $(cat /var/run/suricata.pid)'; echo "  !! đã giết Suricata"
    sleep 5; chainA; echo "  (kỳ vọng: effective=fw - IPS bị bypass)"
    echo "== bật lại Suricata"; x suricata1 "sh /root/start-ips.sh" | tail -1
    wait; sleep 3; chainA; echo "  (kỳ vọng: effective=fw-ips)"
    echo "  thời gian gián đoạn ≈ số gói mất × 0.1 s"
    api -X POST "$API/flows/A/release" >/dev/null ;;
  *) sed -n 2,12p "$0"; exit 1 ;;
esac
