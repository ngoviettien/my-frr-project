#!/bin/sh
# suricata1 – chạy Suricata ở chế độ IPS inline qua NFQUEUE.
# suricata1 là một hop L3 (có IP, forwarding=1), nên dùng NFQUEUE trên hook forward
# thay cho AF_PACKET copy-mode (AF_PACKET + kernel forwarding sẽ nhân đôi gói).
# Yêu cầu host: modprobe nfnetlink_queue nft_queue (scripts/00_host_prep.sh).

# 1) nftables (image jasonish/suricata dựa trên AlmaLinux, có thể chưa có nft)
if ! command -v nft >/dev/null 2>&1; then
  (command -v dnf     >/dev/null 2>&1 && dnf -y -q install nftables) || \
  (command -v microdnf >/dev/null 2>&1 && microdnf -y install nftables) || \
  (command -v apk     >/dev/null 2>&1 && apk add --no-cache nftables) || \
  (command -v apt-get >/dev/null 2>&1 && apt-get update -qq && apt-get install -y -qq nftables)
fi
command -v nft >/dev/null 2>&1 || { echo "!! Không cài được nftables"; exit 1; }

# 2) Đẩy mọi gói forward (cả 2 chiều) vào queue 0.
#    Không dùng cờ 'bypass': nếu Suricata chết thì gói bị drop (fail-closed, đúng tinh thần IPS).
nft flush ruleset
nft -f - <<'EOF'
table inet ips {
  chain forward {
    type filter hook forward priority filter; policy accept;
    iifname { "eth1", "eth2" } counter queue num 0
  }
}
EOF

# 3) Khởi động Suricata
#   -S local.rules        : chỉ nạp rule demo (nhanh, kết quả lặp lại được)
#   -k none               : bỏ kiểm checksum (veth offload gây checksum "sai")
#   stream.midstream=true : controller chèn IPS vào luồng ĐANG chạy, không drop flow giữa chừng
#   async-oneside=true    : chịu được trường hợp chỉ thấy 1 chiều
#   exception-policy=ignore: tránh drop-flow mặc định của IPS mode trong môi trường lab
mkdir -p /var/log/suricata /var/run
rm -f /var/run/suricata.pid
suricata -c /etc/suricata/suricata.yaml -q 0 -k none \
  -S /var/lib/suricata/rules/local.rules \
  --set stream.midstream=true \
  --set stream.async-oneside=true \
  --set exception-policy=ignore \
  -l /var/log/suricata -D --pidfile /var/run/suricata.pid

sleep 3
if [ -f /var/run/suricata.pid ] && kill -0 "$(cat /var/run/suricata.pid)" 2>/dev/null; then
  echo "Suricata IPS (NFQ queue 0) đang chạy, PID $(cat /var/run/suricata.pid)"
else
  echo "!! Suricata không chạy, xem /var/log/suricata/suricata.log"; exit 1
fi
