#!/usr/bin/env bash
# Phase 0 – Chuẩn bị máy host Ubuntu (chạy 1 lần sau mỗi lần reboot, cần sudo)
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== Kernel: $(uname -r)  (cần >= 5.x: seg6, seg6local End.T/End.DT6)"

# Module cần cho: VRF sysctl, NFQUEUE của Suricata, nftables của FW
for m in vrf nf_tables nft_queue nfnetlink_queue ip6_tables; do
  sudo modprobe "$m" && echo "   modprobe $m OK" || echo "   !! không load được $m"
done

# Kernel có hỗ trợ SRv6 lwtunnel không?
if grep -qs 'CONFIG_IPV6_SEG6_LWTUNNEL=y' "/boot/config-$(uname -r)"; then
  echo "== CONFIG_IPV6_SEG6_LWTUNNEL=y  OK"
else
  echo "!! Không thấy CONFIG_IPV6_SEG6_LWTUNNEL=y trong /boot/config-$(uname -r), kiểm tra lại kernel"
fi

# Thư mục bind phải tồn tại TRƯỚC khi deploy (nếu không Docker tạo thư mục root-owned)
mkdir -p controller host/s1/html host/s2/html suricata/suricata1/logs suricata/suricata1/rules
chmod 777 suricata/suricata1/logs
[ -f host/s1/html/index.html ] || echo "<h1>s1 - web server (2001:db8:100:43::10)</h1>" > host/s1/html/index.html
[ -f host/s2/html/index.html ] || echo "<h1>s2 - web server (2001:db8:100:44::10)</h1>" > host/s2/html/index.html
mkdir -p host/s1/html/admin host/s2/html/admin
echo "admin portal" > host/s1/html/admin/index.html
echo "admin portal" > host/s2/html/admin/index.html

# Các file phải có sẵn (lấy từ lab cũ của bạn)
for f in config/r{1..5}/daemons config/r{1..5}/vtysh.conf suricata/suricata1/suricata.yaml; do
  [ -f "$f" ] || echo "!! THIẾU $f, copy từ lab cũ sang"
done
grep -qs '^isisd=yes' config/r1/daemons   || echo "!! daemons: cần isisd=yes"
grep -qs '^staticd=yes' config/r1/daemons || echo "!! daemons: cần staticd=yes (cho route blackhole)"
echo "== Xong. Tiếp: sudo containerlab deploy -t SRv6gem.clab.yaml --reconfigure"
