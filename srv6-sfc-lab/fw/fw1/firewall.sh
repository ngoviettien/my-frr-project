#!/bin/sh
# fw1 – Firewall stateless cho SFC SRv6 (nftables)
# Gói đến fw1 có dạng: outer IPv6 (DA = SID kế tiếp) | SRH (NH 43) | inner IPv6 (NH 41) | TCP/ICMPv6
# Kernel bỏ qua extension header (kể cả SRH) khi tính transport header, nên với
# "meta l4proto 41" thì @th trỏ vào ĐẦU inner IPv6, bất kể SID list dài bao nhiêu:
#   @th,48,8    = inner Next Header (6 = TCP, 17 = UDP, 58 = ICMPv6)
#   @th,64,128  = inner src,  @th,192,128 = inner dst
#   @th,320,16  = inner L4 sport, @th,336,16 = inner L4 dport (khi inner không có ext header)
# Chính sách demo: chặn truy cập "trang quản trị" TCP/8080, cho phép phần còn lại.
nft flush ruleset
nft -f - <<'EOF'
table inet sfc_fw {
  chain forward {
    type filter hook forward priority filter; policy accept;

    # --- Gói SRv6 (inner) ---
    meta l4proto 41 counter comment "srv6-seen"
    meta l4proto 41 @th,48,8 6 @th,336,16 8080 counter drop comment "srv6-inner-tcp-8080-DROP"

    # --- Gói IPv6 thường (dự phòng mô hình A / test không SRv6) ---
    tcp dport 8080 counter drop comment "plain-tcp-8080-DROP"
    counter comment "other-accept"
  }
}
EOF
echo "fw1 ruleset loaded:"; nft list ruleset
