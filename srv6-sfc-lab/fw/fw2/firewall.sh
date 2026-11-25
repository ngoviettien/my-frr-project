#!/bin/sh
# fw2 (SF3) – chống SYN flood: giới hạn tốc độ gói TCP có cờ SYN của inner packet
# Inner TCP flags nằm ở byte 40+13 = 53 của inner IPv6 → bit 424..431.
# So nguyên byte flags == 0x02 (SYN thuần, không ACK). Không dùng trường 1 bit (@th,430,1)
# vì nft userspace bị assertion "payload_expr_complete" khi 'nft list ruleset'.
nft flush ruleset
nft -f - <<'EOF'
table inet sfc_ratelimit {
  chain forward {
    type filter hook forward priority filter; policy accept;

    meta l4proto 41 counter comment "srv6-seen"
    meta l4proto 41 @th,48,8 6 @th,424,8 0x02 limit rate over 50/second burst 20 packets counter drop comment "srv6-inner-SYN-over-50pps-DROP"

    # dự phòng: gói IPv6 thường
    tcp flags & (syn|ack) == syn limit rate over 50/second burst 20 packets counter drop comment "plain-SYN-over-50pps-DROP"
    counter comment "other-accept"
  }
}
EOF
echo "fw2 ruleset loaded:"; nft list ruleset
