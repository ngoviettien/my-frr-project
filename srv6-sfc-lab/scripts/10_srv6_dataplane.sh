#!/usr/bin/env bash
# Phase 2 – Cài SRv6 data plane (Linux kernel, KHÔNG phải vtysh). Idempotent: chạy lại bao nhiêu lần cũng được.
#
#  Node | SID block (gắn sr0, IS-IS quảng bá) | SID dịch vụ
#  r1   | 2001:db8:100:31::/64               | 31::d6  End.DT6 table 254   (egress chiều về)
#  r2   | 2001:db8:100:32::/64               | 32::f2  End.T table 100 -> fw2 (49::10)
#  r3   | 2001:db8:100:33::/64               | 33::d6  End.DT6 table 254   (egress chiều đi)
#  r4   | 2001:db8:100:34::/64               | 34::a1  End.DX6 -> suricata1 (46::10) + re-encap (SR proxy)
#  r5   | 2001:db8:100:35::/64               | 35::f1  End.T table 100 -> fw1 (45::10)
#  3X::1 (địa chỉ trên sr0) = SID "End" mặc định của kernel (seg6_enabled=1).
set -euo pipefail
LAB=${LAB:-SRv6-lab}
x(){ echo "[$1] $2"; docker exec "clab-${LAB}-$1" sh -c "$2"; }
P=2001:db8:100

# 1) SID block trên sr0 -> IS-IS (sr0 passive) tự quảng bá 3X::/64
for i in 1 2 3 4 5; do
  x r$i "ip -6 addr replace $P:3$i::1/64 dev sr0"
done

# 2) Nguồn của outer IPv6 header khi encap = loopback của headend
x r1 "ip sr tunsrc set $P::1"
x r3 "ip sr tunsrc set $P::3"

# 3) Egress: End.DT6 = bóc SRH + outer header, tra inner DA trong bảng main
x r3 "ip -6 route replace $P:33::d6/128 encap seg6local action End.DT6 table 254 dev sr0"
x r1 "ip -6 route replace $P:31::d6/128 encap seg6local action End.DT6 table 254 dev sr0"

# 4) SF steering: End.T = SL--, DA=SID kế tiếp, tra bảng 100 (chỉ có default -> leg vào của SF).
#    SF forward gói (DA = SID kế tiếp) về router qua leg ra -> router tra bảng main như bình thường.
x r5 "ip -6 route replace default via $P:45::10 dev eth2 table 100"
x r5 "ip -6 route replace $P:35::f1/128 encap seg6local action End.T table 100 dev sr0"

# r4 = SR PROXY tĩnh cho suricata1 (SF không hiểu SRv6 – Suricata không giải mã inner sau SRH):
#   vào : 34::a1 End.DX6 -> bóc outer+SRH, đẩy inner IPv6 thường sang suricata1 (46::10, eth2)
#   ra  : suricata1 trả gói thường về r4 qua eth1 -> ip rule "iif eth1" -> bảng 301/302 encap lại
#         phần SID còn lại của chuỗi (do 20_chain.sh lập trình theo vị trí IPS trong chuỗi)
x r4 "ip sr tunsrc set $P::4"
x r4 "ip -6 route flush table 100 2>/dev/null || true"
x r4 "ip -6 route replace $P:34::a1/128 encap seg6local action End.DX6 nh6 $P:46::10 dev eth2"

x r2 "ip -6 route replace default via $P:49::10 dev eth3 table 100"
x r2 "ip -6 route replace $P:32::f2/128 encap seg6local action End.T table 100 dev sr0"

echo "== Xong. Kiểm tra: ./scripts/90_verify.sh srv6"
