#!/usr/bin/env bash
# Lệnh kiểm chứng theo từng phase.  ./scripts/90_verify.sh <underlay|srv6|chain|sf|all>
set -uo pipefail
LAB=${LAB:-SRv6-lab}
x(){ docker exec "clab-${LAB}-$1" sh -c "$2"; }
hdr(){ printf '\n\033[1;36m===== %s =====\033[0m\n' "$*"; }
P=2001:db8:100

underlay(){
  for r in r1 r2 r3 r4 r5; do
    hdr "$r: show isis neighbor"; x $r "vtysh -c 'show isis neighbor'"
  done
  hdr "r1: show ipv6 route isis (mỗi prefix chỉ 1 next-hop)"; x r1 "vtysh -c 'show ipv6 route isis'"
  hdr "r1: route blackhole /56";  x r1 "vtysh -c 'show ipv6 route static'"
  hdr "r1 ping loopback r2..r5"
  for i in 2 3 4 5; do x r1 "ping -6 -c1 -W1 -I $P::1 $P::$i >/dev/null && echo '  ::$i OK' || echo '  ::$i FAIL'"; done
  hdr "h1 -> s1, h2 -> s2 (IS-IS thuần)"
  x h1 "ping -6 -c3 -W1 $P:43::10 | tail -2"
  x h2 "ping -6 -c3 -W1 $P:44::10 | tail -2"
}

srv6(){
  for r in r1 r2 r3 r4 r5; do
    hdr "$r: seg6local SID + bảng 100"
    x $r "ip -6 route show | grep -E 'seg6local' || echo '  (không có SID seg6local)'"
    x $r "ip -6 route show table 100 2>/dev/null"
  done
  hdr "r1: SID block của các node khác học qua IS-IS"; x r1 "vtysh -c 'show ipv6 route' | grep -E ':3[1-5]::/64'"
  hdr "tunsrc"; x r1 "ip sr tunsrc show"; x r3 "ip sr tunsrc show"
}

chain(){
  for r in r1 r3; do
    hdr "$r: ip -6 rule + bảng policy 201/202"
    x $r "ip -6 rule show | grep -E '100[12]:'"
    x $r "ip -6 route show table 201 2>/dev/null; ip -6 route show table 202 2>/dev/null"
  done
  hdr "r4: SR proxy IPS (rule iif eth1 + bảng 301/302)"
  x r4 "ip -6 rule show | grep -E '11[01][12]:'; ip -6 route show table 301 2>/dev/null; ip -6 route show table 302 2>/dev/null"
  hdr "Dấu vết SRH trên leg vào của SF khi h1 ping s1 (3 gói)"
  # fw1/fw2 là SF hiểu SRv6 -> thấy SRH; suricata1 sau proxy End.DX6 -> thấy ICMPv6 thường (không SRH)
  for spec in "r5 eth2 fw1 ip6[6]==43" "r4 eth2 suricata1 icmp6" "r2 eth3 fw2 ip6[6]==43"; do
    set -- $spec
    ( x $1 "timeout 4 tcpdump -nni $2 -c 2 -vv '$4' 2>/dev/null" | sed "s/^/[$1 $2 -> $3] /" ) &
  done
  sleep 1; x h1 "ping -6 -c3 -i0.3 $P:43::10 | tail -2"; wait
}

sf(){
  hdr "fw1 counters";  x fw1 "nft list ruleset | grep -E 'counter|comment'"
  hdr "fw2 counters";  x fw2 "nft list ruleset | grep -E 'counter|comment'"
  hdr "suricata1: tiến trình + queue";  x suricata1 "cat /var/run/suricata.pid 2>/dev/null && ps aux | grep -c '[s]uricata'; nft list ruleset | grep queue"
  hdr "suricata1: 10 dòng fast.log mới nhất"; x suricata1 "tail -n 10 /var/log/suricata/fast.log 2>/dev/null || echo '(chưa có alert)'"
}

case ${1:-all} in
  underlay) underlay ;; srv6) srv6 ;; chain) chain ;; sf) sf ;;
  all) underlay; srv6; chain; sf ;;
  *) echo "dùng: $0 <underlay|srv6|chain|sf|all>"; exit 1 ;;
esac
