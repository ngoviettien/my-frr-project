#!/usr/bin/env bash
# Lập trình chuỗi SFC tại headend (bản thủ công = tiền thân của SDN controller)
#
#   ./scripts/20_chain.sh <flow> <chain>
#     flow : A = h1 (41::/64) <-> s1 (43::/64)   |  B = h2 (42::/64) <-> s2 (44::/64)
#     chain: none            -> tắt SRv6, đi theo IS-IS thuần (baseline)
#            direct          -> SRv6 chỉ có SID egress (không qua SF)
#            fw | ips | fw2  -> 1 dịch vụ
#            fw-ips, ips-fw, fw2-fw-ips, ...  -> nối tên SF bằng dấu '-'
#
#   Chiều đi : headend r1, SID list = [SF..., 33::d6]
#   Chiều về : headend r3, SID list = [SF đảo ngược..., 31::d6]  (để FW/IPS thấy đủ 2 chiều)
#   Route encap nằm trong bảng policy riêng (201/202) + ip -6 rule, KHÔNG đụng bảng main của zebra.
set -euo pipefail
LAB=${LAB:-SRv6-lab}
x(){ docker exec "clab-${LAB}-$1" sh -c "$2"; }

declare -A SID=( [fw]=2001:db8:100:35::f1 [ips]=2001:db8:100:34::a1 [fw2]=2001:db8:100:32::f2 )
EGRESS_FWD=2001:db8:100:33::d6
EGRESS_REV=2001:db8:100:31::d6

flow=${1:?Thiếu flow (A|B)}; chain=${2:?Thiếu chain}
case $flow in
  A) SRC=2001:db8:100:41::/64; DST=2001:db8:100:43::/64; TBL=201; PREF=1001; PTBL=301 ;;
  B) SRC=2001:db8:100:42::/64; DST=2001:db8:100:44::/64; TBL=202; PREF=1002; PTBL=302 ;;
  *) echo "flow phải là A hoặc B"; exit 1 ;;
esac

fwd=(); rev=()
if [[ $chain != none && $chain != direct ]]; then
  IFS='-' read -ra sfs <<< "$chain"
  for sf in "${sfs[@]}"; do
    [[ -n ${SID[$sf]:-} ]] || { echo "SF không tồn tại: $sf (có: ${!SID[*]})"; exit 1; }
    fwd+=("${SID[$sf]}")
  done
  for ((i=${#fwd[@]}-1; i>=0; i--)); do rev+=("${fwd[i]}"); done
fi
fwd+=("$EGRESS_FWD"); rev+=("$EGRESS_REV")
join(){ local IFS=,; echo "$*"; }

program(){ # node src dst segs dev
  local n=$1 s=$2 d=$3 segs=$4 dev=$5
  x "$n" "ip -6 rule show pref $PREF | grep -q lookup || ip -6 rule add pref $PREF from $s to $d lookup $TBL"
  if [[ $chain == none ]]; then
    x "$n" "ip -6 route flush table $TBL 2>/dev/null || true"
    echo "[$n] $s -> $d : IS-IS thuần (không SRv6)"
  else
    x "$n" "ip -6 route replace $d encap seg6 mode encap segs $segs dev $dev table $TBL"
    echo "[$n] $s -> $d : segs [$segs]"
  fi
}

# SR proxy cho IPS trên r4: End.DX6 đã bóc SRH, nên khi suricata1 trả gói về (iif eth1)
# r4 phải encap lại đúng "phần SID còn lại sau ips" của từng chiều.
rest_after_ips(){ # in danh sách SID sau ips, rỗng nếu chuỗi không có ips
  local -a l=("$@"); local i
  for ((i=0; i<${#l[@]}; i++)); do
    [[ ${l[i]} == "${SID[ips]}" ]] && { join "${l[@]:i+1}"; return 0; }
  done
  return 0
}
upto_ips(){ # cắt danh sách tới ips (bao gồm ips). End.DX6 của kernel chỉ chạy khi segleft=0,
  local -a l=("$@") o=(); local s   # nên ips PHẢI là SID cuối của SRH do headend tạo
  for s in "${l[@]}"; do o+=("$s"); [[ $s == "${SID[ips]}" ]] && break; done
  echo "${o[@]}"
}
fr=$(rest_after_ips "${fwd[@]}"); rr=$(rest_after_ips "${rev[@]}")
read -ra fwd <<< "$(upto_ips "${fwd[@]}")"
read -ra rev <<< "$(upto_ips "${rev[@]}")"

program_proxy(){
  x r4 "ip -6 rule show pref $((PREF+100)) | grep -q lookup || ip -6 rule add pref $((PREF+100)) iif eth1 from $SRC to $DST lookup $PTBL"
  x r4 "ip -6 rule show pref $((PREF+110)) | grep -q lookup || ip -6 rule add pref $((PREF+110)) iif eth1 from $DST to $SRC lookup $PTBL"
  x r4 "ip -6 route flush table $PTBL 2>/dev/null || true"
  if [[ -n $fr ]]; then
    x r4 "ip -6 route replace $DST encap seg6 mode encap segs $fr dev eth5 table $PTBL"
    x r4 "ip -6 route replace $SRC encap seg6 mode encap segs $rr dev eth5 table $PTBL"
    echo "[r4] proxy IPS: đi -> [$fr] | về -> [$rr]"
  fi
}

t0=$(date +%s%N)
program r1 "$SRC" "$DST" "$(join "${fwd[@]}")" eth3
program r3 "$DST" "$SRC" "$(join "${rev[@]}")" eth4
program_proxy
t1=$(date +%s%N)
echo "== flow $flow -> chain '$chain' (áp dụng trong $(( (t1-t0)/1000000 )) ms)"
