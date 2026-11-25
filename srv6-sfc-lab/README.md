# SRv6 SFC lab – Runbook Ngày 1 → 4 (Phase 0 → 3)

```
srv6-sfc-lab/
├── SRv6gem.clab.yaml          # topology v2 (thêm fw2, sửa Suricata/MTU/bind)
├── config/r1..r5/frr.conf     # IS-IS (metric bỏ ECMP) + blackhole /56; daemons, vtysh.conf: GIỮ của bạn
├── fw/fw1/firewall.sh         # nft: chặn inner TCP/8080
├── fw/fw2/firewall.sh         # nft: SF3 giới hạn SYN 50 pps
├── suricata/suricata1/
│   ├── start-ips.sh           # NFQUEUE + chạy Suricata IPS
│   ├── rules/local.rules      # 6 rule demo (thêm vào thư mục rules hiện có)
│   └── suricata.yaml          # GIỮ file của bạn (tham số IPS truyền bằng --set)
└── scripts/
    ├── 00_host_prep.sh        # Phase 0
    ├── 10_srv6_dataplane.sh   # Phase 2: SID, tunsrc, bảng 100
    ├── 20_chain.sh            # lập chuỗi tại headend (r1 đi, r3 về)
    ├── 30_scenarios.sh        # kịch bản kiểm thử (gonogo, fw, fw-ips, ips-fw, fw2-fw-ips)
    ├── 40_controller_demo.sh  # Phase 4: demo controller (probe, scan, attack, failover)
    └── 90_verify.sh           # kiểm chứng theo phase
controller/
    ├── sfc_controller.py      # SDN controller (chạy trong container ctl)
    └── policy.yaml            # SF, flow, thang leo thang, trigger
```

## Phase 0 – Chuẩn bị (N1, ~1 giờ)
```bash
sudo containerlab destroy -t <file clab cũ> --cleanup     # dỡ lab cũ
# Giải nén bộ này vào thư mục lab, copy từ lab cũ:
#   config/rX/daemons, config/rX/vtysh.conf, suricata/suricata1/suricata.yaml, suricata/suricata1/rules/*
chmod +x scripts/*.sh fw/*/firewall.sh suricata/suricata1/start-ips.sh
./scripts/00_host_prep.sh
sudo containerlab deploy -t SRv6gem.clab.yaml --reconfigure
```
> ⚠️ **Bẫy**: Containerlab tự tạo thư mục bind nếu chưa có, và thư mục đó thuộc root, nên Suricata không ghi log được. Vì vậy phải chạy `00_host_prep.sh` trước khi deploy.
> ⚠️ `exec` có `&&`, `|`, `>` phải bọc trong `sh -c "..."` (containerlab không chạy exec qua shell).
> ⚠️ Đừng dựa vào `write memory` trong vtysh: frr.conf bind dạng file, FRR ghi kiểu rename nên dễ lỗi `Device or resource busy`. Muốn sửa cấu hình thì sửa file trên host rồi `docker exec clab-SRv6-lab-rX vtysh -b`.

## Phase 1 – Underlay (N1)
```bash
./scripts/90_verify.sh underlay
```
Kỳ vọng:
- `show isis neighbor`: r1 = 3 (r2/eth3, r4/eth4, r5/eth5), r2 = 2, r3 = 3, r4 = 3, r5 = 3; tất cả `Up`, Type `L2`.
- `show ipv6 route isis` trên r1, **mỗi prefix một next-hop**:
  ```
  I>* 2001:db8:100::2/128 [115/20] via fe80::..., eth3
  I>* 2001:db8:100::3/128 [115/30] via fe80::..., eth3     <- đi qua r2, không ECMP
  I>* 2001:db8:100:43::/64 [115/30] via fe80::..., eth3
  ```
- `S>* 2001:db8:100::/56 [1/0] unreachable (blackhole)`.
- h1 → s1, h2 → s2: `0% packet loss`.

## Phase 2 – SRv6 (N2)
```bash
./scripts/10_srv6_dataplane.sh
./scripts/90_verify.sh srv6
./scripts/20_chain.sh A direct      # SRv6 thuần, không qua SF
./scripts/20_chain.sh A fw          # qua fw1
./scripts/90_verify.sh chain
```
Kỳ vọng:
- r5: `2001:db8:100:35::f1 encap seg6local action End.T table 100 dev sr0` và `table 100: default via 2001:db8:100:45::10 dev eth2`.
- r1 học được `2001:db8:100:33::/64`, `34::/64`, `35::/64` qua IS-IS.
- `ip -6 route show table 201` trên r1:
  `2001:db8:100:43::/64  encap seg6 mode encap segs 2 [ 2001:db8:100:35::f1 2001:db8:100:33::d6 ] dev eth3`
- tcpdump trên **r5 eth2** (leg vào fw1) khi chain = `fw`: outer `2001:db8:100::1 > 2001:db8:100:33::d6`, `RT6 (… type=4, segleft=0 …)` rồi inner `41::10 > 43::10 ICMP6 echo request`.
  - Với chain `fw-ips`, trên r5 eth2 sẽ thấy DA = `34::a1`, `segleft=1` (End.T đã trừ SL và đổi DA trước khi đẩy sang SF).
- **IPS = mô hình A (SR proxy trên r4)**: Suricata không giải mã inner sau SRH (stats chỉ có `decoder.ipv6`, không có `ipv6_in_ipv6`), nên `34::a1` là `End.DX6 nh6 46::10` (kernel chỉ chạy End.DX6 khi `segleft=0` ⇒ headend chỉ encap SID **tới ips**, ví dụ `fw-ips` → r1 encap `[35::f1 34::a1]`): r4 bóc SRH, suricata1 nhận IPv6 thường; gói trả về qua eth1 khớp `ip -6 rule iif eth1` → bảng 301/302, nơi `20_chain.sh` ghi sẵn phần SID còn lại sau IPS. Trên r4 eth2 thấy `41::10 > 43::10 ICMP6` **không có SRH**.

## Phase 3 – FW & IPS (N3–N4)
```bash
./scripts/30_scenarios.sh gonogo     # ⏰ GO/NO-GO trước 12h00 N3
./scripts/30_scenarios.sh fw
./scripts/30_scenarios.sh fw-ips
./scripts/30_scenarios.sh ips-fw
./scripts/30_scenarios.sh fw2-fw-ips
./scripts/20_chain.sh A none         # trả về baseline
./scripts/90_verify.sh sf
```
**Tiêu chí GO**: fast.log có dòng `[1:1000010:1] SFC-IPS ICMPv6 echo request … {IPv6-ICMP} 2001:db8:100:41::10:128 -> 2001:db8:100:43::10:0`, tức Suricata đã đọc xuyên SRH tới inner packet; và `GET /attack-test` trả `000`.
**Nếu NO-GO** (không có alert, hoặc alert chỉ hiện outer `::1 -> 34::a1`): gửi mình `suricata.log`, `stats.log` và pcap tại r4 eth2. Khi đó chuyển sang mô hình A (SFF End.DX6 + re-encap), mình sẽ viết sẵn.

## Phase 4 – SDN controller (N5)
`controller/sfc_controller.py` chạy trong container `ctl`. Nó thay `20_chain.sh` (dùng chung bảng 201/202, 301/302 và pref) và thêm phần phản ứng tự động:

| Thành phần | Cách làm |
|---|---|
| Southbound | docker SDK → `docker exec` iproute2 trên r1/r3 (headend) và r4 (proxy). Mỗi node chỉ 1 exec, các node chạy song song, cài proxy trước rồi mới cài headend (make-before-break) |
| Northbound | REST `:8000`: `GET /state`, `GET /events`, `POST /flows/<F>/chain {"chain":"fw-ips"}`, `/quarantine`, `/release` |
| Phản ứng | stream `eve.json` của Suricata, poll counter nft của fw1, kiểm tra sức khoẻ SF mỗi 2 s |
| Chính sách | `controller/policy.yaml`: thang `fw → fw-ips → fw2-fw-ips → quarantine`; hết `hold` giây không có trigger thì về baseline; SF chết thì bypass |

```bash
# terminal 1: chạy controller (cài baseline 'fw' cho flow A, B)
sudo docker exec clab-SRv6-lab-ctl python -c "import docker, yaml" && echo "deps OK"
sudo docker exec -it clab-SRv6-lab-ctl python /app/sfc_controller.py run

# terminal 2: kịch bản (chạy liền nhau, trong vòng 60 s)
./scripts/40_controller_demo.sh probe      # :8080 bị FW drop → chèn IPS:      fw → fw-ips
./scripts/40_controller_demo.sh scan       # quét cổng → alert 1000004:         → fw2-fw-ips
./scripts/40_controller_demo.sh attack     # 3× /attack-test bị drop:           → quarantine (ping mất)
#   ... 120 s sau tự về baseline 'fw'
./scripts/40_controller_demo.sh failover   # giết Suricata → bypass → bật lại → chèn lại IPS
./scripts/40_controller_demo.sh events     # số liệu: thời gian áp dụng (ms), lý do, trigger
```
Mọi sự kiện được ghi vào `controller/logs/events.jsonl` (có `ms` của từng lần đổi chuỗi), dùng làm số liệu cho báo cáo. Lệnh thủ công: `python /app/sfc_controller.py apply A fw-ips` và `... show`.

## Gỡ lỗi nhanh (từ dưới lên)
| Triệu chứng | Kiểm tra |
|---|---|
| ping h1→s1 mất khi bật chain | `ip -6 route get 2001:db8:100:43::10 from 2001:db8:100:41::10 iif eth1` trên r1 phải ra `encap seg6`; `ip -6 route get 2001:db8:100:35::f1` trên r1 phải ra hướng r5 |
| Gói tới r5 nhưng không sang fw1 | `ip -6 route show table 100` trên r5; `ip -6 neigh show dev eth2` (45::10 REACHABLE?) |
| fw1 nhận nhưng không trả về | `ip -6 route` trên fw1: default via 47::1 dev eth2; `nft list ruleset` counter |
| Qua IPS là mất hết | trên host: `lsmod | grep nfnetlink_queue`; Suricata còn chạy? (`90_verify.sh sf`) |
| Tới r3 không bóc | `ip -6 route show | grep End.DT6` trên r3; `tcpdump -nni eth3/eth2` trên r3 |
