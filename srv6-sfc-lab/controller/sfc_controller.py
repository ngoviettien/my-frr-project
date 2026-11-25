#!/usr/bin/env python3
"""SDN controller cho lab SRv6 SFC.

Chạy trong container `ctl` (docker.sock được mount) và điều khiển các node qua docker SDK.

  Southbound : docker exec -> iproute2 (seg6 encap, ip -6 rule, bảng policy) trên r1/r3/r4
  Northbound : REST API JSON (mặc định :8000) + CLI
  Phản ứng   : eve.json của Suricata (stream), counter nftables của FW (poll),
               sức khoẻ SF (poll) -> leo thang / hạ thang / bypass SF hỏng

  python sfc_controller.py run                    # chạy daemon (API + phản ứng tự động)
  python sfc_controller.py apply A fw-ips         # lập chuỗi 1 lần rồi thoát
  python sfc_controller.py show                   # in bảng policy trên các node
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
import threading
import time
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import docker
import yaml

HERE = Path(__file__).resolve().parent
LOG_DIR = HERE / "logs"
SPECIAL = ("none", "direct", "quarantine")
sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def log(event: str, **kw):
    """In ra màn hình + ghi logs/events.jsonl (dùng làm số liệu cho báo cáo)."""
    rec = {"ts": round(time.time(), 3), "event": event, **kw}
    extra = " ".join(f"{k}={v}" for k, v in kw.items())
    print(f"{time.strftime('%H:%M:%S')} [{event}] {extra}", flush=True)
    LOG_DIR.mkdir(exist_ok=True)
    with open(LOG_DIR / "events.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")


# ============================ Southbound ============================
class Southbound:
    def __init__(self, lab: str):
        self.lab = lab
        self.client = docker.from_env()
        self._cache = {}

    def _c(self, node: str):
        if node not in self._cache:
            self._cache[node] = self.client.containers.get(f"clab-{self.lab}-{node}")
        return self._cache[node]

    def run(self, node: str, script: str) -> tuple[int, str]:
        r = self._c(node).exec_run(["sh", "-c", script])
        return r.exit_code, r.output.decode(errors="replace")

    def stream(self, node: str, cmd: list[str]):
        return self._c(node).exec_run(cmd, stream=True).output


# ============================ Mô hình ============================
@dataclass
class SF:
    name: str
    sid: str
    container: str
    health: str
    proxy: dict | None = None
    alive: bool = True


@dataclass
class Flow:
    name: str
    src: str
    dst: str
    fwd: dict
    rev: dict
    table: int
    pref: int
    proxy_table: int
    baseline: str
    chain: str = "none"           # chuỗi mong muốn (theo policy)
    applied: str = "none"         # chuỗi thực sự đã cài (sau khi bỏ SF hỏng)
    pinned: bool = False          # đặt tay qua API/CLI -> không tự hạ thang
    last_trigger: float = 0.0
    history: list = field(default_factory=list)

    def match(self, a: str, b: str) -> bool:
        try:
            a, b = ipaddress.ip_address(a), ipaddress.ip_address(b)
        except ValueError:
            return False
        s, d = ipaddress.ip_network(self.src), ipaddress.ip_network(self.dst)
        return (a in s and b in d) or (a in d and b in s)


class Controller:
    def __init__(self, policy_path: Path):
        self.p = yaml.safe_load(policy_path.read_text(encoding="utf-8"))
        self.sb = Southbound(self.p["lab"])
        self.sfs = {n: SF(n, d["sid"], d["container"], d.get("health", "true"), d.get("proxy"))
                    for n, d in self.p["service_functions"].items()}
        self.flows = {n: Flow(n, **{k: d[k] for k in ("src", "dst", "fwd", "rev", "table", "pref",
                                                    "proxy_table", "baseline")})
                      for n, d in self.p["flows"].items()}
        self.escalation = self.p.get("escalation", [])
        self.lock = threading.RLock()
        self.alert_hits = defaultdict(deque)     # trigger name -> (ts, flow)
        self.nft_last = {}
        self.pool = ThreadPoolExecutor(max_workers=8)

    # ---------------- tính SID list ----------------
    def parse_chain(self, chain: str) -> list[str]:
        if chain in SPECIAL:
            return []
        names = chain.split("-")
        bad = [n for n in names if n not in self.sfs]
        if bad:
            raise ValueError(f"SF không tồn tại: {bad} (có: {list(self.sfs)})")
        return names

    def effective(self, chain: str) -> str:
        """Bỏ các SF đang hỏng khỏi chuỗi nếu sf_failure=bypass."""
        if chain in SPECIAL or self.p.get("sf_failure", "bypass") != "bypass":
            return chain
        alive = [n for n in self.parse_chain(chain) if self.sfs[n].alive]
        return "-".join(alive) if alive else "direct"

    def segments(self, names: list[str], egress: str) -> list[tuple[str | None, list[str]]]:
        """Chia SID list tại các SF proxy.
        Trả [(None, segs của headend), (proxy_sf, segs proxy đó encap lại), ...]"""
        out, cur, owner = [], [], None
        for n in names:
            cur.append(self.sfs[n].sid)
            if self.sfs[n].proxy:
                out.append((owner, cur))
                cur, owner = [], n
        cur.append(egress)
        out.append((owner, cur))
        return out

    # ---------------- lập trình node ----------------
    def build(self, f: Flow, chain: str) -> dict[str, list[str]]:
        """Sinh lệnh iproute2 cho từng node (gộp thành 1 lần docker exec mỗi node)."""
        cmds: dict[str, list[str]] = defaultdict(list)
        names = self.parse_chain(chain)
        legs = (("fwd", f.src, f.dst, names), ("rev", f.dst, f.src, names[::-1]))

        # bảng proxy: luôn flush cho flow này, rồi ghi lại nếu chuỗi có SF proxy
        for sf in self.sfs.values():
            if not sf.proxy:
                continue
            pn, rif = sf.proxy["node"], sf.proxy["return_if"]
            for off, (s, d) in ((100, (f.src, f.dst)), (110, (f.dst, f.src))):
                pref = f.pref + off
                cmds[pn].append(f"ip -6 rule show pref {pref} | grep -q lookup || "
                                f"ip -6 rule add pref {pref} iif {rif} from {s} to {d} lookup {f.proxy_table}")
            cmds[pn].append(f"ip -6 route flush table {f.proxy_table} 2>/dev/null || true")

        for leg, s, d, seq in legs:
            he, dev, egress = f.__dict__[leg]["headend"], f.__dict__[leg]["dev"], f.__dict__[leg]["egress_sid"]
            cmds[he].append(f"ip -6 rule show pref {f.pref} | grep -q lookup || "
                            f"ip -6 rule add pref {f.pref} from {s} to {d} lookup {f.table}")
            if chain == "none":
                cmds[he].append(f"ip -6 route flush table {f.table} 2>/dev/null || true")
                continue
            if chain == "quarantine":
                cmds[he].append(f"ip -6 route replace blackhole {d} table {f.table}")
                continue
            for owner, segs in self.segments(seq, egress):
                if owner is None:
                    cmds[he].append(f"ip -6 route replace {d} encap seg6 mode encap segs "
                                    f"{','.join(segs)} dev {dev} table {f.table}")
                else:
                    px = self.sfs[owner].proxy
                    cmds[px["node"]].append(f"ip -6 route replace {d} encap seg6 mode encap segs "
                                            f"{','.join(segs)} dev {px['encap_dev']} table {f.proxy_table}")
        return cmds

    def apply(self, flow: str, chain: str, reason: str, pinned: bool | None = None) -> dict:
        with self.lock:
            f = self.flows[flow]
            self.parse_chain(chain)                      # kiểm tra tên trước khi đụng node
            eff = self.effective(chain)
            cmds = self.build(f, eff)
            heads = {f.fwd["headend"], f.rev["headend"]}
            t0 = time.perf_counter()
            # make-before-break: cài bảng proxy (re-encap) trước, headend (đổi đường) sau
            first = {n: c for n, c in cmds.items() if n not in heads}
            errs = self._run_parallel(first) + self._run_parallel({n: cmds[n] for n in heads if n in cmds})
            ms = round((time.perf_counter() - t0) * 1000, 1)
            old = f.applied
            f.chain, f.applied = chain, eff
            if pinned is not None:
                f.pinned = pinned
            f.history.append({"ts": time.time(), "from": old, "to": eff, "reason": reason, "ms": ms})
            del f.history[:-50]
            log("apply", flow=flow, chain=chain, effective=eff, prev=old, ms=ms, reason=reason,
                errors=len(errs))
            for e in errs:
                log("apply-error", flow=flow, detail=e)
            self._save()
            return {"flow": flow, "chain": chain, "effective": eff, "ms": ms, "errors": errs}

    def _run_parallel(self, cmds: dict[str, list[str]]) -> list[str]:
        futs = {n: self.pool.submit(self.sb.run, n, "set -e\n" + "\n".join(c)) for n, c in cmds.items()}
        errs = []
        for n, fu in futs.items():
            rc, out = fu.result()
            if rc != 0:
                errs.append(f"{n}: rc={rc} {out.strip()[-300:]}")
        return errs

    # ---------------- phản ứng ----------------
    def rank(self, chain: str) -> int:
        return self.escalation.index(chain) if chain in self.escalation else -1

    def escalate(self, flow: str, target: str, trigger: str, detail: str = ""):
        with self.lock:
            f = self.flows[flow]
            if f.pinned:
                log("trigger-ignored", flow=flow, trigger=trigger, why="pinned")
                return
            f.last_trigger = time.time()
            if self.rank(target) > self.rank(f.chain):
                log("trigger", flow=flow, trigger=trigger, action=target, detail=detail)
                self.apply(flow, target, reason=f"trigger:{trigger}")
            else:
                log("trigger-refresh", flow=flow, trigger=trigger, current=f.chain)

    def on_alert(self, ev: dict):
        sid = ev.get("alert", {}).get("signature_id")
        src, dst = ev.get("src_ip", ""), ev.get("dest_ip", "")
        flow = next((n for n, f in self.flows.items() if f.match(src, dst)), None)
        log("alert", sid=sid, src=src, dst=dst, flow=flow,
            action=ev.get("alert", {}).get("action"), msg=ev.get("alert", {}).get("signature"))
        if not flow:
            return
        now = time.time()
        for t in self.p.get("triggers", []):
            if t["type"] != "alert" or sid not in t["sids"]:
                continue
            q = self.alert_hits[(t["name"], flow)]
            q.append(now)
            while q and now - q[0] > t.get("window", 60):
                q.popleft()
            if len(q) >= t.get("count", 1):
                q.clear()
                self.escalate(flow, t["action"], t["name"], f"sid={sid}")

    @staticmethod
    def _inner_src_match(prefix: str) -> str:
        """Khớp inner src prefix của gói SRv6: @th trỏ vào đầu inner IPv6, src ở bit 64.
        Chỉ dùng độ dài chia hết cho 8 (trường raw lẻ bit làm 'nft list' bị assertion)."""
        net = ipaddress.ip_network(prefix)
        if net.prefixlen % 8:
            raise ValueError(f"prefix {prefix}: độ dài phải chia hết cho 8")
        return f"@th,64,{net.prefixlen} 0x{net.network_address.packed[:net.prefixlen // 8].hex()}"

    def install_nft_monitors(self, t: dict):
        """Controller tự cài counter RIÊNG cho từng flow lên SF (chỉ đếm, không có verdict,
        gói vẫn đi tiếp tới rule gốc của firewall.sh). Xoá bản cũ trước nên chạy lại được."""
        tag = f"ctl-{t['name']}-"
        rc, out = self.sb.run(t["container"], f"nft -a list chain {t['nft_chain']}")
        if rc != 0:
            log("nft-monitor-error", trigger=t["name"], detail=out.strip()[-200:])
            return
        cmds = [f"nft delete rule {t['nft_chain']} handle {h}"
                for h in re.findall(r'comment "%s\w+".*# handle (\d+)' % re.escape(tag), out)]
        for fn, f in self.flows.items():
            cmds.append(f"nft insert rule {t['nft_chain']} {t['match']} {self._inner_src_match(f.src)} "
                        f"counter comment '\"{tag}{fn}\"'")
        rc, out = self.sb.run(t["container"], "set -e\n" + "\n".join(cmds))
        log("nft-monitor", trigger=t["name"], container=t["container"], flows=list(self.flows),
            ok=rc == 0, detail="" if rc == 0 else out.strip()[-200:])

    def poll_nft(self):
        for t in self.p.get("triggers", []):
            if t["type"] != "nft_counter":
                continue
            rc, out = self.sb.run(t["container"], "nft list ruleset")
            if rc != 0:
                continue
            for fn in self.flows:
                key = f"ctl-{t['name']}-{fn}"
                m = re.search(r'counter packets (\d+) bytes \d+ comment "%s"' % re.escape(key), out)
                if not m:                                # SF khởi động lại (flush ruleset) -> cài lại
                    self.nft_last.pop(key, None)
                    self.install_nft_monitors(t)
                    break
                val = int(m.group(1))
                prev = self.nft_last.get(key, val)
                self.nft_last[key] = val
                if val - prev >= t.get("threshold", 1):
                    self.escalate(fn, t["action"], t["name"], f"+{val - prev} gói")

    def poll_health(self):
        def check(sf):
            try:
                return self.sb.run(sf.container, sf.health)[0]
            except docker.errors.APIError:
                return 1
        rcs = dict(zip(self.sfs, self.pool.map(check, self.sfs.values())))   # kiểm tra song song
        changed = False
        for name, sf in self.sfs.items():
            alive = rcs[name] == 0
            if alive != sf.alive:
                sf.alive, changed = alive, True
                log("sf-up" if alive else "sf-down", sf=sf.name, container=sf.container)
        if changed:
            with self.lock:
                for fn, f in self.flows.items():
                    if self.effective(f.chain) != f.applied:
                        self.apply(fn, f.chain, reason="sf-health")

    def hold_for(self, chain: str) -> int:
        return self.p.get("quarantine_hold" if chain == "quarantine" else "hold", 60)

    def maybe_revert(self):
        now = time.time()
        with self.lock:
            for fn, f in self.flows.items():
                if f.pinned or f.chain == f.baseline or not f.last_trigger:
                    continue
                hold = self.hold_for(f.chain)
                if now - f.last_trigger >= hold:
                    f.last_trigger = 0.0
                    self.apply(fn, f.baseline, reason=f"hold {hold}s hết, về baseline")

    # ---------------- vòng lặp ----------------
    def watch_eve(self):
        """Stream eve.json của Suricata qua docker exec tail -F (tự nối lại nếu đứt)."""
        container = self.sfs["ips"].container if "ips" in self.sfs else "suricata1"
        while True:
            try:
                buf = b""
                for chunk in self.sb.stream(container, ["tail", "-n0", "-F", "/var/log/suricata/eve.json"]):
                    buf += chunk
                    *lines, buf = buf.split(b"\n")
                    for ln in lines:
                        try:
                            ev = json.loads(ln)
                        except ValueError:
                            continue
                        if ev.get("event_type") == "alert":
                            self.on_alert(ev)
            except Exception as e:                       # noqa: BLE001
                log("eve-reconnect", error=repr(e))
            time.sleep(2)

    def loop(self, fns, iv: float):
        while True:
            for fn in fns:
                try:
                    fn()
                except Exception as e:                   # noqa: BLE001
                    log("loop-error", fn=fn.__name__, error=repr(e))
            time.sleep(iv)

    def state(self) -> dict:
        now = time.time()
        return {
            "sfs": {n: {"sid": s.sid, "alive": s.alive, "proxy": bool(s.proxy)} for n, s in self.sfs.items()},
            "flows": {n: {"src": f.src, "dst": f.dst, "chain": f.chain, "effective": f.applied,
                          "baseline": f.baseline, "pinned": f.pinned,
                          "hold_left": (max(0, round(self.hold_for(f.chain) - (now - f.last_trigger)))
                                        if f.last_trigger else None),
                          "history": f.history[-10:]}
                      for n, f in self.flows.items()},
        }

    def _save(self):
        (HERE / "state.json").write_text(json.dumps(self.state(), indent=2, ensure_ascii=False), encoding="utf-8")


# ============================ Northbound REST ============================
def make_handler(ctl: Controller):
    class H(BaseHTTPRequestHandler):
        def _send(self, code: int, obj):
            body = json.dumps(obj, indent=2, ensure_ascii=False).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

        def do_GET(self):
            if self.path in ("/", "/state"):
                return self._send(200, ctl.state())
            if self.path == "/events":
                p = LOG_DIR / "events.jsonl"
                lines = p.read_text(encoding="utf-8").splitlines()[-50:] if p.exists() else []
                return self._send(200, [json.loads(x) for x in lines])
            self._send(404, {"error": "không có"})

        def do_POST(self):
            # POST /flows/<F>/chain {"chain": "fw-ips"}  |  /flows/<F>/quarantine  |  /flows/<F>/release
            m = re.fullmatch(r"/flows/(\w+)/(chain|quarantine|release)", self.path)
            if not m or m.group(1) not in ctl.flows:
                return self._send(404, {"error": "dùng /flows/<flow>/{chain|quarantine|release}"})
            flow, op = m.groups()
            n = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(n) or b"{}")
            try:
                if op == "chain":
                    r = ctl.apply(flow, body["chain"], reason="api", pinned=body.get("pin", True))
                elif op == "quarantine":
                    r = ctl.apply(flow, "quarantine", reason="api", pinned=True)
                else:
                    r = ctl.apply(flow, ctl.flows[flow].baseline, reason="api release", pinned=False)
                self._send(200, r)
            except (KeyError, ValueError) as e:
                self._send(400, {"error": str(e)})
    return H


# ============================ CLI ============================
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--policy", default=str(HERE / "policy.yaml"))
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("run")
    a = sub.add_parser("apply")
    a.add_argument("flow")
    a.add_argument("chain")
    sub.add_parser("show")
    args = ap.parse_args()

    ctl = Controller(Path(args.policy))
    if args.cmd == "apply":
        r = ctl.apply(args.flow, args.chain, reason="cli")
        sys.exit(1 if r["errors"] else 0)
    if args.cmd == "show":
        for node in sorted({f.fwd["headend"] for f in ctl.flows.values()} |
                           {f.rev["headend"] for f in ctl.flows.values()} |
                           {s.proxy["node"] for s in ctl.sfs.values() if s.proxy}):
            tabs = sorted({f.table for f in ctl.flows.values()} | {f.proxy_table for f in ctl.flows.values()})
            _, out = ctl.sb.run(node, "ip -6 rule show | grep -vE '^(0|32766|32767):'; " +
                                "; ".join(f"ip -6 route show table {t} 2>/dev/null | sed 's/^/  [{t}] /'"
                                          for t in tabs))
            print(f"===== {node} =====\n{out}")
        return

    # run: cài baseline cho mọi flow, rồi bật các luồng phản ứng + API
    log("start", policy=args.policy, flows=list(ctl.flows), sfs=list(ctl.sfs))
    ctl.poll_health()
    for fn, f in ctl.flows.items():
        ctl.apply(fn, f.baseline, reason="baseline", pinned=False)
    threading.Thread(target=ctl.watch_eve, daemon=True).start()
    for t in ctl.p.get("triggers", []):
        if t["type"] == "nft_counter":
            ctl.install_nft_monitors(t)
    # sức khoẻ SF: vòng riêng, nhanh (quyết định thời gian gián đoạn khi SF chết)
    threading.Thread(target=ctl.loop, args=((ctl.poll_health,), ctl.p.get("health_interval", 0.5)),
                     daemon=True).start()
    threading.Thread(target=ctl.loop, args=((ctl.poll_nft, ctl.maybe_revert), ctl.p.get("poll_interval", 2)),
                     daemon=True).start()
    api = ctl.p.get("api", {})
    srv = ThreadingHTTPServer((api.get("host", "0.0.0.0"), api.get("port", 8000)), make_handler(ctl))
    log("api", listen=f"{api.get('host', '0.0.0.0')}:{api.get('port', 8000)}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        log("stop")


if __name__ == "__main__":
    main()
