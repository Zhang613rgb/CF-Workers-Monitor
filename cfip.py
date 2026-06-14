#!/usr/bin/env python3
"""cfip - Cloudflare 优选 IP 扫描器 (Python版)"""
import socket, ssl, sys, time, random, json, ipaddress, argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib.request
from pathlib import Path
from threading import Lock, Event

SCRIPT_DIR = Path(__file__).parent
DEFAULT_CACHE_DIR = Path("/tmp/cfip_cache")

OFFICIAL_CIDRS_V4 = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
]

OFFICIAL_CIDRS_V6 = [
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32",
    "2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
]

FALLBACK_URL = "cloudflaremirrors.com/oracle/OL9/u1/x86_64/OracleLinux-R9-U1-x86_64-dvd.iso"

FALLBACK_LOCATIONS = [
    {"iata":"SIN","city":"Singapore"},{"iata":"HKG","city":"Hong Kong"},
    {"iata":"NRT","city":"Tokyo"},{"iata":"ICN","city":"Seoul"},
    {"iata":"FRA","city":"Frankfurt"},{"iata":"AMS","city":"Amsterdam"},
    {"iata":"LHR","city":"London"},{"iata":"CDG","city":"Paris"},
    {"iata":"SJC","city":"San Jose"},{"iata":"LAX","city":"Los Angeles"},
    {"iata":"SFO","city":"San Francisco"},{"iata":"SEA","city":"Seattle"},
    {"iata":"JFK","city":"New York"},{"iata":"ORD","city":"Chicago"},
    {"iata":"MIA","city":"Miami"},{"iata":"DFW","city":"Dallas"},
]


class ScanState:
    def __init__(self, cache_dir=None):
        self.cache_dir = Path(cache_dir) if cache_dir else DEFAULT_CACHE_DIR
        self.location_map = {}
        self.speed_domain = ""
        self.speed_path = ""
        self._loaded_subnets_v4 = None
        self._loaded_subnets_v6 = None
        self._cancel_event = Event()
        self._progress_lock = Lock()
        self._progress = ""
        self._progress_callback = None

    def reset(self):
        self._cancel_event.clear()
        self.set_progress("正在初始化...")

    def cancel(self):
        self._cancel_event.set()
        self.set_progress("用户已取消扫描")

    def is_cancelled(self):
        return self._cancel_event.is_set()

    def set_progress(self, msg):
        with self._progress_lock:
            self._progress = msg
        if self._progress_callback:
            try:
                self._progress_callback(msg)
            except Exception:
                pass

    def get_progress(self):
        with self._progress_lock:
            return self._progress

    def set_progress_callback(self, callback):
        self._progress_callback = callback


_state = ScanState()


def get_state():
    return _state


def expand_to_24s(cidrs):
    result = []
    for c in cidrs:
        net = ipaddress.ip_network(c, strict=False)
        if net.prefixlen <= 24:
            result.extend(str(sub) for sub in net.subnets(new_prefix=24))
        else:
            result.append(str(net))
    return result


def try_download(url, timeout=8):
    req = urllib.request.Request(url, headers={
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/125.0.0.0 Safari/537.36"
    })
    return urllib.request.urlopen(req, timeout=timeout).read()


def read_file_lines(path):
    return [l.strip() for l in path.read_text().splitlines() if l.strip()]


def save_file(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, str):
        path.write_text(content)
    else:
        path.write_bytes(content)


def download_all_data(state):
    url_file = state.cache_dir / "url.txt"
    if not url_file.exists():
        if state.is_cancelled():
            return
        state.set_progress("正在下载测速 URL...")
        try:
            data = try_download("https://www.baipiao.eu.org/cloudflare/url")
            save_file(url_file, data)
        except Exception as e:
            state.set_progress(f"下载测速 URL 失败: {e}")
            return

    try:
        text = url_file.read_text().strip()
        idx = text.index("/")
        state.speed_domain = text[:idx]
        state.speed_path = text[idx:]
    except Exception as e:
        state.set_progress(f"解析测速 URL 失败: {e}")
        return

    for name, url in [("ips-v4.txt", "https://www.baipiao.eu.org/cloudflare/ips-v4"),
                      ("ips-v6.txt", "https://www.baipiao.eu.org/cloudflare/ips-v6")]:
        if state.is_cancelled():
            return
        fp = state.cache_dir / name
        if not fp.exists():
            state.set_progress(f"正在下载 IP 列表: {name}")
            try:
                data = try_download(url)
                save_file(fp, data)
            except Exception as e:
                state.set_progress(f"下载 IP 列表失败: {e}")
                return

    if state.is_cancelled():
        return
    loc_file = state.cache_dir / "locations.json"
    if not loc_file.exists():
        state.set_progress("正在下载位置信息...")
        try:
            data = try_download("https://www.baipiao.eu.org/cloudflare/locations")
            save_file(loc_file, data)
        except Exception as e:
            state.set_progress(f"下载位置信息失败: {e}")


def init_locations(state):
    download_all_data(state)
    if state.is_cancelled():
        return

    loc_file = state.cache_dir / "locations.json"
    try:
        data = json.loads(loc_file.read_text())
        state.location_map = {loc["iata"]: loc["city"] for loc in data}
    except Exception as e:
        state.set_progress(f"解析位置信息失败: {e}")
        state.location_map = {loc["iata"]: loc["city"] for loc in FALLBACK_LOCATIONS}


def load_ip_list(state, ip_type=4):
    if ip_type == 6 and state._loaded_subnets_v6 is not None:
        return state._loaded_subnets_v6
    if ip_type == 4 and state._loaded_subnets_v4 is not None:
        return state._loaded_subnets_v4

    filename = "ips-v6.txt" if ip_type == 6 else "ips-v4.txt"
    local_paths = [SCRIPT_DIR / filename, state.cache_dir / filename]

    for p in local_paths:
        if p.exists():
            subnets = read_file_lines(p)
            state.set_progress(f"使用本地文件 {p.name}")
            if ip_type == 6:
                state._loaded_subnets_v6 = subnets
            else:
                state._loaded_subnets_v4 = subnets
            return subnets

    cidrs = OFFICIAL_CIDRS_V6 if ip_type == 6 else OFFICIAL_CIDRS_V4
    subnets = expand_to_24s(cidrs)
    state.set_progress(f"使用官方 CIDR ({len(subnets)} 个)")
    if ip_type == 6:
        state._loaded_subnets_v6 = subnets
    else:
        state._loaded_subnets_v4 = subnets
    return subnets


def random_sample(lst, n):
    shuffled = lst[:]
    random.shuffle(shuffled)
    return shuffled[:min(n, len(shuffled))]


def get_random_ipv4s(subnets):
    ips = []
    for subnet in subnets:
        parts = subnet.split("/")[0].split(".")
        if len(parts) == 4:
            parts[-1] = str(random.randint(0, 255))
            ips.append(".".join(parts))
    return ips


def get_random_ipv6s(subnets):
    ips = []
    for subnet in subnets:
        subnet = subnet.split("/")[0]
        if "::" in subnet:
            left, right = subnet.split("::")
            left_parts = left.split(":") if left else []
            right_parts = right.split(":") if right else []
            missing = 8 - len(left_parts) - len(right_parts)
            sections = left_parts + ["0"] * missing + right_parts
        else:
            sections = subnet.split(":")
        if len(sections) >= 3:
            sections = sections[:3]
            for _ in range(3, 8):
                sections.append(f"{random.randint(0, 65535):x}")
            ips.append(":".join(sections))
    return ips


def test_rtt(ip, state, use_tls=True, timeout=1):
    port = 443 if use_tls else 80
    tcp_times = []
    for _ in range(3):
        try:
            if state.is_cancelled():
                return 0
            t0 = time.time()
            sock = socket.create_connection((ip, port), timeout=timeout)
            tcp_ms = int((time.time() - t0) * 1000)

            if use_tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname="cloudflare.com")
                sock.settimeout(timeout)

            req = f"GET / HTTP/1.1\r\nHost: cloudflare.com\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
            sock.sendall(req.encode())

            buf = b""
            while True:
                chunk = sock.read(4096)
                if not chunk:
                    break
                buf += chunk
            sock.close()

            if use_tls and b"CF-RAY" not in buf:
                return 0
            if not use_tls and b"HTTP/" not in buf:
                return 0
            tcp_times.append(tcp_ms)
        except Exception:
            return 0
    return sum(tcp_times) // len(tcp_times) if tcp_times else 0


def run_rtt_test(ip_list, state, task_num=50, use_tls=True):
    if len(ip_list) < task_num:
        task_num = len(ip_list)

    total = len(ip_list)
    count = 0
    count_lock = Lock()
    results = []

    def test_one(ip):
        nonlocal count
        if state.is_cancelled():
            return None
        avg_ms = test_rtt(ip, state, use_tls)
        with count_lock:
            count += 1
            current = count
        if current % 10 == 0 or current == total:
            state.set_progress(f"RTT 测试进度: {current}/{total}")
        if avg_ms > 0:
            return (ip, avg_ms)
        return None

    with ThreadPoolExecutor(max_workers=task_num) as pool:
        futures = {pool.submit(test_one, ip): ip for ip in ip_list}
        for f in as_completed(futures):
            if state.is_cancelled():
                return []
            result = f.result()
            if result:
                results.append(result)

    if state.is_cancelled():
        return []

    results.sort(key=lambda x: x[1])
    if len(results) > 10:
        state.set_progress(f"RTT 测试完成，{len(results)}/{total} 个 IP 有效，保留延迟最低的 10 个")
        results = results[:10]
    else:
        state.set_progress(f"RTT 测试完成，{len(results)}/{total} 个 IP 有效")
    return results


def test_speed(ip, state, use_tls=True, timeout=5):
    port = 443 if use_tls else 80
    tcp_ms = 0
    try:
        t0 = time.time()
        sock = socket.create_connection((ip, port), timeout=3)
        tcp_ms = int((time.time() - t0) * 1000)

        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=state.speed_domain)
            sock.settimeout(timeout)

        scheme = "https" if use_tls else "http"
        req = (
            f"GET {state.speed_path} HTTP/1.1\r\n"
            f"Host: {state.speed_domain}\r\n"
            f"User-Agent: curl/8.0\r\n"
            f"Accept: */*\r\n"
            f"Connection: close\r\n\r\n"
        )
        sock.sendall(req.encode())

        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = sock.read(4096)
            if not chunk:
                sock.close()
                return 0, tcp_ms, ""
            buf += chunk

        header_end = buf.find(b"\r\n\r\n") + 4
        status_line = buf.split(b"\r\n")[0]
        if b"200" not in status_line and b"206" not in status_line:
            sock.close()
            return 0, tcp_ms, ""

        dc = ""
        for line in buf[:header_end].split(b"\r\n"):
            if line.lower().startswith(b"cf-ray:"):
                ray = line.split(b":", 1)[1].strip().decode()
                parts = ray.rsplit("-", 1)
                dc = parts[1] if len(parts) > 1 else ""
                break

        window_bytes = len(buf[header_end:])
        window_start = time.time()
        max_speed = 0
        deadline = time.time() + timeout

        while time.time() < deadline:
            remaining = deadline - time.time()
            if remaining <= 0:
                break
            try:
                sock.settimeout(min(remaining, 5))
                chunk = sock.read(65536)
            except Exception:
                break
            if not chunk:
                break
            window_bytes += len(chunk)

            elapsed = time.time() - window_start
            if elapsed >= 1.0:
                speed_kb = int(window_bytes / 1024 / elapsed)
                if speed_kb > max_speed:
                    max_speed = speed_kb
                window_bytes = 0
                window_start = time.time()

        elapsed = time.time() - window_start
        if elapsed > 0 and window_bytes > 0:
            speed_kb = int(window_bytes / 1024 / elapsed)
            if speed_kb > max_speed:
                max_speed = speed_kb

        sock.close()
        return max_speed, tcp_ms, dc
    except Exception:
        return 0, tcp_ms, ""


def lookup_city(state, dc):
    if not dc:
        return ""
    return state.location_map.get(dc, dc)


def cloudflare_test(state, ip_type=4, use_tls=True, task_num=50, speed_target=1280):
    init_locations(state)
    if state.is_cancelled():
        return "", 0, 0, ""

    subnets = load_ip_list(state, ip_type)
    state.set_progress(f"正在从 {len(subnets)} 个子网中随机生成 IP...")

    sample_size = min(100, len(subnets))

    while True:
        if state.is_cancelled():
            return "", 0, 0, ""

        sampled = random_sample(subnets, sample_size)
        test_ips = get_random_ipv6s(sampled) if ip_type == 6 else get_random_ipv4s(sampled)

        state.set_progress(f"已生成 {len(test_ips)} 个测试 IP，开始 RTT 测试...")
        rtt_results = run_rtt_test(test_ips, state, task_num, use_tls)

        if state.is_cancelled():
            return "", 0, 0, ""
        if not rtt_results:
            state.set_progress("当前所有 IP 都存在 RTT 丢包，继续新的 RTT 测试...")
            continue

        for ip, rtt in rtt_results:
            if state.is_cancelled():
                return "", 0, 0, ""

            state.set_progress(f"正在测速 {ip} (延迟 {rtt}ms)")
            speed, tcp_ms, dc = test_speed(ip, state, use_tls)
            dc_name = lookup_city(state, dc) if dc else ""

            state.set_progress(f"{ip} 峰值速度 {speed} kB/s, 数据中心 {dc_name}")

            if speed >= speed_target:
                return ip, speed, tcp_ms, dc_name

        state.set_progress("当前所有 IP 都未达到期望带宽，重新开始新一轮测试...")


def scan(bandwidth_mbps=10, task_num=50, use_tls=True, ip_type=4, cache_dir=None, progress_callback=None):
    state = get_state()
    if cache_dir:
        state.cache_dir = Path(cache_dir)
    if progress_callback:
        state.set_progress_callback(progress_callback)

    state.reset()
    speed_target = bandwidth_mbps * 128

    ip, max_speed, latency, dc = cloudflare_test(state, ip_type, use_tls, task_num, speed_target)

    return {
        "ip": ip,
        "bandwidth": bandwidth_mbps,
        "realBandwidth": max_speed // 128,
        "maxSpeed": max_speed,
        "latencyMs": latency,
        "dataCenter": dc,
        "error": f"未找到符合 {bandwidth_mbps} Mbps 带宽目标的 IP" if not ip else ""
    }


def update_data(cache_dir=None):
    state = get_state()
    if cache_dir:
        state.cache_dir = Path(cache_dir)
    state.set_progress("正在更新数据...")
    for f in ["locations.json", "ips-v4.txt", "ips-v6.txt", "url.txt"]:
        fp = state.cache_dir / f
        if fp.exists():
            fp.unlink()
    init_locations(state)
    state.set_progress("数据更新完成")


def clear_cache(cache_dir=None):
    state = get_state()
    if cache_dir:
        state.cache_dir = Path(cache_dir)
    state.set_progress("正在清除缓存...")
    for f in ["locations.json", "ips-v4.txt", "ips-v6.txt", "url.txt"]:
        fp = state.cache_dir / f
        if fp.exists():
            fp.unlink()
    state.set_progress("缓存已清除")


def git_commit_push(repo_dir, files, msg="更新优选 IP"):
    """提交文件并推送到 GitHub"""
    import subprocess
    try:
        for f in files:
            subprocess.run(["git", "-C", str(repo_dir), "add", f], capture_output=True)
        r = subprocess.run(
            ["git", "-C", str(repo_dir), "commit", "-m", f"[auto] {msg}"],
            capture_output=True, timeout=10
        )
        if r.returncode == 0:
            subprocess.run(
                ["git", "-C", str(repo_dir), "push"],
                capture_output=True, timeout=30
            )
            print("[*] 已推送至 GitHub")
        elif b"nothing to commit" in r.stderr:
            print("[*] 无变更，跳过推送")
        else:
            print(f"[*] git commit 失败: {r.stderr.decode()}")
    except Exception as e:
        print(f"[*] git push 失败: {e}")


def main():
    parser = argparse.ArgumentParser(description="Cloudflare 优选 IP 扫描器")
    subparsers = parser.add_subparsers(dest="command", help="子命令")

    scan_parser = subparsers.add_parser("scan", help="扫描优选 IP")
    scan_parser.add_argument("-b", "--bandwidth", type=int, default=10, help="期望带宽 Mbps (默认 10)")
    scan_parser.add_argument("-t", "--tasks", type=int, default=50, help="并发任务数 (默认 50)")
    scan_parser.add_argument("-n", "--count", type=int, default=1, help="扫描 IP 数量 (默认 1)")
    scan_parser.add_argument("--no-tls", action="store_true", help="不使用 TLS")
    scan_parser.add_argument("-6", "--ipv6", action="store_true", help="使用 IPv6")
    scan_parser.add_argument("-c", "--cache-dir", type=str, help="缓存目录")
    scan_parser.add_argument("-r", "--repo", type=str, help="GitHub 仓库路径，用于保存结果")
    scan_parser.add_argument("--push", action="store_true", help="自动提交并推送到 GitHub")

    subparsers.add_parser("update", help="更新数据文件").add_argument("-c", "--cache-dir", type=str)
    subparsers.add_parser("clear", help="清除缓存").add_argument("-c", "--cache-dir", type=str)

    args = parser.parse_args()

    def print_progress(msg):
        print(f"[*] {msg}", file=sys.stderr)

    if args.command == "update":
        update_data(args.cache_dir)
        return
    elif args.command == "clear":
        clear_cache(args.cache_dir)
        return

    if args.command != "scan":
        if args.command is None:
            args = scan_parser.parse_args([])
        else:
            sys.exit(1)

    ports = [443, 8443, 2053, 2083, 2087, 2096]
    all_lines = []
    scanned = set()

    for i in range(args.count):
        print(f"\n{'='*40}\n第 {i+1}/{args.count} 次扫描\n{'='*40}")
        result = scan(
            bandwidth_mbps=args.bandwidth,
            task_num=args.tasks,
            use_tls=not args.no_tls,
            ip_type=6 if args.ipv6 else 4,
            cache_dir=args.cache_dir,
            progress_callback=print_progress
        )
        if result["ip"]:
            ip = result["ip"]
            if ip in scanned:
                print(f"[*] IP {ip} 已存在，跳过")
                continue
            scanned.add(ip)

            dc = f" [{result['dataCenter']}]" if result['dataCenter'] else ""
            speed_mbps = result['realBandwidth']
            latency = result['latencyMs']
            for p in ports:
                all_lines.append(f"{ip}:{p}#{ip}-{p}{dc} {speed_mbps}Mbps {latency}ms")
            print(f"✓ {ip} {speed_mbps}Mbps {latency}ms{dc}")
        else:
            print(f"✗ 第 {i+1} 次扫描失败: {result['error']}", file=sys.stderr)
            if i == 0:
                sys.exit(1)

    if not all_lines:
        print("无有效 IP", file=sys.stderr)
        sys.exit(1)

    # 输出到文件
    repo_dir = Path(args.repo) if args.repo else SCRIPT_DIR
    repo_dir.mkdir(parents=True, exist_ok=True)
    out_dir = repo_dir / "speedtest" / "output"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "cfyd.txt"
    out_path.write_text("\n".join(all_lines))
    print(f"\n[*] 共 {args.count} 个 IP → {len(all_lines)} 条节点 → {out_path}")

    # 自动推送到 GitHub
    if args.push and args.repo:
        git_commit_push(args.repo, [str(out_path.relative_to(args.repo))], f"更新优选 IP ({len(scanned)} 个)")


if __name__ == "__main__":
    main()
