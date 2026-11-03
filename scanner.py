#!/usr/bin/env python3
"""Scan local : qui est sur le même Wi-Fi."""

from __future__ import annotations

import ipaddress
import json
import re
import socket
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

OUI_PATH = Path("/usr/share/nmap/nmap-mac-prefixes")
SAVE_PATH = Path(__file__).resolve().parent / "appareils_connus.json"
HIST_PATH = Path(__file__).resolve().parent / "appareils_historique.json"

vendors: dict[str, str] = {}


def run(cmd: list[str], timeout: float = 8) -> str:
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return result.stdout or ""
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return ""


def load_vendors() -> dict[str, str]:
    table: dict[str, str] = {}
    if not OUI_PATH.exists():
        return table
    for line in OUI_PATH.read_text(errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) == 2 and re.fullmatch(r"[0-9A-Fa-f]{6,10}", parts[0]):
            table[parts[0].upper()] = parts[1].strip()
    return table


def vendor_of(mac: str) -> str:
    clean = mac.replace(":", "").replace("-", "").upper()
    for size in (10, 8, 6):
        if clean[:size] in vendors:
            return vendors[clean[:size]]
    return "Marque inconnue"


def load_names() -> dict[str, str]:
    if not SAVE_PATH.exists():
        return {}
    try:
        data = json.loads(SAVE_PATH.read_text())
        return {k.lower(): v for k, v in data.items() if isinstance(v, str)}
    except (OSError, json.JSONDecodeError):
        return {}


def save_name(mac: str, name: str) -> None:
    names = load_names()
    key = mac.lower()
    name = name.strip()
    if name:
        names[key] = name
    else:
        names.pop(key, None)
    SAVE_PATH.write_text(json.dumps(names, ensure_ascii=False, indent=2))


def wifi_info() -> dict:
    info = {
        "ssid": "Wi-Fi",
        "iface": "",
        "ip": "",
        "cidr": "",
        "gateway": "",
        "mac": "",
        "hostname": socket.gethostname(),
        "network": "",
        "host_count": 0,
        "scan_network": "",
        "shared": False,
    }

    for line in run(["nmcli", "-t", "-f", "DEVICE,TYPE,STATE,CONNECTION", "device"]).splitlines():
        parts = line.split(":")
        if len(parts) >= 4 and parts[1] == "wifi" and "connect" in parts[2]:
            info["iface"] = parts[0]
            info["ssid"] = parts[3] or info["ssid"]
            break

    if not info["iface"]:
        for line in run(["ip", "-4", "route", "show", "default"]).splitlines():
            match = re.search(r"dev (\S+)", line)
            if match and match.group(1) not in {"lo", "docker0"}:
                info["iface"] = match.group(1)
                break

    iface = info["iface"]
    for line in run(["ip", "-4", "route"]).splitlines():
        if line.startswith("default") and iface and f"dev {iface}" in line:
            gw = re.search(r"via (\d+\.\d+\.\d+\.\d+)", line)
            if gw:
                info["gateway"] = gw.group(1)
        elif iface and f"dev {iface}" in line and "proto kernel" in line:
            match = re.search(r"(\d+\.\d+\.\d+\.\d+/\d+)", line)
            src = re.search(r"src (\d+\.\d+\.\d+\.\d+)", line)
            if match:
                info["cidr"] = match.group(1)
            if src:
                info["ip"] = src.group(1)

    if iface:
        link = run(["ip", "-o", "link", "show", iface])
        mac = re.search(r"link/ether ([0-9a-f:]{17})", link, re.I)
        if mac:
            info["mac"] = mac.group(1).lower()

    if info["cidr"]:
        net = ipaddress.IPv4Network(info["cidr"], strict=False)
        info["network"] = str(net)
        info["scan_network"] = str(net)
        info["host_count"] = max(net.num_addresses - 2, 0)
        info["shared"] = net.prefixlen < 24
    return info


def mac_randomized(mac: str) -> bool:
    try:
        return bool(int(mac.split(":")[0], 16) & 0x02)
    except (ValueError, IndexError):
        return False


def classify_device(vendor: str, hostname: str, role: str, ttl: int | None, mac: str) -> tuple[str, str, str]:
    brand = vendor if vendor and vendor != "Marque inconnue" else ""
    blob = f"{vendor} {hostname}".lower()
    kind = "Appareil"
    system = ""

    if ttl is not None:
        if ttl <= 64:
            system = "Linux / Android / Apple"
        elif ttl <= 128:
            system = "Windows"
        else:
            system = "Équipement réseau"

    def has(*words: str) -> bool:
        return any(word in blob for word in words)

    if role == "box" or has("routeur", "router", "gateway", "box"):
        kind = "Box / routeur"
        system = system or "Équipement réseau"
    elif has("iphone"):
        kind, brand, system = "Téléphone", brand or "Apple", "iPhone / iOS"
    elif has("ipad"):
        kind, brand, system = "Tablette", brand or "Apple", "iPadOS"
    elif has("macbook", "imac", "mac-mini", "mac mini"):
        kind, brand, system = "PC", brand or "Apple", "macOS"
    elif has(
        "android", "galaxy", "pixel", "redmi", "poco", "xiaomi", "honor",
        "oppo", "vivo", "oneplus", "realme", "tecno", "infinix", "motorola",
        "nokia", "smartphone", "sm-", "phone",
    ):
        kind = "Téléphone"
        if has("samsung", "galaxy", "sm-"):
            brand = brand or "Samsung"
            system = "Android"
        elif has("xiaomi", "redmi", "poco"):
            brand = brand or "Xiaomi"
            system = "Android"
        elif has("pixel", "google"):
            brand = brand or "Google"
            system = "Android"
        else:
            system = "Android"
    elif has("tablet", "tab "):
        kind = "Tablette"
    elif has("playstation", "xbox", "nintendo", "switch"):
        kind = "Console"
    elif has("bravia", "chromecast", "roku", "firetv", "fire-tv", "smart-tv", "webos", "hisense"):
        kind = "TV"
    elif has("printer", "imprim", "canon", "epson", "brother", "xerox", "deskjet", "laserjet"):
        kind = "Imprimante"
    elif has("tp-link", "netgear", "cisco", "mikrotik", "ubiquiti", "zyxel", "sagem", "arcadyan", "technicolor"):
        kind = "Box / routeur"
    elif has("espressif", "esp32", "tuya", "shelly", "sonoff", "echo", "nest", "ring"):
        kind = "Objet connecté"
    elif has(
        "intel", "dell", "lenovo", "hewlett", "hp inc", "asus", "acer", "msi",
        "gigabyte", "realtek", "azurewave", "liteon", "hon hai", "foxconn",
        "thinkpad", "latitude", "optiplex", "desktop", "laptop", "windows",
    ):
        kind = "PC"
        if "windows" in blob or (ttl is not None and 100 <= ttl <= 128):
            system = "Windows"
    elif "apple" in blob:
        kind = "Appareil Apple"
        brand = brand or "Apple"
        system = system or "Apple"
    elif mac_randomized(mac) and role != "box":
        kind = "Téléphone"
        brand = brand or "Marque masquée"
        system = system or "Android / iPhone (MAC aléatoire)"

    if not brand:
        brand = "Marque inconnue" if not mac_randomized(mac) else "Marque masquée (MAC aléatoire)"
    return kind, brand, system


def ping_ttl(ip: str) -> int | None:
    output = run(["ping", "-c", "1", "-W", "1", ip], timeout=2)
    match = re.search(r"ttl[=:](\d+)", output, re.I)
    if match:
        return int(match.group(1))
    return None


def mdns_names() -> dict[str, str]:
    names: dict[str, str] = {}
    output = run(["avahi-browse", "-a", "-t", "-p", "-l"], timeout=10)
    for line in output.splitlines():
        parts = line.split(";")
        if len(parts) < 8:
            continue
        host = parts[6].strip().strip(".")
        addr = parts[7].strip()
        if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", addr) and host:
            names[addr] = host.split(".")[0]
    return names


def parse_nmap_xml(xml: str) -> dict[str, dict]:
    found: dict[str, dict] = {}
    if not xml.strip():
        return found
    for block in re.findall(r"<host\b.*?</host>", xml, re.S):
        if 'state="up"' not in block:
            continue
        ip_match = re.search(r'addr="(\d+\.\d+\.\d+\.\d+)" addrtype="ipv4"', block)
        mac_match = re.search(r'addr="([0-9A-Fa-f:]{17})" addrtype="mac"', block)
        vendor_match = re.search(r'addrtype="mac"[^>]*vendor="([^"]*)"', block)
        if not ip_match:
            continue
        ip = ip_match.group(1)
        mac = mac_match.group(1).lower() if mac_match else ""
        if not mac:
            continue
        vendor = vendor_match.group(1) if vendor_match else ""
        found[ip] = {"ip": ip, "mac": mac, "status": "en ligne", "nmap_vendor": vendor}
    return found


def nmap_hosts(network: str) -> dict[str, dict]:
    xml = run(
        [
            "nmap",
            "-sn",
            "-n",
            "-T5",
            "--max-retries",
            "1",
            "--host-timeout",
            "800ms",
            "--min-rate",
            "2000",
            "-oX",
            "-",
            network,
        ],
        timeout=90,
    )
    return parse_nmap_xml(xml)


def nmap_hosts_privileged(network: str) -> dict[str, dict]:
    xml = run(
        [
            "pkexec",
            "nmap",
            "-sn",
            "-PR",
            "-n",
            "-T5",
            "--min-rate",
            "1000",
            "-oX",
            "-",
            network,
        ],
        timeout=180,
    )
    return parse_nmap_xml(xml)


UDP_PORTS = (53, 67, 123, 137, 138, 161, 500, 1900, 5353, 5355, 33434, 17500, 3702)
TCP_PORTS = (80, 443, 8080, 8443, 62078, 5555, 445, 139, 22, 5000)


def ingest_neigh_line(line: str, iface: str, into: dict[str, dict], lock: threading.Lock) -> None:
    if "Deleted" in line or "FAILED" in line:
        return
    if iface and f"dev {iface}" not in line:
        return
    mac_match = re.search(r"lladdr ([0-9a-f:]{17})", line, re.I)
    if not mac_match:
        return
    ipv4 = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
    if ipv4:
        ip = ipv4.group(1)
    else:
        first = re.match(r"(\S+)", line.strip())
        ip = first.group(1) if first else ""
        if not ip:
            return
    status = "en ligne" if any(x in line for x in ("REACHABLE", "DELAY", "PROBE", "PERMANENT")) else "vu récemment"
    row = {"ip": ip, "mac": mac_match.group(1).lower(), "status": status}
    with lock:
        prev = into.get(ip)
        if prev is None or (status == "en ligne" and prev.get("status") != "en ligne"):
            into[ip] = row


class NeighWatch:
    def __init__(self, iface: str, into: dict[str, dict], lock: threading.Lock):
        self.iface = iface
        self.into = into
        self.lock = lock
        self.proc: subprocess.Popen | None = None
        self.thread: threading.Thread | None = None

    def start(self) -> None:
        self.proc = subprocess.Popen(
            ["ip", "monitor", "neigh"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
        )
        self.thread = threading.Thread(target=self._read, daemon=True)
        self.thread.start()

    def _read(self) -> None:
        if not self.proc or not self.proc.stdout:
            return
        for line in self.proc.stdout:
            ingest_neigh_line(line, self.iface, self.into, self.lock)

    def stop(self) -> None:
        if self.proc:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=1)
            except subprocess.TimeoutExpired:
                self.proc.kill()


def probe(ip: str) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    try:
        payload = b"\x00"
        for port in UDP_PORTS:
            try:
                sock.sendto(payload, (ip, port))
            except OSError:
                pass
    finally:
        sock.close()


def tcp_poke(ip: str) -> None:
    for port in TCP_PORTS:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.08)
        try:
            sock.connect((ip, port))
        except OSError:
            pass
        finally:
            sock.close()


def ssdp_blast() -> None:
    msg = (
        'M-SEARCH * HTTP/1.1\r\n'
        'HOST: 239.255.255.250:1900\r\n'
        'MAN: "ssdp:discover"\r\n'
        'MX: 1\r\n'
        'ST: ssdp:all\r\n\r\n'
    ).encode()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.settimeout(0.4)
    try:
        sock.sendto(msg, ("239.255.255.250", 1900))
        sock.sendto(msg, ("255.255.255.255", 1900))
    except OSError:
        pass
    finally:
        sock.close()


def mdns_blast() -> None:
    # PTR query for services, enough to wake mDNS stacks.
    payload = bytes.fromhex("000000000001000000000000095f7365727669636573075f646e732d7364045f756470056c6f63616c00000c0001")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    try:
        sock.sendto(payload, ("224.0.0.251", 5353))
    except OSError:
        pass
    finally:
        sock.close()


def parse_arp(iface: str) -> dict[str, dict]:
    found: dict[str, dict] = {}
    output = run(["ip", "neigh", "show", "nud", "all"])
    for line in output.splitlines():
        if iface and f"dev {iface}" not in line:
            continue
        ip_match = re.match(r"(\d+\.\d+\.\d+\.\d+)", line)
        mac_match = re.search(r"lladdr ([0-9a-f:]{17})", line, re.I)
        if not ip_match or not mac_match:
            continue
        status = "vu récemment"
        if any(flag in line for flag in ("REACHABLE", "DELAY", "PROBE", "PERMANENT")):
            status = "en ligne"
        ip = ip_match.group(1)
        found[ip] = {
            "ip": ip,
            "mac": mac_match.group(1).lower(),
            "status": status,
        }
    return found


def harvest_arp(into: dict[str, dict], iface: str, lock: threading.Lock | None = None) -> None:
    rank = {"en ligne": 0, "vu récemment": 1, "hors ligne": 2}
    rows = parse_arp(iface)

    def merge() -> None:
        for ip, row in rows.items():
            prev = into.get(ip)
            if prev is None or rank.get(row["status"], 9) <= rank.get(prev["status"], 9):
                into[ip] = row

    if lock:
        with lock:
            merge()
    else:
        merge()


def harvest_ipv6(into: dict[str, dict], iface: str) -> None:
    run(["ping", "-6", "-c", "2", "-W", "1", "-I", iface, "ff02::1"], timeout=5)
    known_macs = {row["mac"] for row in into.values() if row.get("mac")}
    output = run(["ip", "-6", "neigh", "show"])
    for line in output.splitlines():
        if iface and f"dev {iface}" not in line:
            continue
        ip_match = re.match(r"(\S+)", line)
        mac_match = re.search(r"lladdr ([0-9a-f:]{17})", line, re.I)
        if not ip_match or not mac_match:
            continue
        mac = mac_match.group(1).lower()
        if mac in known_macs:
            continue
        ip = ip_match.group(1)
        status = "en ligne" if "REACHABLE" in line else "vu récemment"
        into[ip] = {"ip": ip, "mac": mac, "status": status}
        known_macs.add(mac)


def load_history() -> dict[str, dict]:
    if not HIST_PATH.exists():
        return {}
    try:
        data = json.loads(HIST_PATH.read_text())
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def save_history(arp: dict[str, dict]) -> None:
    hist = load_history()
    for row in arp.values():
        mac = row.get("mac", "")
        if not mac:
            continue
        hist[mac] = {
            "ip": row["ip"],
            "mac": mac,
            "status": "vu récemment",
            "nmap_vendor": row.get("nmap_vendor", ""),
        }
    HIST_PATH.write_text(json.dumps(hist, ensure_ascii=False, indent=2))


def merge_history(arp: dict[str, dict]) -> None:
    known_macs = {row["mac"] for row in arp.values() if row.get("mac")}
    known_ips = set(arp)
    for mac, row in load_history().items():
        ip = row.get("ip") or mac
        if mac in known_macs or ip in known_ips:
            continue
        arp[ip] = {
            "ip": ip,
            "mac": mac,
            "status": "vu récemment",
            "nmap_vendor": row.get("nmap_vendor", ""),
        }


def hostname_of(ip: str) -> str:
    result = [""]

    def lookup() -> None:
        try:
            name = socket.getnameinfo((ip, 0), socket.NI_NAMEREQD)[0]
            if name and name != ip:
                result[0] = name.split(".")[0]
        except OSError:
            pass

    worker = threading.Thread(target=lookup, daemon=True)
    worker.start()
    worker.join(0.2)
    return result[0]


def build_devices(info: dict, arp: dict[str, dict], resolve_names: bool = False) -> list[dict]:
    names = load_names()
    devices = []
    arp = dict(arp)

    if info.get("ip") and info.get("mac"):
        arp[info["ip"]] = {
            "ip": info["ip"],
            "mac": info["mac"],
            "status": "en ligne",
        }

    hosts: dict[str, str] = dict(info.get("mdns") or {})
    ttls: dict[str, int | None] = {}
    if resolve_names:
        with ThreadPoolExecutor(max_workers=48) as pool:
            host_futs = {pool.submit(hostname_of, ip): ip for ip in arp}
            ttl_futs = {}
            if len(arp) <= 120:
                ttl_futs = {pool.submit(ping_ttl, ip): ip for ip in arp}
            for future in as_completed(host_futs):
                ip = host_futs[future]
                try:
                    hosts[ip] = future.result() or hosts.get(ip, "")
                except Exception:
                    hosts.setdefault(ip, "")
            for future in as_completed(ttl_futs):
                ip = ttl_futs[future]
                try:
                    ttls[ip] = future.result()
                except Exception:
                    ttls[ip] = None

    for ip, row in arp.items():
        mac = row["mac"]
        role = "appareil"
        label = names.get(mac, "")
        if ip == info.get("gateway"):
            role = "box"
            label = label or "Box / routeur"
        elif ip == info.get("ip"):
            role = "toi"
            label = label or f"Cet ordinateur ({info.get('hostname') or 'toi'})"
        host = hosts.get(ip, "")
        vendor = row.get("nmap_vendor") or vendor_of(mac)
        kind, brand, system = classify_device(vendor, host or label, role, ttls.get(ip), mac)
        if role == "toi":
            kind = "PC"
            brand = brand if brand != "Marque inconnue" else vendor_of(mac)
        known = bool(label) or role in {"toi", "box"}
        devices.append(
            {
                "ip": ip,
                "mac": mac,
                "status": row["status"],
                "vendor": vendor,
                "brand": brand,
                "kind": kind,
                "system": system,
                "hostname": host,
                "name": label,
                "role": role,
                "known": known,
            }
        )

    order = {"toi": 0, "box": 1, "appareil": 2}
    status_order = {"en ligne": 0, "vu récemment": 1, "hors ligne": 2}
    devices.sort(
        key=lambda d: (
            0 if d["known"] else 1,
            order.get(d["role"], 9),
            status_order.get(d["status"], 9),
            ip_sort_key(d["ip"]),
        )
    )
    return devices


def ip_sort_key(ip: str) -> tuple:
    try:
        return (0, int(ipaddress.IPv4Address(ip)))
    except Exception:
        try:
            return (1, int(ipaddress.IPv6Address(ip)))
        except Exception:
            return (2, 0)


def scan_targets(info: dict) -> list[str]:
    network = info.get("scan_network") or info.get("cidr")
    if not network:
        return []
    net = ipaddress.IPv4Network(network, strict=False)
    targets = [str(ip) for ip in net.hosts() if str(ip) != info.get("ip")]
    gateway = info.get("gateway")
    if gateway and gateway != info.get("ip") and gateway not in targets:
        targets.append(gateway)
    return targets


def scan_network(on_progress=None, deep: bool = False) -> dict:
    global vendors
    if not vendors:
        vendors = load_vendors()

    def progress(pct: int, message: str, info: dict, devices: list[dict]) -> None:
        if on_progress:
            on_progress(
                {
                    "scanning": True,
                    "progress": pct,
                    "message": message,
                    "info": info,
                    "devices": devices,
                }
            )

    info = wifi_info()
    if not info.get("cidr") or not info.get("iface"):
        result = {
            "scanning": False,
            "progress": 0,
            "message": "Impossible de trouver le Wi-Fi.",
            "info": info,
            "devices": [],
        }
        if on_progress:
            on_progress(result)
        return result

    iface = info["iface"]
    lock = threading.Lock()
    seen: dict[str, dict] = {}
    harvest_arp(seen, iface, lock)
    watch = NeighWatch(iface, seen, lock)
    watch.start()
    devices = build_devices(info, seen, resolve_names=False)
    progress(3, f"Scan profond de TOUT {info.get('network')} ({info.get('host_count')} IP)…", info, devices)

    try:
        if info.get("cidr"):
            net = ipaddress.IPv4Network(info["cidr"], strict=False)
            run(["ping", "-b", "-c", "3", "-W", "1", str(net.broadcast_address)], timeout=5)
        ssdp_blast()
        mdns_blast()
        harvest_arp(seen, iface, lock)

        targets = scan_targets(info)
        total = max(len(targets), 1)
        network = info.get("scan_network") or info.get("cidr")

        def snapshot(pct: int, message: str) -> None:
            with lock:
                current = dict(seen)
            progress(pct, f"{message} — {len(current)} trouvé(s)", info, build_devices(info, current, False))

        snapshot(6, "Réveil multicast / broadcast")

        with ThreadPoolExecutor(max_workers=400) as pool:
            done = 0
            for _ in pool.map(probe, targets):
                done += 1
                if done % 200 == 0 or done == total:
                    snapshot(6 + int(done / total * 25), f"UDP sur toutes les IP… {done}/{total}")

        snapshot(32, "Deuxième passe UDP")
        with ThreadPoolExecutor(max_workers=400) as pool:
            list(pool.map(probe, targets))

        if network:
            snapshot(38, "fping de tout le réseau")
            run(["fping", "-a", "-q", "-i", "1", "-r", "1", "-t", "80", "-g", network], timeout=45)

        snapshot(48, "Connexions TCP (téléphones / PC)")
        with ThreadPoolExecutor(max_workers=200) as pool:
            done = 0
            for _ in pool.map(tcp_poke, targets):
                done += 1
                if done % 250 == 0 or done == total:
                    snapshot(48 + int(done / total * 22), f"TCP sur toutes les IP… {done}/{total}")

        ssdp_blast()
        mdns_blast()
        harvest_ipv6(seen, iface)
        time.sleep(1.2)
        harvest_arp(seen, iface, lock)

        if deep and network:
            snapshot(84, "Scan root ARP : mot de passe Linux si demandé")
            extra = nmap_hosts_privileged(network)
            with lock:
                for ip, row in extra.items():
                    seen[ip] = row
    finally:
        watch.stop()

    harvest_arp(seen, iface, lock)
    merge_history(seen)
    save_history(seen)
    arp = dict(seen)
    info["mdns"] = mdns_names()
    progress(90, f"Identification de {len(arp)} appareil(s)…", info, build_devices(info, arp, False))
    devices = build_devices(info, arp, resolve_names=True)
    online = sum(1 for d in devices if d["status"] == "en ligne")
    unknown = sum(1 for d in devices if not d["known"])
    macs = {d["mac"] for d in devices if d.get("mac")}
    message = f"{len(devices)} appareil(s), {len(macs)} MAC, {online} en ligne, {unknown} inconnu(s)"
    result = {
        "scanning": False,
        "progress": 100,
        "message": message,
        "info": info,
        "devices": devices,
    }
    if on_progress:
        on_progress(result)
    return result
