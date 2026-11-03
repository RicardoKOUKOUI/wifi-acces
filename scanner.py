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
        return result.stdout
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
        info["host_count"] = max(net.num_addresses - 2, 0)
        if net.prefixlen < 24 and info["ip"]:
            local = ipaddress.IPv4Network(f"{info['ip']}/24", strict=False)
            info["scan_network"] = str(local)
            info["shared"] = True
        else:
            info["scan_network"] = str(net)
    return info


def probe(ip: str) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    try:
        sock.sendto(b"\x00", (ip, 5353))
    except OSError:
        pass
    finally:
        sock.close()


def parse_arp(iface: str) -> dict[str, dict]:
    found: dict[str, dict] = {}
    output = run(["ip", "neigh", "show"])
    for line in output.splitlines():
        if iface and f"dev {iface}" not in line:
            continue
        ip_match = re.match(r"(\d+\.\d+\.\d+\.\d+)", line)
        mac_match = re.search(r"lladdr ([0-9a-f:]{17})", line, re.I)
        if not ip_match or not mac_match:
            continue
        status = "hors ligne"
        if any(flag in line for flag in ("REACHABLE", "DELAY", "PROBE", "PERMANENT")):
            status = "en ligne"
        elif "STALE" in line:
            status = "vu récemment"
        else:
            continue
        ip = ip_match.group(1)
        found[ip] = {
            "ip": ip,
            "mac": mac_match.group(1).lower(),
            "status": status,
        }
    return found


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

    hosts: dict[str, str] = {}
    if resolve_names:
        with ThreadPoolExecutor(max_workers=24) as pool:
            futures = {pool.submit(hostname_of, ip): ip for ip in arp}
            for future in as_completed(futures):
                ip = futures[future]
                try:
                    hosts[ip] = future.result() or ""
                except Exception:
                    hosts[ip] = ""

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
        known = bool(label) or role in {"toi", "box"}
        devices.append(
            {
                "ip": ip,
                "mac": mac,
                "status": row["status"],
                "vendor": vendor_of(mac),
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
            tuple(int(x) for x in d["ip"].split(".")),
        )
    )
    return devices


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


def scan_network(on_progress=None) -> dict:
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

    arp = parse_arp(info["iface"])
    devices = build_devices(info, arp, resolve_names=False)
    progress(8, "Recherche des autres appareils…", info, devices)

    targets = scan_targets(info)
    total = max(len(targets), 1)
    done = 0
    with ThreadPoolExecutor(max_workers=128) as pool:
        futures = [pool.submit(probe, ip) for ip in targets]
        for future in as_completed(futures):
            future.result()
            done += 1
            if done % 40 == 0 or done == total:
                progress(8 + int(done / total * 80), f"Scan du réseau… {done}/{total}", info, devices)

    time.sleep(1.0)
    arp = parse_arp(info["iface"])
    devices = build_devices(info, arp, resolve_names=True)
    online = sum(1 for d in devices if d["status"] == "en ligne")
    unknown = sum(1 for d in devices if not d["known"])
    message = f"{len(devices)} appareil(s), {online} en ligne, {unknown} inconnu(s)"
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
