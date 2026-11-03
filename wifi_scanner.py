#!/usr/bin/env python3
"""Radar Wi-Fi — version navigateur."""

from __future__ import annotations

import json
import os
import re
import sys
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

import scanner

HOST = "127.0.0.1"
PORT = 8765

lock = threading.Lock()
state = {
    "scanning": False,
    "progress": 0,
    "message": "Prêt",
    "devices": [],
    "info": {},
}


def scan_network() -> None:
    def on_progress(data: dict) -> None:
        with lock:
            state["scanning"] = True
            state["progress"] = data.get("progress", 0)
            state["message"] = data.get("message", "")
            state["devices"] = list(data.get("devices") or [])
            state["info"] = dict(data.get("info") or {})

    result = scanner.scan_network(on_progress)
    with lock:
        state["scanning"] = False
        state["progress"] = result.get("progress", 100)
        state["message"] = result.get("message", "")
        state["devices"] = list(result.get("devices") or [])
        state["info"] = dict(result.get("info") or {})


PAGE = r"""<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Radar Wi-Fi</title>
  <style>
    :root {
      --bg: #10131a;
      --panel: #181d27;
      --panel-2: #1f2633;
      --line: #2b3444;
      --text: #eef3fb;
      --muted: #9aa8bd;
      --accent: #5ee0c0;
      --accent-2: #7aa7ff;
      --online: #3ddc97;
      --stale: #f0c14b;
      --shadow: 0 18px 50px rgba(0, 0, 0, .35);
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      font-family: "Segoe UI", "Avenir Next", sans-serif;
      color: var(--text);
      background:
        radial-gradient(1000px 500px at 10% -10%, #1b3b3a 0%, transparent 50%),
        radial-gradient(800px 400px at 100% 0%, #1a2744 0%, transparent 46%),
        var(--bg);
    }
    .wrap { max-width: 1080px; margin: 0 auto; padding: 28px 20px 60px; }
    header {
      display: flex; justify-content: space-between; gap: 16px;
      align-items: flex-start; flex-wrap: wrap; margin-bottom: 22px;
    }
    h1 { margin: 0; font-size: 28px; letter-spacing: -.03em; }
    .sub { color: var(--muted); margin-top: 6px; }
    .ssid { color: var(--accent); font-weight: 700; }
    .actions { display: flex; gap: 10px; flex-wrap: wrap; }
    button {
      border: 0; border-radius: 999px; padding: 12px 18px; cursor: pointer;
      font-weight: 700; color: #08241d; background: var(--accent);
    }
    button:disabled { opacity: .55; cursor: wait; }
    .ghost {
      background: transparent; color: var(--text);
      border: 1px solid var(--line);
    }
    .grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; }
    .card {
      background: var(--panel); border: 1px solid var(--line);
      border-radius: 18px; padding: 16px; box-shadow: var(--shadow);
    }
    .label { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .08em; }
    .value { margin-top: 6px; font-size: 18px; font-weight: 700; }
    .bar {
      margin: 18px 0; height: 8px; background: var(--panel-2);
      border-radius: 99px; overflow: hidden;
    }
    .bar > div {
      height: 100%; width: 0; background: linear-gradient(90deg, var(--accent), var(--accent-2));
      transition: width .25s ease;
    }
    .status-line { color: var(--muted); margin: 8px 0 16px; min-height: 1.2em; }
    .list { display: flex; flex-direction: column; gap: 10px; }
    .row {
      display: grid; grid-template-columns: 22px 1.4fr .9fr 1.1fr .9fr auto;
      gap: 10px; align-items: center; background: var(--panel);
      border: 1px solid var(--line); border-radius: 16px; padding: 14px 16px;
    }
    .dot { width: 10px; height: 10px; border-radius: 50%; background: #667; }
    .dot.online { background: var(--online); box-shadow: 0 0 10px var(--online); }
    .dot.stale { background: var(--stale); }
    .name { font-weight: 700; }
    .meta, .ip, .mac, .vendor { color: var(--muted); font-size: 13px; }
    .mac { font-family: ui-monospace, monospace; }
    .tag {
      justify-self: end; font-size: 11px; font-weight: 700;
      padding: 4px 8px; border-radius: 999px; background: #223;
      color: var(--accent-2);
    }
    .rename {
      justify-self: end; background: var(--panel-2); color: var(--text);
      border: 1px solid var(--line); padding: 8px 12px;
    }
    .hint { margin-top: 18px; color: var(--muted); line-height: 1.5; }
    @media (max-width: 900px) {
      .grid { grid-template-columns: 1fr 1fr; }
      .row { grid-template-columns: 22px 1fr auto; }
      .ip, .mac, .vendor { display: none; }
    }
  </style>
</head>
<body>
  <div class="wrap">
    <header>
      <div>
        <h1>Radar Wi-Fi</h1>
        <div class="sub">Réseau : <span class="ssid" id="ssid">…</span></div>
      </div>
      <div class="actions">
        <button class="ghost" onclick="loadData()">Actualiser</button>
        <button id="scanBtn" onclick="startScan()">Scanner le Wi-Fi</button>
      </div>
    </header>

    <div class="grid">
      <div class="card"><div class="label">Appareils</div><div class="value" id="count">0</div></div>
      <div class="card"><div class="label">Toi</div><div class="value" id="me">…</div></div>
      <div class="card"><div class="label">Box / routeur</div><div class="value" id="gw">…</div></div>
      <div class="card"><div class="label">Réseau</div><div class="value" id="net">…</div></div>
    </div>

    <div class="bar"><div id="bar"></div></div>
    <div class="status-line" id="message">Chargement…</div>
    <div class="list" id="list"></div>
    <p class="hint">
      Clique <b>Scanner le Wi-Fi</b> pour voir qui est connecté.
      Tu peux donner un nom à un appareil (ex. « téléphone du cousin »).
      Si le Wi-Fi est partagé (immeuble, opérateur), tu peux aussi voir des appareils qui ne sont pas chez toi.
    </p>
  </div>
  <script>
    let timer = null;
    const $ = (id) => document.getElementById(id);

    function esc(value) {
      return String(value || "").replace(/[&<>"'`]/g, (c) => ({
        "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;", "`": "&#96;"
      }[c]));
    }
    function badge(role) {
      if (role === "toi") return "TOI";
      if (role === "box") return "BOX";
      return "";
    }

    function render(data) {
      const info = data.info || {};
      const devices = data.devices || [];
      $("ssid").textContent = info.ssid || "Wi-Fi";
      $("count").textContent = devices.length;
      $("me").textContent = info.ip || "…";
      $("gw").textContent = info.gateway || "…";
      $("net").textContent = info.network || "…";
      $("message").textContent = data.message || "";
      $("bar").style.width = (data.progress || 0) + "%";
      $("scanBtn").disabled = !!data.scanning;

      $("list").innerHTML = devices.map(d => {
        const title = esc(d.name || d.hostname || "Appareil inconnu");
        const klass = d.status === "en ligne" ? "online" : (d.status === "vu récemment" ? "stale" : "");
        const tag = badge(d.role);
        const extra = d.hostname && d.name ? " · " + esc(d.hostname) : "";
        return `<div class="row">
          <div class="dot ${klass}"></div>
          <div>
            <div class="name">${title}</div>
            <div class="meta">${esc([d.kind, d.brand || d.vendor, d.system, d.status].filter(Boolean).join(" · "))}${extra}</div>
          </div>
          <div class="ip">${esc(d.ip)}</div>
          <div class="mac">${esc(d.mac)}</div>
          <div class="vendor">${esc(d.kind || "")} · ${esc(d.brand || d.vendor)}</div>
          ${tag ? `<div class="tag">${tag}</div>` : `<button class="rename" onclick="renameMac('${esc(d.mac)}')">Nommer</button>`}
        </div>`;
      }).join("") || `<div class="card">Aucun appareil pour l’instant. Lance un scan.</div>`;
    }

    async function loadData() {
      const res = await fetch("/api/state");
      render(await res.json());
    }

    async function startScan() {
      $("scanBtn").disabled = true;
      await fetch("/api/scan", { method: "POST" });
      poll();
    }

    async function renameMac(mac) {
      const name = prompt("Nom de cet appareil (ex: téléphone du cousin) :");
      if (name === null) return;
      await fetch("/api/rename", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ mac, name })
      });
      loadData();
    }

    function poll() {
      if (timer) clearInterval(timer);
      timer = setInterval(async () => {
        const res = await fetch("/api/state");
        const data = await res.json();
        render(data);
        if (!data.scanning) clearInterval(timer);
      }, 600);
    }

    loadData();
  </script>
</body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args) -> None:
        return

    def _json(self, payload: dict, code: int = 200) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _html(self) -> None:
        body = PAGE.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path in {"/", "/index.html"}:
            self._html()
            return
        if path == "/api/state":
            with lock:
                snapshot = {
                    "scanning": state["scanning"],
                    "progress": state["progress"],
                    "message": state["message"],
                    "devices": list(state["devices"]),
                    "info": dict(state["info"]),
                }
            self._json(snapshot)
            return
        self._json({"error": "not found"}, 404)

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        length = int(self.headers.get("Content-Length", "0") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            payload = json.loads(raw.decode("utf-8") or "{}")
        except json.JSONDecodeError:
            payload = {}

        if path == "/api/scan":
            with lock:
                already = state["scanning"]
            if not already:
                threading.Thread(target=scan_network, daemon=True).start()
            self._json({"ok": True})
            return

        if path == "/api/rename":
            mac = str(payload.get("mac", "")).lower()
            name = str(payload.get("name", ""))
            if re.fullmatch(r"[0-9a-f]{2}(:[0-9a-f]{2}){5}", mac):
                scanner.save_name(mac, name)
                with lock:
                    info = state["info"] or scanner.wifi_info()
                    arp = scanner.parse_arp(info.get("iface", ""))
                    state["devices"] = scanner.build_devices(info, arp, resolve_names=False)
                self._json({"ok": True})
                return
            self._json({"ok": False}, 400)
            return

        self._json({"error": "not found"}, 404)


def main() -> None:
    scanner.vendors = scanner.load_vendors()
    info = scanner.wifi_info()
    with lock:
        state["info"] = info
        state["devices"] = scanner.build_devices(info, scanner.parse_arp(info.get("iface", "")), resolve_names=False)
        state["message"] = "Clique sur Scanner le Wi-Fi pour voir tout le monde."

    httpd = None
    port = PORT
    for candidate in range(PORT, PORT + 10):
        try:
            httpd = ThreadingHTTPServer((HOST, candidate), Handler)
            port = candidate
            break
        except OSError:
            continue
    if httpd is None:
        print("Impossible d'ouvrir l'application (ports occupés).")
        sys.exit(1)

    url = f"http://{HOST}:{port}"
    print(f"Radar Wi-Fi est prêt : {url}", flush=True)
    print("Laisse cette fenêtre ouverte, et ouvre le lien dans ton navigateur.", flush=True)
    threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nApplication fermée.")
        httpd.server_close()


if __name__ == "__main__":
    os.chdir(Path(__file__).resolve().parent)
    main()
