#!/usr/bin/env python3
"""Wi-Fi Accès — logiciel Linux pour voir qui est sur ton Wi-Fi."""

from __future__ import annotations

import os
import threading
import webbrowser
from pathlib import Path

import gi

gi.require_version("Gtk", "3.0")
from gi.repository import Gdk, GLib, Gtk, Pango

import scanner

ROOT = Path(__file__).resolve().parent
CSS = """
window, box, viewport, list {
  background-color: #10131a;
  color: #eef3fb;
  font-family: "Segoe UI", "Noto Sans", sans-serif;
}
headerbar {
  background-color: #181d27;
  color: #eef3fb;
  padding: 8px;
}
.ssid { color: #5ee0c0; font-weight: 700; }
.muted { color: #9aa8bd; }
.card {
  background-color: #181d27;
  border-radius: 14px;
  padding: 14px;
}
.stat-value { font-size: 22px; font-weight: 800; }
.row-card {
  background-color: #181d27;
  border-radius: 14px;
  padding: 12px 14px;
  margin: 4px 2px;
}
.name { font-weight: 700; font-size: 15px; }
.meta { color: #9aa8bd; font-size: 12px; }
button.suggested-action {
  background: #5ee0c0;
  color: #08241d;
  font-weight: 700;
  border-radius: 999px;
  padding: 10px 16px;
  border: 0;
}
button.flat-ghost {
  background: #1f2633;
  color: #eef3fb;
  border-radius: 999px;
  padding: 10px 16px;
}
.tag {
  background-color: #223046;
  color: #7aa7ff;
  border-radius: 999px;
  padding: 3px 8px;
  font-size: 11px;
  font-weight: 700;
}
.tag-warn {
  background-color: #3a2a12;
  color: #f0c14b;
}
.hint {
  color: #9aa8bd;
  font-size: 13px;
}
"""


def load_css() -> None:
    provider = Gtk.CssProvider()
    provider.load_from_data(CSS.encode("utf-8"))
    Gtk.StyleContext.add_provider_for_screen(
        Gdk.Screen.get_default(),
        provider,
        Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION,
    )


def ellipsize(label: Gtk.Label) -> None:
    label.set_ellipsize(Pango.EllipsizeMode.END)
    label.set_xalign(0)


class DeviceRow(Gtk.ListBoxRow):
    def __init__(self, device: dict):
        super().__init__()
        self.device = device
        self.set_selectable(True)

        box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        box.get_style_context().add_class("row-card")
        box.set_margin_start(4)
        box.set_margin_end(4)

        if device["status"] == "en ligne":
            color = "#3ddc97"
        elif device["status"] == "vu récemment":
            color = "#f0c14b"
        else:
            color = "#667788"
        dot = Gtk.Label()
        dot.set_markup(f'<span foreground="{color}" size="large">●</span>')

        text = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        text.set_hexpand(True)
        title = Gtk.Label(label=device.get("name") or device.get("hostname") or "Appareil inconnu")
        title.get_style_context().add_class("name")
        ellipsize(title)
        extra = device.get("hostname") if device.get("name") and device.get("hostname") else ""
        meta = Gtk.Label(
            label=" · ".join(
                part for part in (device["status"], extra, device["vendor"], device["ip"], device["mac"]) if part
            )
        )
        meta.get_style_context().add_class("meta")
        ellipsize(meta)
        text.pack_start(title, False, False, 0)
        text.pack_start(meta, False, False, 0)

        right = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        right.set_valign(Gtk.Align.CENTER)
        if device["role"] == "toi":
            tag = Gtk.Label(label="TOI")
            tag.get_style_context().add_class("tag")
            right.pack_start(tag, False, False, 0)
        elif device["role"] == "box":
            tag = Gtk.Label(label="BOX")
            tag.get_style_context().add_class("tag")
            right.pack_start(tag, False, False, 0)
        elif not device.get("known"):
            tag = Gtk.Label(label="INCONNU")
            tag.get_style_context().add_class("tag")
            tag.get_style_context().add_class("tag-warn")
            right.pack_start(tag, False, False, 0)
            btn = Gtk.Button(label="Nommer")
            btn.connect("clicked", self.on_rename)
            right.pack_start(btn, False, False, 0)
        else:
            btn = Gtk.Button(label="Renommer")
            btn.connect("clicked", self.on_rename)
            right.pack_start(btn, False, False, 0)

        box.pack_start(dot, False, False, 0)
        box.pack_start(text, True, True, 0)
        box.pack_start(right, False, False, 0)
        self.add(box)

    def on_rename(self, _button) -> None:
        window = self.get_toplevel()
        if isinstance(window, AppWindow):
            window.rename_device(self.device)


class AppWindow(Gtk.ApplicationWindow):
    def __init__(self, app: Gtk.Application):
        super().__init__(application=app, title="Wi-Fi Accès")
        self.set_default_size(860, 640)
        icon = ROOT / "assets" / "wifi-acces.png"
        if icon.exists():
            self.set_icon_from_file(str(icon))
        self.scanning = False
        self.info: dict = {}
        self.devices: list[dict] = []

        header = Gtk.HeaderBar()
        header.set_show_close_button(True)
        header.set_title("Wi-Fi Accès")
        header.set_subtitle("Qui est connecté à ton Wi-Fi")
        self.set_titlebar(header)

        self.refresh_btn = Gtk.Button(label="Actualiser")
        self.refresh_btn.get_style_context().add_class("flat-ghost")
        self.refresh_btn.connect("clicked", lambda *_: self.refresh_snapshot())
        header.pack_start(self.refresh_btn)

        self.box_btn = Gtk.Button(label="Ouvrir la box")
        self.box_btn.get_style_context().add_class("flat-ghost")
        self.box_btn.set_tooltip_text("Ouvre la page de ta box pour changer le mot de passe Wi-Fi")
        self.box_btn.connect("clicked", self.open_router)
        header.pack_end(self.box_btn)

        self.scan_btn = Gtk.Button(label="Scanner le Wi-Fi")
        self.scan_btn.get_style_context().add_class("suggested-action")
        self.scan_btn.connect("clicked", lambda *_: self.start_scan())
        header.pack_end(self.scan_btn)

        root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
        root.set_margin_top(16)
        root.set_margin_bottom(16)
        root.set_margin_start(18)
        root.set_margin_end(18)

        self.ssid = Gtk.Label(label="Réseau : …")
        self.ssid.get_style_context().add_class("ssid")
        self.ssid.set_xalign(0)
        root.pack_start(self.ssid, False, False, 0)

        stats = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        self.stat_total = self._stat_card("Appareils", "0")
        self.stat_online = self._stat_card("En ligne", "0")
        self.stat_unknown = self._stat_card("Inconnus", "0")
        self.stat_ip = self._stat_card("Toi", "…")
        for card in (self.stat_total, self.stat_online, self.stat_unknown, self.stat_ip):
            stats.pack_start(card, True, True, 0)
        root.pack_start(stats, False, False, 0)

        self.warn = Gtk.Label()
        self.warn.set_line_wrap(True)
        self.warn.set_xalign(0)
        self.warn.get_style_context().add_class("hint")
        root.pack_start(self.warn, False, False, 0)

        self.bar = Gtk.ProgressBar()
        self.bar.set_fraction(0)
        root.pack_start(self.bar, False, False, 0)

        self.message = Gtk.Label(label="Clique sur Scanner le Wi-Fi pour voir qui est connecté.")
        self.message.get_style_context().add_class("muted")
        self.message.set_xalign(0)
        root.pack_start(self.message, False, False, 0)

        scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        self.listbox = Gtk.ListBox()
        self.listbox.set_selection_mode(Gtk.SelectionMode.NONE)
        scroll.add(self.listbox)
        root.pack_start(scroll, True, True, 0)

        hint = Gtk.Label(
            label="Pour vraiment régler le problème : ouvre la box, change le mot de passe Wi-Fi, "
            "et donne-le seulement aux personnes que tu veux."
        )
        hint.set_line_wrap(True)
        hint.set_xalign(0)
        hint.get_style_context().add_class("hint")
        root.pack_start(hint, False, False, 0)

        self.add(root)
        self.connect("key-press-event", self.on_key)
        self.refresh_snapshot()

    def _stat_card(self, title: str, value: str) -> Gtk.Box:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        box.get_style_context().add_class("card")
        label = Gtk.Label(label=title)
        label.get_style_context().add_class("muted")
        label.set_xalign(0)
        val = Gtk.Label(label=value)
        val.get_style_context().add_class("stat-value")
        val.set_xalign(0)
        val.set_name(title)
        box.pack_start(label, False, False, 0)
        box.pack_start(val, False, False, 0)
        box.value_label = val  # type: ignore[attr-defined]
        return box

    def on_key(self, _widget, event) -> bool:
        if event.keyval in (Gdk.KEY_F5,):
            self.start_scan()
            return True
        return False

    def set_stat(self, card: Gtk.Box, value: str) -> None:
        card.value_label.set_text(value)  # type: ignore[attr-defined]

    def refresh_snapshot(self) -> None:
        if self.scanning:
            return
        info = scanner.wifi_info()
        devices = scanner.build_devices(info, scanner.parse_arp(info.get("iface", "")), resolve_names=False)
        self.apply_state(
            {
                "scanning": False,
                "progress": 0,
                "message": "Clique sur Scanner le Wi-Fi pour voir qui est connecté.",
                "info": info,
                "devices": devices,
            }
        )

    def apply_state(self, data: dict) -> None:
        self.scanning = bool(data.get("scanning"))
        self.info = data.get("info") or {}
        self.devices = data.get("devices") or []
        ssid = self.info.get("ssid") or "Wi-Fi"
        self.ssid.set_text(f"Réseau : {ssid}")
        online = sum(1 for d in self.devices if d["status"] == "en ligne")
        unknown = sum(1 for d in self.devices if not d.get("known"))
        self.set_stat(self.stat_total, str(len(self.devices)))
        self.set_stat(self.stat_online, str(online))
        self.set_stat(self.stat_unknown, str(unknown))
        self.set_stat(self.stat_ip, self.info.get("ip") or "…")
        self.message.set_text(data.get("message") or "")
        self.bar.set_fraction((data.get("progress") or 0) / 100)
        self.scan_btn.set_sensitive(not self.scanning)
        self.refresh_btn.set_sensitive(not self.scanning)
        self.box_btn.set_sensitive(bool(self.info.get("gateway")))

        if self.info.get("shared"):
            self.warn.set_text(
                "Ce Wi-Fi ressemble à un réseau partagé (opérateur / immeuble). "
                "Tu peux voir des appareils qui ne sont pas chez toi. "
                "Le scan se limite à ton voisinage immédiat."
            )
        else:
            self.warn.set_text("")

        for child in list(self.listbox.get_children()):
            self.listbox.remove(child)
        if not self.devices:
            empty = Gtk.Label(label="Aucun appareil pour l’instant. Lance un scan.")
            empty.get_style_context().add_class("muted")
            empty.set_margin_top(18)
            self.listbox.add(empty)
        else:
            for device in self.devices:
                self.listbox.add(DeviceRow(device))
        self.listbox.show_all()

    def start_scan(self) -> None:
        if self.scanning:
            return
        self.scanning = True
        self.scan_btn.set_sensitive(False)
        self.refresh_btn.set_sensitive(False)
        self.message.set_text("Scan en cours…")

        def worker() -> None:
            scanner.scan_network(lambda data: GLib.idle_add(self.apply_state, data))

        threading.Thread(target=worker, daemon=True).start()

    def open_router(self, _button=None) -> None:
        gateway = self.info.get("gateway")
        if not gateway:
            self.info = scanner.wifi_info()
            gateway = self.info.get("gateway")
        if gateway:
            webbrowser.open(f"http://{gateway}")

    def rename_device(self, device: dict) -> None:
        dialog = Gtk.Dialog(title="Nommer l’appareil", transient_for=self, modal=True)
        dialog.add_buttons("Annuler", Gtk.ResponseType.CANCEL, "Enregistrer", Gtk.ResponseType.OK)
        dialog.set_default_response(Gtk.ResponseType.OK)
        box = dialog.get_content_area()
        box.set_margin_top(12)
        box.set_margin_bottom(12)
        box.set_margin_start(12)
        box.set_margin_end(12)
        label = Gtk.Label(label=f"{device['vendor']}  ·  {device['mac']}")
        label.get_style_context().add_class("muted")
        entry = Gtk.Entry()
        entry.set_text(device.get("name") or "")
        entry.set_placeholder_text("ex. téléphone du cousin")
        entry.set_activates_default(True)
        box.pack_start(label, False, False, 6)
        box.pack_start(entry, False, False, 6)
        dialog.show_all()
        response = dialog.run()
        if response == Gtk.ResponseType.OK:
            scanner.save_name(device["mac"], entry.get_text())
            self.refresh_snapshot()
        dialog.destroy()


class WifiAcces(Gtk.Application):
    def __init__(self):
        super().__init__(application_id="com.ricardokoukoui.wifiacces")

    def do_activate(self) -> None:
        load_css()
        scanner.vendors = scanner.load_vendors()
        win = AppWindow(self)
        win.show_all()
        win.present()


def main() -> None:
    os.chdir(ROOT)
    WifiAcces().run()


if __name__ == "__main__":
    main()
