#!/usr/bin/env python3
"""Wi-Fi Accès — logiciel Linux pour voir qui est sur ton Wi-Fi."""

from __future__ import annotations

import os
import threading
import webbrowser
from pathlib import Path

import gi

gi.require_version("Gdk", "3.0")
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
button.danger {
  background: #d45b4a;
  color: #fff8f6;
  font-weight: 700;
  border-radius: 999px;
  padding: 10px 16px;
  border: 0;
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


def copy_text(text: str) -> None:
    clipboard = Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD)
    clipboard.set_text(text, -1)
    clipboard.store()


def wrapped_label(text: str, css: str = "hint") -> Gtk.Label:
    label = Gtk.Label(label=text)
    label.set_line_wrap(True)
    label.set_xalign(0)
    label.get_style_context().add_class(css)
    return label


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
                part
                for part in (
                    device.get("kind"),
                    device.get("brand") or device.get("vendor"),
                    device.get("system"),
                    device["status"],
                    extra,
                    device["ip"],
                    device["mac"],
                )
                if part
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
        else:
            kind_tag = Gtk.Label(label=(device.get("kind") or "Appareil").upper())
            kind_tag.get_style_context().add_class("tag")
            right.pack_start(kind_tag, False, False, 0)
            if not device.get("known"):
                tag = Gtk.Label(label="INCONNU")
                tag.get_style_context().add_class("tag")
                tag.get_style_context().add_class("tag-warn")
                right.pack_start(tag, False, False, 0)
            actions = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
            name_btn = Gtk.Button(label="Nommer")
            name_btn.connect("clicked", self.on_rename)
            block_btn = Gtk.Button(label="Bloquer")
            block_btn.get_style_context().add_class("danger")
            block_btn.connect("clicked", self.on_block)
            actions.pack_start(name_btn, False, False, 0)
            actions.pack_start(block_btn, False, False, 0)
            right.pack_start(actions, False, False, 0)

        box.pack_start(dot, False, False, 0)
        box.pack_start(text, True, True, 0)
        box.pack_start(right, False, False, 0)
        self.add(box)

    def on_rename(self, _button) -> None:
        window = self.get_toplevel()
        if isinstance(window, AppWindow):
            window.rename_device(self.device)

    def on_block(self, _button) -> None:
        window = self.get_toplevel()
        if isinstance(window, AppWindow):
            window.block_device(self.device)


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
        header.set_subtitle("Voir, nommer et bloquer les appareils")
        self.set_titlebar(header)

        self.refresh_btn = Gtk.Button(label="Actualiser")
        self.refresh_btn.get_style_context().add_class("flat-ghost")
        self.refresh_btn.connect("clicked", lambda *_: self.refresh_snapshot())
        header.pack_start(self.refresh_btn)

        self.kick_btn = Gtk.Button(label="Virer tout le monde")
        self.kick_btn.get_style_context().add_class("danger")
        self.kick_btn.set_tooltip_text("Change le mot de passe Wi-Fi dans la box : les voisins sont coupés")
        self.kick_btn.connect("clicked", lambda *_: self.kick_everyone())
        header.pack_end(self.kick_btn)

        self.box_btn = Gtk.Button(label="Ouvrir la box")
        self.box_btn.get_style_context().add_class("flat-ghost")
        self.box_btn.set_tooltip_text("Ouvre la page de ta box")
        self.box_btn.connect("clicked", self.open_router)
        header.pack_end(self.box_btn)

        self.scan_btn = Gtk.Button(label="Scanner le Wi-Fi")
        self.scan_btn.get_style_context().add_class("suggested-action")
        self.scan_btn.connect("clicked", lambda *_: self.start_scan(False))
        header.pack_end(self.scan_btn)

        self.deep_btn = Gtk.Button(label="Scan profond")
        self.deep_btn.get_style_context().add_class("flat-ghost")
        self.deep_btn.set_tooltip_text("Demande le mot de passe Linux pour voir encore plus d’appareils")
        self.deep_btn.connect("clicked", lambda *_: self.start_scan(True))
        header.pack_end(self.deep_btn)

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

        hint = wrapped_label(
            "Bloquer un appareil ouvre la box avec son adresse MAC. "
            "Pour couper tous les voisins d’un coup : Virer tout le monde, puis change le mot de passe Wi-Fi."
        )
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
            self.start_scan(False)
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
        self.deep_btn.set_sensitive(not self.scanning)
        self.refresh_btn.set_sensitive(not self.scanning)
        has_box = bool(self.info.get("gateway"))
        self.box_btn.set_sensitive(has_box)
        self.kick_btn.set_sensitive(has_box)

        count = len(self.devices)
        self.warn.set_text(
            f"Ce PC voit {count} appareil(s) qui répondent. "
            "S’il y en a 300, le reste est dans la box ou ne répond pas. "
            "Clique Scan profond (mot de passe Linux) ou Ouvrir la box → appareils connectés."
        )

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

    def start_scan(self, deep: bool = False) -> None:
        if self.scanning:
            return
        self.scanning = True
        self.scan_btn.set_sensitive(False)
        self.deep_btn.set_sensitive(False)
        self.refresh_btn.set_sensitive(False)
        self.message.set_text("Scan profond en cours…" if deep else "Scan en cours…")

        def worker() -> None:
            scanner.scan_network(lambda data: GLib.idle_add(self.apply_state, data), deep=deep)

        threading.Thread(target=worker, daemon=True).start()

    def open_router(self, _button=None) -> None:
        gateway = self.info.get("gateway")
        if not gateway:
            self.info = scanner.wifi_info()
            gateway = self.info.get("gateway")
        if gateway:
            webbrowser.open(f"http://{gateway}")

    def block_device(self, device: dict) -> None:
        mac = device.get("mac", "")
        copy_text(mac)
        title = device.get("name") or device.get("hostname") or "Appareil inconnu"
        dialog = Gtk.Dialog(title="Bloquer cet appareil", transient_for=self, modal=True)
        dialog.add_buttons("Fermer", Gtk.ResponseType.CLOSE)
        box = dialog.get_content_area()
        box.set_spacing(8)
        for margin in ("top", "bottom", "start", "end"):
            getattr(box, f"set_margin_{margin}")(14)
        box.pack_start(wrapped_label(f"{title}\n{device.get('vendor', '')}  ·  {mac}", "name"), False, False, 0)
        box.pack_start(
            wrapped_label(
                "L’adresse MAC est copiée. Un ordinateur ne peut pas virer un téléphone tout seul : "
                "c’est la box qui décide. Colle cette adresse dans la box, ou change le mot de passe."
            ),
            False,
            False,
            0,
        )
        box.pack_start(
            wrapped_label(
                "1. Clique Ouvrir la box\n"
                "2. Connecte-toi (identifiants sur l’étiquette de la box)\n"
                "3. Cherche Appareils connectés, Filtrage MAC ou Liste noire\n"
                "4. Colle l’adresse MAC et bloque l’appareil\n"
                "5. Pour tout le monde d’un coup : Virer tout le monde"
            ),
            False,
            False,
            0,
        )
        actions = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        copy_btn = Gtk.Button(label="Copier l’adresse MAC")
        copy_btn.connect("clicked", lambda *_: copy_text(mac))
        open_btn = Gtk.Button(label="Ouvrir la box")
        open_btn.get_style_context().add_class("suggested-action")
        open_btn.connect("clicked", self.open_router)
        actions.pack_start(copy_btn, False, False, 0)
        actions.pack_start(open_btn, False, False, 0)
        box.pack_start(actions, False, False, 8)
        dialog.show_all()
        dialog.run()
        dialog.destroy()

    def kick_everyone(self, _button=None) -> None:
        dialog = Gtk.Dialog(title="Virer tout le monde", transient_for=self, modal=True)
        dialog.add_buttons("Fermer", Gtk.ResponseType.CLOSE)
        box = dialog.get_content_area()
        box.set_spacing(8)
        for margin in ("top", "bottom", "start", "end"):
            getattr(box, f"set_margin_{margin}")(14)
        box.pack_start(
            wrapped_label(
                "C’est la seule méthode qui marche vraiment. "
                "Dès que tu changes le mot de passe Wi-Fi, les voisins sont coupés. "
                "Donne le nouveau code seulement à la famille."
            ),
            False,
            False,
            0,
        )
        box.pack_start(
            wrapped_label(
                "1. Clique Ouvrir la box (ça s’ouvre dans le navigateur)\n"
                "2. Connecte-toi. Identifiant et mot de passe sont souvent sur une étiquette sous la box\n"
                "3. Cherche Wi-Fi, WLAN ou Sans fil\n"
                "4. Change le mot de passe Wi-Fi\n"
                "5. Enregistre, puis reconnecte tes appareils avec le nouveau code"
            ),
            False,
            False,
            0,
        )
        open_btn = Gtk.Button(label="Ouvrir la box maintenant")
        open_btn.get_style_context().add_class("suggested-action")
        open_btn.connect("clicked", self.open_router)
        box.pack_start(open_btn, False, False, 8)
        dialog.show_all()
        dialog.run()
        dialog.destroy()

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
