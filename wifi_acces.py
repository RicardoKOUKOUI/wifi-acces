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
CSS = b"""
window {
  background-color: #0a1018;
  color: #eef3fb;
}
headerbar {
  background-image: none;
  background-color: #101822;
  color: #eef3fb;
  border-bottom: 1px solid #243044;
  min-height: 54px;
  padding: 6px 10px;
}
headerbar label { color: #eef3fb; }
box.hero {
  background-color: #121b28;
  border: 1px solid #2a3c55;
  border-radius: 22px;
  padding: 20px 22px;
}
label.total-label { color: #8fa6c0; }
label.ssid { color: #d7e6ff; }
label.muted { color: #8fa3bb; }
box.card {
  background-color: #151e2c;
  border: 1px solid #2a3c55;
  border-radius: 18px;
  padding: 14px 16px;
}
label.stat-label { color: #8fa3bb; }
button {
  min-height: 34px;
  padding: 8px 14px;
  border-radius: 999px;
}
button.suggested-action {
  background-image: none;
  background-color: #5ee0c0;
  color: #06241c;
  font-weight: 800;
  border: 0;
}
button.flat-ghost {
  background-image: none;
  background-color: #1b2636;
  color: #eef3fb;
  border: 1px solid #334863;
}
button.danger {
  background-image: none;
  background-color: #d45b4a;
  color: #fff8f6;
  font-weight: 800;
  border: 0;
}
label.hint { color: #8fa3bb; }
scrolledwindow {
  background-color: #101822;
  border: 1px solid #2a3c55;
  border-radius: 16px;
}
treeview {
  background-color: #101822;
  color: #e8eef8;
}
treeview.view {
  background-color: #101822;
  color: #e8eef8;
}
treeview.view:selected {
  background-color: #1b3d38;
  color: #ffffff;
}
treeview header button {
  background-image: none;
  background-color: #151e2c;
  color: #9cb0c9;
  border: 0;
  border-radius: 0;
  min-height: 36px;
}
progressbar trough {
  background-color: #1b2636;
  border-radius: 999px;
  min-height: 10px;
}
progressbar progress {
  background-image: none;
  background-color: #5ee0c0;
  border-radius: 999px;
}
"""


def load_css() -> None:
    provider = Gtk.CssProvider()
    provider.load_from_data(CSS)
    Gtk.StyleContext.add_provider_for_screen(
        Gdk.Screen.get_default(),
        provider,
        Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION,
    )


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


def current_arp(info: dict) -> dict[str, dict]:
    arp = scanner.parse_arp(info.get("iface", ""))
    scanner.merge_history(arp)
    return arp


class AppWindow(Gtk.ApplicationWindow):
    def __init__(self, app: Gtk.Application):
        super().__init__(application=app, title="Wi-Fi Accès")
        self.set_default_size(1100, 740)
        icon = ROOT / "assets" / "wifi-acces.png"
        if icon.exists():
            self.set_icon_from_file(str(icon))
        self.scanning = False
        self.info: dict = {}
        self.devices: list[dict] = []
        self.selected: dict | None = None

        header = Gtk.HeaderBar()
        header.set_show_close_button(False)
        header.set_title("Wi-Fi Accès")
        header.set_subtitle("Tous les appareils, y compris les inconnus")
        self.set_titlebar(header)

        self.refresh_btn = Gtk.Button(label="Actualiser")
        self.refresh_btn.get_style_context().add_class("flat-ghost")
        self.refresh_btn.connect("clicked", lambda *_: self.refresh_snapshot())
        header.pack_start(self.refresh_btn)

        self.kick_btn = Gtk.Button(label="Virer tout le monde")
        self.kick_btn.get_style_context().add_class("danger")
        self.kick_btn.connect("clicked", lambda *_: self.kick_everyone())
        header.pack_end(self.kick_btn)

        self.box_btn = Gtk.Button(label="Ouvrir la box")
        self.box_btn.get_style_context().add_class("flat-ghost")
        self.box_btn.connect("clicked", self.open_router)
        header.pack_end(self.box_btn)

        self.scan_btn = Gtk.Button(label="Scanner le Wi-Fi")
        self.scan_btn.get_style_context().add_class("suggested-action")
        self.scan_btn.connect("clicked", lambda *_: self.start_scan(False))
        header.pack_end(self.scan_btn)

        self.deep_btn = Gtk.Button(label="Scan profond")
        self.deep_btn.get_style_context().add_class("flat-ghost")
        self.deep_btn.connect("clicked", lambda *_: self.start_scan(True))
        header.pack_end(self.deep_btn)

        root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
        root.set_margin_top(16)
        root.set_margin_bottom(16)
        root.set_margin_start(18)
        root.set_margin_end(18)

        hero = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=18)
        hero.get_style_context().add_class("hero")
        total_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        total_caption = Gtk.Label(label="TOTAL APPAREILS")
        total_caption.get_style_context().add_class("total-label")
        total_caption.set_xalign(0)
        self.total_value = Gtk.Label()
        self.total_value.set_markup('<span size="42000" weight="ultrabold" foreground="#5ee0c0">0</span>')
        self.total_value.set_xalign(0)
        self.total_value.set_use_markup(True)
        total_box.pack_start(total_caption, False, False, 0)
        total_box.pack_start(self.total_value, False, False, 0)
        right_hero = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        self.ssid = Gtk.Label()
        self.ssid.set_markup('<span size="15000" weight="bold" foreground="#d7e6ff">Réseau : …</span>')
        self.ssid.set_xalign(0)
        self.ssid.set_use_markup(True)
        self.breakdown = Gtk.Label(label="Inconnus, téléphones, PC, box : 0")
        self.breakdown.get_style_context().add_class("muted")
        self.breakdown.set_xalign(0)
        self.breakdown.set_line_wrap(True)
        right_hero.pack_start(self.ssid, False, False, 0)
        right_hero.pack_start(self.breakdown, False, False, 0)
        hero.pack_start(total_box, False, False, 0)
        hero.pack_start(right_hero, True, True, 0)
        root.pack_start(hero, False, False, 0)

        stats = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        self.stat_unknown = self._stat_card("Inconnus", "0", "stat-unknown", "#f0c14b")
        self.stat_online = self._stat_card("En ligne", "0", "stat-online", "#3ddc97")
        self.stat_phones = self._stat_card("Téléphones", "0")
        self.stat_pc = self._stat_card("PC", "0")
        for card in (self.stat_unknown, self.stat_online, self.stat_phones, self.stat_pc):
            stats.pack_start(card, True, True, 0)
        root.pack_start(stats, False, False, 0)

        self.bar = Gtk.ProgressBar()
        self.bar.set_show_text(True)
        self.bar.set_text("En attente")
        root.pack_start(self.bar, False, False, 0)

        scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        scroll.set_min_content_height(380)
        self.store = Gtk.ListStore(int, str, str, str, str, str, str, str, str)
        self.tree = Gtk.TreeView(model=self.store)
        self.tree.set_headers_visible(True)
        self.tree.set_enable_search(True)
        self.tree.set_search_column(2)
        columns = [
            (0, "#", 50),
            (1, "État", 110),
            (2, "Nom", 220),
            (3, "Type", 120),
            (4, "Marque", 160),
            (5, "IP", 140),
            (6, "MAC", 160),
            (7, "Système", 160),
        ]
        for index, title, width in columns:
            renderer = Gtk.CellRendererText()
            if index == 2:
                renderer.set_property("weight", Pango.Weight.BOLD)
            column = Gtk.TreeViewColumn(title, renderer, text=index)
            column.set_min_width(width)
            column.set_resizable(True)
            column.set_sort_column_id(index)
            self.tree.append_column(column)
        self.tree.get_selection().connect("changed", self.on_select)
        scroll.add(self.tree)
        root.pack_start(scroll, True, True, 0)

        actions = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        self.selected_label = Gtk.Label(label="Sélectionne un appareil dans la liste.")
        self.selected_label.get_style_context().add_class("muted")
        self.selected_label.set_xalign(0)
        self.selected_label.set_hexpand(True)
        self.rename_btn = Gtk.Button(label="Nommer")
        self.rename_btn.get_style_context().add_class("flat-ghost")
        self.rename_btn.connect("clicked", self.on_rename_clicked)
        self.block_btn = Gtk.Button(label="Bloquer")
        self.block_btn.get_style_context().add_class("danger")
        self.block_btn.connect("clicked", self.on_block_clicked)
        actions.pack_start(self.selected_label, True, True, 0)
        actions.pack_start(self.rename_btn, False, False, 0)
        actions.pack_start(self.block_btn, False, False, 0)
        root.pack_start(actions, False, False, 0)

        hint = wrapped_label(
            "Toute la liste est affichée, inconnus compris, avec le numéro et le total. "
            "Pour couper les voisins : Virer tout le monde, puis change le mot de passe dans la box."
        )
        root.pack_start(hint, False, False, 0)

        self.add(root)
        self.connect("key-press-event", self.on_key)
        self.refresh_snapshot()

    def _stat_card(self, title: str, value: str, extra: str = "", color: str = "#f4f7fb") -> Gtk.Box:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        box.get_style_context().add_class("card")
        if extra:
            box.get_style_context().add_class(extra)
        label = Gtk.Label(label=title.upper())
        label.get_style_context().add_class("stat-label")
        label.set_xalign(0)
        val = Gtk.Label()
        val.set_use_markup(True)
        val.set_xalign(0)
        val.stat_color = color  # type: ignore[attr-defined]
        val.set_markup(
            f'<span size="22000" weight="ultrabold" foreground="{color}">{value}</span>'
        )
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
        label = card.value_label  # type: ignore[attr-defined]
        color = getattr(label, "stat_color", "#f4f7fb")
        label.set_markup(f'<span size="22000" weight="ultrabold" foreground="{color}">{value}</span>')

    def refresh_snapshot(self) -> None:
        if self.scanning:
            return
        info = scanner.wifi_info()
        devices = scanner.build_devices(info, current_arp(info), resolve_names=False)
        self.apply_state(
            {
                "scanning": False,
                "progress": 0,
                "message": "Prêt — clique Scanner le Wi-Fi pour tout lister.",
                "info": info,
                "devices": devices,
            }
        )

    def apply_state(self, data: dict) -> None:
        self.scanning = bool(data.get("scanning"))
        self.info = data.get("info") or {}
        self.devices = list(data.get("devices") or [])
        ssid = self.info.get("ssid") or "Wi-Fi"
        total = len(self.devices)
        online = sum(1 for d in self.devices if d["status"] == "en ligne")
        unknown = sum(1 for d in self.devices if not d.get("known"))
        phones = sum(1 for d in self.devices if "éléphone" in (d.get("kind") or ""))
        pcs = sum(1 for d in self.devices if (d.get("kind") or "") == "PC")
        self.total_value.set_markup(
            f'<span size="42000" weight="ultrabold" foreground="#5ee0c0">{total}</span>'
        )
        self.ssid.set_markup(
            f'<span size="15000" weight="bold" foreground="#d7e6ff">Réseau : {GLib.markup_escape_text(ssid)}</span>'
        )
        self.breakdown.set_text(
            f"{unknown} inconnus  ·  {online} en ligne  ·  {phones} téléphones  ·  {pcs} PC  ·  {total} au total"
        )
        self.set_stat(self.stat_unknown, str(unknown))
        self.set_stat(self.stat_online, str(online))
        self.set_stat(self.stat_phones, str(phones))
        self.set_stat(self.stat_pc, str(pcs))
        message = data.get("message") or ""
        progress = data.get("progress") or 0
        self.bar.set_fraction(progress / 100)
        self.bar.set_text(message or f"{total} appareils dans la liste")
        self.scan_btn.set_sensitive(not self.scanning)
        self.deep_btn.set_sensitive(not self.scanning)
        self.refresh_btn.set_sensitive(not self.scanning)
        has_box = bool(self.info.get("gateway"))
        self.box_btn.set_sensitive(has_box)
        self.kick_btn.set_sensitive(has_box)
        self.fill_table()

    def fill_table(self) -> None:
        self.store.clear()
        for index, device in enumerate(self.devices, start=1):
            name = device.get("name") or device.get("hostname") or "Appareil inconnu"
            if not device.get("known"):
                name = f"Inconnu · {name}"
            self.store.append(
                [
                    index,
                    device.get("status") or "",
                    name,
                    device.get("kind") or "Appareil",
                    device.get("brand") or device.get("vendor") or "",
                    device.get("ip") or "",
                    device.get("mac") or "",
                    device.get("system") or "",
                    device.get("role") or "",
                ]
            )
        if len(self.devices) > 0:
            self.tree.scroll_to_cell(Gtk.TreePath.new_first())

    def on_select(self, selection) -> None:
        model, tree_iter = selection.get_selected()
        if not tree_iter:
            self.selected = None
            self.selected_label.set_text("Sélectionne un appareil dans la liste.")
            return
        index = int(model[tree_iter][0]) - 1
        if 0 <= index < len(self.devices):
            self.selected = self.devices[index]
            d = self.selected
            label = d.get("name") or d.get("hostname") or "Appareil inconnu"
            self.selected_label.set_text(
                f"#{index + 1}  {label}  ·  {d.get('kind', '')}  ·  {d.get('ip', '')}  ·  {d.get('mac', '')}"
            )

    def on_rename_clicked(self, _button) -> None:
        if self.selected:
            self.rename_device(self.selected)

    def on_block_clicked(self, _button) -> None:
        if self.selected:
            self.block_device(self.selected)

    def start_scan(self, deep: bool = False) -> None:
        if self.scanning:
            return
        self.scanning = True
        self.scan_btn.set_sensitive(False)
        self.deep_btn.set_sensitive(False)
        self.refresh_btn.set_sensitive(False)
        self.bar.set_text("Scan profond en cours…" if deep else "Scan en cours…")

        def worker() -> None:
            scanner.scan_network(lambda data: GLib.idle_add(self.apply_state, data), deep=deep)

        threading.Thread(target=worker, daemon=True).start()

    def open_router(self, _button=None) -> None:
        gateway = self.info.get("gateway")
        if not gateway:
            self.info = scanner.wifi_info()
            gateway = self.info.get("gateway")
        if gateway:
            webbrowser.open(f"https://{gateway}")

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
        box.pack_start(wrapped_label(f"{title}\n{device.get('vendor', '')}  ·  {mac}", "ssid"), False, False, 0)
        box.pack_start(
            wrapped_label(
                "L’adresse MAC est copiée. Colle-la dans la box (liste noire / filtrage MAC), "
                "ou change le mot de passe Wi-Fi."
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
                "Change le mot de passe Wi-Fi dans la box. "
                "Les voisins sont coupés. Donne le nouveau code seulement à la famille."
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
        label = Gtk.Label(label=f"{device.get('vendor', '')}  ·  {device.get('mac', '')}")
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
