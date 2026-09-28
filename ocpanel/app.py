"""ocpanel - a terminal panel for driving an OpenConnect client and deciding
which traffic uses the tunnel.

Presentation lives in ui.py. This module holds the state, the routing decisions
and the actions the keys are bound to.
"""
from __future__ import annotations

import ipaddress
import sys
import time
from dataclasses import dataclass, field

from rich.markup import escape
from rich.text import Text
from textual import work
from textual.app import App, ComposeResult, SystemCommand
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import DataTable, Footer, RichLog, Static, TabbedContent, TabPane

from . import keychain as kc, netinfo, rules as R, sdr, services, ui, vpn
from .config import (CONFIG_FILE, DEFAULT_THEME, MODE_DIRECT, MODE_VPN, Config,
                     invoking_home, load_state, save_state)
from .ui import (ConfirmScreen, ConnectScreen, FilterInput, HelpScreen, InfoPanel,
                 Palette, PickerScreen, QuitScreen, RuleScreen, StatusBar, TrafficPanel)


def human_bytes(n: float) -> str:
    for unit in ("B", "K", "M", "G", "T"):
        if abs(n) < 1024 or unit == "T":
            return f"{n:.0f}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}T"


def human_secs(s: float) -> str:
    s = int(s)
    if s <= 0:
        return "-"
    h, rem = divmod(s, 3600)
    m, sec = divmod(rem, 60)
    return f"{h:d}:{m:02d}:{sec:02d}" if h else f"{m:d}:{sec:02d}"


@dataclass
class Snapshot:
    """Everything the panel shows, collected off the UI thread."""
    tunnel: netinfo.Link | None = None
    physical: netinfo.Link | None = None
    tunnel_addr: str = ""
    session: netinfo.Session | None = None
    dns: list[str] = field(default_factory=list)
    rx_tun: int = 0
    tx_tun: int = 0
    rx_phy: int = 0
    tx_phy: int = 0
    taken: float = 0.0
    verified: dict[str, str] = field(default_factory=dict)   # rule target -> iface
    halves: dict[str, netinfo.Link] = field(default_factory=dict)  # 0/1, 128/1 routes


# log_line() styles -> (glyph, palette role)
LOG_STYLES = {
    "green": ("✓", "ok"), "red": ("✗", "bad"),
    "yellow": ("!", "warn"), "bold yellow": ("!", "warn"),
    "cyan": ("›", "vpn"), "bold cyan": ("›", "vpn"),
    "magenta": ("›", "direct"), "bold magenta": ("›", "direct"),
    "bold": ("▸", "fg"), "dim": ("·", "muted"), "": ("·", "fg"),
}

# Actions that act on the highlighted rule; greyed out when there is none.
NEEDS_RULE = {"edit_rule", "toggle_rule", "delete_rule", "transfer_rule"}

# Our own key actions. Textual's built-ins (Tab to the next field, Ctrl+P ...)
# are not in here and keep working inside dialogs.
OWN_ACTIONS = {k.action.split("(")[0] for _, group in ui.KEYMAP for k in group} - {"quit"}


class OCPanel(App):
    CSS_PATH = "app.tcss"
    TITLE = "ocpanel"
    BINDINGS = ui.bindings()

    LISTS = ("bypass", "vpn")

    def __init__(self) -> None:
        super().__init__()
        self.cfg = Config.load()
        self.snap = Snapshot()
        self.pal = Palette()
        self._prev: Snapshot | None = None
        self._rates = (0.0, 0.0, 0.0, 0.0)
        self._pending_note: dict[str, str] = {}
        self._startup_applied = False
        self._link_key: tuple[str | None, str | None] | None = None
        # Which list is on screen. Independent of the mode: you can edit either
        # list at any time, the mode only decides which one is applied.
        self.view = "vpn" if self.cfg.mode == MODE_DIRECT else "bypass"
        self._tab_labels: dict[str, str] = {}
        self._filter = ""
        self._sig: dict[str, tuple] = {}            # last drawn rows, per list
        self._undo: tuple[str, int, R.Rule] | None = None
        self._built = False                         # set once the screen is fully built
        self._connecting = False                    # a connect attempt is running
        self._quitting = False

    # ---------------------------------------------------------------- layout

    def compose(self) -> ComposeResult:
        yield StatusBar(id="status")
        yield Static(id="banner")
        with Horizontal(id="panels"):
            yield InfoPanel("Connection", id="conn", classes="panel")
            yield InfoPanel("Routing", id="route", classes="panel")
            yield TrafficPanel(id="traffic", classes="panel")
        with Vertical(id="rules-wrap"):
            with TabbedContent(id="lists", initial=f"tab-{self.view}"):
                for view in self.LISTS:
                    with TabPane(self.list_name(view), id=f"tab-{view}"):
                        yield DataTable(id=f"rules-{view}", cursor_type="row",
                                        zebra_stripes=True)
                        yield Static(id=f"empty-{view}", classes="empty")
            yield FilterInput(placeholder="filter by target, note or type  ·  "
                              "Enter: back to list  ·  Esc: clear", id="filter")
        yield RichLog(id="activity", markup=False, wrap=True, max_lines=1000)
        yield Footer()

    def on_mount(self) -> None:
        for view in self.LISTS:
            self.query_one(f"#rules-{view}", DataTable).add_columns(
                " ", "Target", "Type", "Addresses", "Route", "Note")
        self.theme = self.cfg.theme if self.cfg.theme in self.available_themes else DEFAULT_THEME
        self.pal = Palette.from_variables(self.get_css_variables())
        self.query_one("#activity", RichLog).border_title = "Activity"
        self.query_one("#filter", FilterInput).display = False
        if not R.is_root():
            banner = self.query_one("#banner", Static)
            banner.update(" Read-only: changing routes needs root. Quit and run "
                          " sudo ~/.local/bin/ocpanel ")
            banner.add_class("visible")
        shown = str(CONFIG_FILE).replace(str(invoking_home()), "~")
        self.log_line(f"config {shown}  ·  press ? for every key", "dim")
        self.update_mode_ui()
        self.refresh_rules()
        self.render_status()
        self.query_one(f"#rules-{self.view}", DataTable).focus()
        self._built = True
        self.poll()
        self.set_interval(2.0, self.poll)
        self.set_interval(1.0, self.render_status)

    def watch_theme(self, theme: str) -> None:
        """Rich text is coloured from the theme, so redraw it all on a change."""
        self.pal = Palette.from_variables(self.get_css_variables())
        self._sig.clear()
        if self._built:
            self.render_status()
            self.render_panels()
            self.refresh_rules()
        if self.cfg.theme != theme:              # remember the choice
            self.cfg.theme = theme
            self.cfg.save()

    # ---------------------------------------------------- keys and commands

    def check_action(self, action: str, parameters: tuple[object, ...]) -> bool | None:
        # A dialog owns the keyboard: our keys must not fire behind it.
        if isinstance(self.screen, ModalScreen) and action in OWN_ACTIONS:
            return False
        if not self._built:
            return True
        if action in NEEDS_RULE:
            return True if self.selected_rule() is not None else None
        if action == "undo":
            return True if self._undo else None
        if action in ("connect", "connect_in_terminal"):
            return True if self.snap.session is None and not self._connecting else None
        if action == "disconnect":
            return True if self.snap.session is not None else None
        if action == "reconnect":
            return None if self._connecting else True
        if action == "forget_password":
            return True if self.cfg.profile.save_password else None
        return True

    def get_system_commands(self, screen):
        """Every action is also in the Ctrl+P palette, searchable by name."""
        yield from super().get_system_commands(screen)
        for group, keys in ui.KEYMAP:
            for k in keys:
                if k.action.startswith("cursor") or k.action == "quit":
                    continue
                yield SystemCommand(
                    k.description, f"{group}  ·  key {ui.pretty_keys(k.keys)}",
                    lambda a=k.action: self.call_later(self.run_action, a))

    # ------------------------------------------------------------ activity

    def log_line(self, msg: str, style: str = "") -> None:
        glyph, role = LOG_STYLES.get(style, ("·", "fg"))
        color = getattr(self.pal, role)
        line = Text(time.strftime("%H:%M:%S") + "  ", style=self.pal.muted)
        line.append(f"{glyph} ", style=f"bold {color}")
        line.append_text(Text.from_markup(
            msg, style=f"{'bold ' if style.startswith('bold') else ''}{color}"))
        self.query_one("#activity", RichLog).write(line)

    # ------------------------------------------------------------- polling

    @work(exclusive=True, thread=True, group="poll")
    def poll(self) -> None:
        snap = Snapshot(taken=time.monotonic())
        snap.tunnel = netinfo.tunnel_link()
        snap.physical = netinfo.physical_link()
        if snap.tunnel:
            snap.tunnel_addr = netinfo.iface_addr(snap.tunnel.iface)
            snap.rx_tun, snap.tx_tun = netinfo.iface_bytes(snap.tunnel.iface)
        if snap.physical:
            snap.rx_phy, snap.tx_phy = netinfo.iface_bytes(snap.physical.iface)
        sessions = netinfo.openconnect_sessions()
        snap.session = sessions[0] if sessions else None
        snap.dns = netinfo.dns_servers()
        snap.halves = netinfo.half_default_routes()
        unused = self.cfg.rules if self.direct_mode else self.cfg.vpn_rules
        for rule in unused:
            if rule.kind != "host":             # cheap, no DNS - just to show addresses
                rule.networks()
        for rule in self.cfg.active_rules:
            nets = rule.networks()
            snap.verified[rule.target] = netinfo.route_iface(
                str(nets[0].network_address)) if nets else ""
        self.call_from_thread(self.apply_snapshot, snap)

    def apply_snapshot(self, snap: Snapshot) -> None:
        if self._prev is not None:
            dt = max(snap.taken - self._prev.taken, 0.001)
            self._rates = (
                max(snap.rx_tun - self._prev.rx_tun, 0) / dt,
                max(snap.tx_tun - self._prev.tx_tun, 0) / dt,
                max(snap.rx_phy - self._prev.rx_phy, 0) / dt,
                max(snap.tx_phy - self._prev.tx_phy, 0) / dt,
            )
        self._prev, self.snap = snap, snap
        key = (snap.tunnel.iface if snap.tunnel else None,
               snap.physical.gateway if snap.physical else None)
        links_changed = self._link_key is not None and key != self._link_key
        self._link_key = key
        self.render_status()
        self.render_panels()
        self.refresh_rules()
        if not R.is_root() or snap.physical is None:
            return
        # Routes point at a specific gateway and tunnel. macOS does not repoint
        # them when either changes, so we have to - in direct mode a stale
        # gateway would take down every connection, not just the listed ones.
        if self.direct_mode:
            wanted = snap.tunnel is not None
        else:
            wanted = any(r.enabled for r in self.cfg.rules)
        if not self._startup_applied:
            # Wait for a real snapshot, or we would not know the gateway yet.
            self._startup_applied = True
            if wanted:
                self.log_line("restoring saved routes", "bold")
                self.action_apply()
        elif links_changed and wanted:
            self.log_line("network changed - re-pointing routes", "bold")
            self.action_apply()

    # ------------------------------------------------------------- drawing

    def direct_routes_state(self) -> str:
        """'ok', or what is wrong with the half-default routes for this mode."""
        ours = [l for l in self.snap.halves.values() if not netinfo.is_tunnel(l.iface)]
        if self.direct_mode:
            return "ok" if len(ours) == 2 else "not applied"
        return "ok" if not ours else "stale"

    def render_status(self) -> None:
        s, p = self.snap, self.pal
        left = Text()
        left.append(" ◆ ocpanel ", style=f"bold {p.bg} on {p.info}")
        left.append(" ")
        if self.direct_mode:
            left.append(" DIRECT BY DEFAULT ", style=f"bold {p.bg} on {p.direct}")
        else:
            left.append(" VPN BY DEFAULT ", style=f"bold {p.bg} on {p.vpn}")
        left.append("   ")
        if self._connecting:
            left.append("◐ connecting…", style=f"bold {p.warn}")
        elif s.session is not None and s.tunnel is not None:
            left.append("● connected", style=f"bold {p.ok}")
        elif s.session is not None:
            left.append("◐ connecting", style=f"bold {p.warn}")
        else:
            left.append("○ disconnected", style=f"bold {p.bad}")
        server = (s.session.server if s.session else "") or self.cfg.profile.server
        if server:
            left.append(f"   {server}", style=p.fg)
        if s.session and s.session.started:
            left.append(f"   up {human_secs(time.time() - s.session.started)}", style=p.muted)
        state = self.direct_routes_state()
        if state != "ok" and self._prev is not None:
            left.append(f"   ! direct routes {state} - press p", style=f"bold {p.warn}")
        right = Text()
        if R.is_root():
            right.append(" root ", style=f"{p.muted}")
        else:
            right.append(" READ-ONLY ", style=f"bold {p.bg} on {p.warn}")
        right.append(f"  {time.strftime('%H:%M:%S')} ", style=p.fg)
        self.query_one("#status", StatusBar).show(left, right)

    def render_panels(self) -> None:
        s, p = self.snap, self.pal
        online = s.session is not None and s.tunnel is not None
        if online:
            state = Text("● Connected", style=f"bold {p.ok}")
        elif s.session is not None:
            state = Text("◐ Connecting", style=f"bold {p.warn}")
        else:
            state = Text("○ Disconnected", style=f"bold {p.bad}")
        conn = self.query_one("#conn", InfoPanel)
        conn.set_class(online, "online")
        conn.set_class(not online, "offline")
        conn.set_rows([
            ("Status", state),
            ("Server", (s.session.server if s.session else "") or self.cfg.profile.server or "-"),
            ("User", (s.session.user if s.session else "") or self.cfg.profile.user or "-"),
            ("Tunnel", f"{s.tunnel.iface} · {s.tunnel_addr}" if s.tunnel else "-"),
            ("Uptime", human_secs(time.time() - s.session.started)
             if s.session and s.session.started else "-"),
            ("PID", str(s.session.pid) if s.session else "-"),
            ("Password", "from auth_command" if self.cfg.profile.auth_command else
             (Text("saved in keychain", style=p.ok) if self.cfg.profile.save_password
              else "asked each time")),
        ], p)

        rules = self.cfg.active_rules
        on = sum(1 for r in rules if r.enabled)
        state = self.direct_routes_state()
        if self.direct_mode:
            mode = Text("Direct by default", style=f"bold {p.direct}")
        else:
            mode = Text("VPN by default", style=f"bold {p.vpn}")
        if state != "ok":
            mode.append(f"  ({state})", style=p.warn)
        self.query_one("#route", InfoPanel).set_rows([
            ("Mode", mode),
            ("Gateway", f"{s.physical.gateway} · {s.physical.iface}" if s.physical
             else Text("no network", style=p.bad)),
            ("DNS", ", ".join(s.dns[:2]) or "-"),
            ("In use", f"{self.list_name('vpn' if self.direct_mode else 'bypass')} "
                       f"· {on} of {len(rules)} on"),
            ("Access", "root" if R.is_root() else Text("read-only", style=p.warn)),
        ], p)

        rx_t, tx_t, rx_p, tx_p = self._rates
        traffic = self.query_one("#traffic", TrafficPanel)
        for key, name, rx, tx, total, color in (
                ("tun", "Tunnel", rx_t, tx_t, (s.rx_tun, s.tx_tun), p.vpn),
                ("dir", "Direct", rx_p, tx_p, (s.rx_phy, s.tx_phy), p.direct)):
            label = Text(f"{name:<8}", style=f"bold {p.fg}")
            label.append(f"↓ {human_bytes(rx)}/s  ↑ {human_bytes(tx)}/s", style=color)
            label.append(f"   {human_bytes(total[0])} / {human_bytes(total[1])}", style=p.muted)
            traffic.push(key, rx + tx, label)

    # ----------------------------------------------------------------- lists

    def rules_for(self, view: str) -> list[R.Rule]:
        return self.cfg.vpn_rules if view == "vpn" else self.cfg.rules

    def list_in_use(self, view: str) -> bool:
        """Only one list is ever applied: the one the current mode uses."""
        return (view == "vpn") == self.direct_mode

    @staticmethod
    def list_name(view: str) -> str:
        return "VPN list" if view == "vpn" else "bypass list"

    @property
    def viewed_rules(self) -> list[R.Rule]:
        return self.rules_for(self.view)

    def rule_cells(self, rule: R.Rule, in_use: bool, phy: str) -> tuple[tuple[str, str], ...]:
        """One table row as (text, style) pairs - cheap to compare between polls."""
        p = self.pal
        status = ("●", f"bold {p.ok}") if rule.enabled else ("○", p.muted)
        target = (rule.target, p.fg if rule.enabled else p.muted)
        if rule.error:
            addrs = (rule.error, p.bad)
        elif rule.kind == "service":
            addrs = (f"{len(rule.addresses)} published ranges", p.fg)
        elif not rule.addresses:
            addrs = ("resolved when used" if rule.kind == "host" else "-", p.muted)
        else:
            shown = ", ".join(rule.addresses[:3])
            if len(rule.addresses) > 3:
                shown += f"  +{len(rule.addresses) - 3}"
            addrs = (shown, p.fg)
        route = self.route_cell(rule, phy) if in_use else ("ignored in this mode", p.muted)
        return (status, target, (rule.kind, p.muted), addrs, route, (rule.note, p.muted))

    def route_cell(self, rule: R.Rule, phy: str) -> tuple[str, str]:
        """Where the kernel really sends this rule - ok colour when that is what the mode wants."""
        p = self.pal
        iface = self.snap.verified.get(rule.target, "")
        if not iface:
            return ("checking…", p.muted)
        tunnelled = netinfo.is_tunnel(iface)
        if tunnelled:
            label, wanted = f"▸ vpn · {iface}", self.direct_mode
        elif iface == phy:
            label, wanted = f"▸ direct · {iface}", not self.direct_mode
        else:
            label, wanted = f"▸ {iface}", None
        if not rule.enabled:
            return (label, p.muted)
        if wanted is None:
            return (label, p.warn)
        return (label, p.ok if wanted else f"bold {p.bad}")

    def refresh_rules(self, force: bool = False) -> None:
        phy = self.snap.physical.iface if self.snap.physical else ""
        needle = self._filter.lower()
        for view in self.LISTS:
            table = self.query_one(f"#rules-{view}", DataTable)
            rules = self.rules_for(view)
            in_use = self.list_in_use(view)
            rows = [(str(i), self.rule_cells(rule, in_use, phy))
                    for i, rule in enumerate(rules)
                    if not needle or needle in f"{rule.target} {rule.note} {rule.kind}".lower()]
            sig = tuple(rows)
            if force or self._sig.get(view) != sig:
                # Keep the highlight on the same rule, not the same row number.
                current = (table.ordered_rows[table.cursor_row].key.value
                           if table.row_count else None)
                cursor = table.cursor_row
                table.clear()
                for key, cells in rows:
                    table.add_row(*(Text(t, style=st) for t, st in cells), key=key)
                keys = [k for k, _ in rows]
                if rows:
                    row = keys.index(current) if current in keys else min(cursor, len(rows) - 1)
                    table.move_cursor(row=row)
                self._sig[view] = sig
            empty = self.query_one(f"#empty-{view}", Static)
            table.display = bool(rows)
            empty.display = not rows
            if not rows:
                empty.update(self.empty_text(view, bool(rules)))
        self.update_list_labels()
        self.refresh_bindings()

    def empty_text(self, view: str, has_rules: bool) -> Text:
        p = self.pal
        out = Text()
        if has_rules:
            out.append(f"Nothing matches “{self._filter}”\n\n", style=f"bold {p.fg}")
            out.append_text(ui.key_hints([("Esc", "clear the filter (from the filter box)"),
                                          ("/", "change it")], p))
            return out
        if view == "vpn":
            out.append("The VPN list is empty\n", style=f"bold {p.fg}")
            out.append("In direct mode this is the only traffic that uses the VPN.\n\n",
                       style=p.muted)
            out.append_text(ui.key_hints([("a", "add a site"),
                                          ("s", "add a whole service like YouTube")], p))
        else:
            out.append("The bypass list is empty\n", style=f"bold {p.fg}")
            out.append("In VPN mode this traffic skips the VPN.\n\n", style=p.muted)
            out.append_text(ui.key_hints([("a", "add a site"), ("g", "Dota 2 relays"),
                                          ("f", "find a running game")], p))
        return out

    def update_list_labels(self) -> None:
        tabs = self.query_one("#lists", TabbedContent)
        for n, view in enumerate(self.LISTS, 1):
            state = "● in use" if self.list_in_use(view) else "○ ignored"
            name = "VPN list" if view == "vpn" else "Bypass list"
            label = f"{n}  {name}  {len(self.rules_for(view))}  {state}"
            if self._tab_labels.get(view) != label:     # relabelling redraws the tab
                tabs.get_tab(f"tab-{view}").label = label
                self._tab_labels[view] = label
        wrap = self.query_one("#rules-wrap")
        if self._filter:
            shown = sum(len(self._sig.get(v, ())) for v in self.LISTS)
            wrap.border_subtitle = f"filter “{self._filter}” · {shown} shown"
        else:
            wrap.border_subtitle = "Enter edit · Space on/off · / filter · ? keys"

    def show_list(self, view: str) -> None:
        self.view = view
        tabs = self.query_one("#lists", TabbedContent)
        if tabs.active != f"tab-{view}":
            tabs.active = f"tab-{view}"
        self.query_one(f"#rules-{view}", DataTable).focus()
        self.refresh_bindings()

    def on_tabbed_content_tab_activated(self, event: TabbedContent.TabActivated) -> None:
        # Clicking a tab with the mouse lands here as well as the keys.
        self.view = "vpn" if event.tabbed_content.active == "tab-vpn" else "bypass"
        self.refresh_bindings()

    def on_data_table_row_highlighted(self) -> None:
        self.refresh_bindings()                    # footer greys out rule keys

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.data_table.id == f"rules-{self.view}":
            self.action_edit_rule()

    def selected_rule(self) -> R.Rule | None:
        table = self.query_one(f"#rules-{self.view}", DataTable)
        if not table.row_count or not table.display:
            return None
        key = table.ordered_rows[table.cursor_row].key.value
        rules = self.viewed_rules
        try:
            return rules[int(key)]
        except (ValueError, IndexError, TypeError):
            return None

    def saved_not_applied(self, view: str) -> None:
        mode = "direct" if view == "vpn" else "VPN"
        self.log_line(f"saved to the {self.list_name(view)} - it is only applied in "
                      f"{mode} mode (press m to switch)", "dim")

    # ------------------------------------------------ list and cursor keys

    def action_show_list(self, view: str) -> None:
        self.show_list(view)

    def action_switch_list(self) -> None:
        self.show_list("vpn" if self.view == "bypass" else "bypass")

    def action_cursor(self, delta: int) -> None:
        table = self.query_one(f"#rules-{self.view}", DataTable)
        if table.row_count:
            table.move_cursor(row=max(0, min(table.cursor_row + delta, table.row_count - 1)))
        table.focus()

    def action_filter(self) -> None:
        box = self.query_one("#filter", FilterInput)
        box.display = True
        box.focus()

    def action_clear_filter(self) -> None:
        box = self.query_one("#filter", FilterInput)
        box.value = ""
        box.display = False
        self._filter = ""
        self.refresh_rules(force=True)
        self.query_one(f"#rules-{self.view}", DataTable).focus()

    def on_input_changed(self, event: FilterInput.Changed) -> None:
        if event.input.id == "filter":
            self._filter = event.value.strip()
            self.refresh_rules(force=True)

    def on_input_submitted(self, event: FilterInput.Submitted) -> None:
        if event.input.id == "filter":
            if not event.value.strip():
                event.input.display = False
            self.query_one(f"#rules-{self.view}", DataTable).focus()

    def action_help(self) -> None:
        self.push_screen(HelpScreen())

    # ------------------------------------------------------------- actions

    def require_root(self) -> bool:
        if R.is_root():
            return True
        self.notify("Changing routes needs root. Quit and run: sudo ~/.local/bin/ocpanel",
                    severity="warning", title="Read-only")
        return False

    def add_targets(self, targets: list[str] | None) -> None:
        """Game helpers (f, g) always fill the bypass list."""
        self.add_targets_to("bypass", targets)

    def add_targets_to(self, view: str, targets: list[str] | None) -> None:
        """Add several rules to one list at once, skipping ones already on it."""
        if not targets:
            return
        rules = self.rules_for(view)
        in_use = self.list_in_use(view)
        added = 0
        for target in targets:
            if any(r.target == target for r in rules):
                continue
            rule = R.Rule(target=target, note=self._pending_note.get(target, ""))
            rule.networks()
            if rule.error:
                self.log_line(f"{escape(target)}: {escape(rule.error)}", "red")
                continue
            rules.append(rule)
            added += 1
            if in_use and R.is_root():
                self.apply_rule(rule)
        self.cfg.save()
        self._pending_note = {}
        self.log_line(f"added {added} rule(s) to the {self.list_name(view)}",
                      "green" if added else "yellow")
        if added and not in_use:
            self.saved_not_applied(view)
        self.show_list(view)
        self.refresh_rules()

    def action_add_service(self) -> None:
        self.log_line("loading published service ranges", "dim")
        self._add_service(self.view)

    @work(exclusive=True, thread=True, group="discover")
    def _add_service(self, view: str) -> None:
        """Offer whole services by their published ranges, for the list on screen."""
        choices, notes = [], {}
        for key, svc in services.SERVICES.items():
            age = services.cache_age(key)
            fresh = age is not None and age < services.MAX_AGE
            ranges = services.cached(key) if fresh else services.fetch(key)
            target = f"{R.SERVICE_PREFIX}{key}"
            if ranges:
                choices.append((f"{svc.name:<20} {len(ranges)} ranges   ({svc.source})",
                                target, False))
            else:
                choices.append((f"{svc.name:<20} could not download - check your connection",
                                target, False))
            notes[target] = svc.name
        self._pending_note = notes
        self.call_from_thread(self.push_screen, PickerScreen(
            f"Add a service to the {self.list_name(view)}",
            "Big services use hundreds of addresses, and DNS gives out different ones "
            "every time - so a hostname rule only ever catches a few of them. These "
            "use the ranges the operator publishes, which cover the whole service.",
            choices),
            lambda picked: self.add_targets_to(view, picked))

    def action_find_live(self) -> None:
        self.log_line("scanning live game connections", "dim")
        self._find_live()

    @work(exclusive=True, thread=True, group="discover")
    def _find_live(self) -> None:
        """Look at what the game is actually talking to right now."""
        peers = netinfo.live_peers()
        if not peers:
            self.call_from_thread(
                self.notify, "No live game connections found. Launch Dota 2 first.",
                severity="warning", title="Nothing to find")
            return
        data = sdr.load_cache() or sdr.fetch()
        choices, notes = [], {}
        for peer in peers:
            pop = sdr.lookup(peer.remote, data)
            # Relay IPs move around inside a cluster, so take the whole /24.
            target = f"{peer.remote}/24" if pop else peer.remote
            where = f"  [{pop.label}]" if pop else ""
            choices.append((f"{peer.remote}:{peer.port}  {peer.process}{where}",
                            target, True))
            notes[target] = pop.desc if pop else peer.process
        self._pending_note = notes
        self.call_from_thread(self.push_screen, PickerScreen(
            "Live game connections",
            "These are the addresses your game processes are connected to right "
            "now. Ticked entries will be added to the bypass list.", choices),
            self.add_targets)

    def action_add_relays(self) -> None:
        self.log_line("fetching Valve relay directory", "dim")
        self._add_relays()

    @work(exclusive=True, thread=True, group="discover")
    def _add_relays(self) -> None:
        """Offer Valve's published Dota 2 relay clusters."""
        data = sdr.fetch()
        pops = sdr.pops(data)
        if not pops:
            self.call_from_thread(
                self.notify,
                "Could not reach Valve's relay directory and no cache exists.",
                severity="error")
            return
        live = {p.remote for p in netinfo.live_peers()}
        choices, notes = [], {}
        for pop in pops:
            # Pre-tick whichever cluster the game is using at the moment.
            using = any(sdr.lookup(ip, data) and sdr.lookup(ip, data).code == pop.code
                        for ip in live)
            for net in pop.networks:
                mark = "   (in use now)" if using else ""
                choices.append((f"{str(net):<19} {pop.desc}{mark}", str(net), using))
                notes[str(net)] = f"dota2 relay {pop.code}"
        self._pending_note = notes
        age = sdr.cache_age()
        fresh = "just fetched" if age is not None and age < 60 else "from cache"
        self.call_from_thread(self.push_screen, PickerScreen(
            f"Dota 2 relay clusters ({fresh})",
            "Valve routes Dota 2 through whichever relay cluster is nearest, so "
            "there is no single game IP. Tick the clusters you actually use - the "
            "one in use right now is pre-selected.", choices),
            self.add_targets)

    def action_add_rule(self) -> None:
        view = self.view                     # the list on screen when 'a' was pressed
        rules = self.rules_for(view)
        name = self.list_name(view)

        def added(result: tuple[str, str] | None) -> None:
            if not result:
                return
            target, note = result
            if any(r.target == target for r in rules):
                self.notify(f"{target} is already on the {name}.", severity="warning")
                return
            rule = R.Rule(target=target, note=note)
            nets = rule.networks()
            if rule.error:
                self.notify(f"{target}: {rule.error}", severity="error", title="Not added")
                return
            rules.append(rule)
            self.cfg.save()
            self.log_line(f"added [b]{escape(target)}[/b] to the {name} -> "
                          f"{', '.join(str(n) for n in nets[:3])}"
                          f"{f' +{len(nets) - 3}' if len(nets) > 3 else ''}", "green")
            owner = next((services.owner(str(n.network_address)) for n in nets
                          if rule.kind == "host" and services.owner(str(n.network_address))), None)
            if owner:
                svc = services.SERVICES[owner].name
                self.log_line(f"{escape(target)} is part of {svc} - one address will not "
                              f"cover it. Press s and add {svc} instead.", "bold yellow")
                self.notify(f"{target} only covers {len(nets)} of {svc}'s addresses. "
                            "Press s to add the whole service.", severity="warning",
                            title="Probably not enough", timeout=10)
            if not self.list_in_use(view):
                self.saved_not_applied(view)
            elif R.is_root():
                self.apply_rule(rule)
            self.refresh_rules()
            self.move_to_rule(view, rule)

        if view == "vpn":
            screen = RuleScreen(
                "Add to the VPN list",
                "In direct mode this is the only traffic that uses the VPN; in VPN mode "
                "the list is ignored. For big services like YouTube press s instead - a "
                "hostname only catches a few of its addresses.")
        else:
            screen = RuleScreen(
                "Add to the bypass list",
                "In VPN mode this traffic leaves over your real connection instead of "
                "the VPN; in direct mode the list is ignored.")
        self.push_screen(screen, added)

    def move_to_rule(self, view: str, rule: R.Rule) -> None:
        """Put the highlight on a rule, e.g. one just added or restored."""
        rules = self.rules_for(view)
        if rule not in rules:
            return
        key = str(rules.index(rule))
        table = self.query_one(f"#rules-{view}", DataTable)
        for row, r in enumerate(table.ordered_rows):
            if r.key.value == key:
                table.move_cursor(row=row)
                break

    def action_edit_rule(self) -> None:
        rule, view = self.selected_rule(), self.view
        if rule is None:
            return

        def saved(result: tuple[str, str] | None) -> None:
            if not result:
                return
            target, note = result
            rules = self.rules_for(view)
            if target == rule.target:
                if note != rule.note:
                    rule.note = note
                    self.cfg.save()
                    self.log_line(f"note updated for [b]{escape(target)}[/b]", "green")
                self.refresh_rules(force=True)
                return
            if any(r.target == target for r in rules if r is not rule):
                self.notify(f"{target} is already on the {self.list_name(view)}.",
                            severity="warning")
                return
            in_use = self.list_in_use(view)
            if in_use and not self.require_root():
                return
            replacement = R.Rule(target=target, note=note, enabled=rule.enabled)
            replacement.networks()
            if replacement.error:
                self.notify(f"{target}: {replacement.error}", severity="error",
                            title="Not changed")
                return
            if in_use:
                self.apply_rule(rule, remove=True, poll=False)
            rules[rules.index(rule)] = replacement
            self.cfg.save()
            self.log_line(f"changed [b]{escape(rule.target)}[/b] → "
                          f"[b]{escape(target)}[/b]", "green")
            if in_use:
                self.apply_rule(replacement)
            self.refresh_rules(force=True)

        self.push_screen(RuleScreen(
            f"Edit rule · {self.list_name(view)}",
            "Change the target or the note. A new target replaces the old one's routes.",
            rule.target, rule.note), saved)

    def action_delete_rule(self) -> None:
        rule, view = self.selected_rule(), self.view
        if rule is None:
            return
        in_use = self.list_in_use(view)
        if in_use and not self.require_root():
            return
        # The unused list has no routes - and must not delete any the used list owns.
        if in_use:
            for net in rule.networks():
                R.delete_route(net)
        rules = self.rules_for(view)
        index = rules.index(rule)
        rules.remove(rule)
        self.cfg.save()
        self._undo = (view, index, rule)
        self.log_line(f"removed [b]{escape(rule.target)}[/b] from the {self.list_name(view)}"
                      f"  ·  u to undo", "yellow")
        self.notify(f"Deleted {rule.target}. Press u to undo.", title="Deleted", timeout=6)
        self.refresh_rules()

    def action_undo(self) -> None:
        if not self._undo:
            return
        view, index, rule = self._undo
        rules = self.rules_for(view)
        if any(r.target == rule.target for r in rules):
            self.notify(f"{rule.target} is already back on the list.", severity="warning")
            self._undo = None
            return
        in_use = self.list_in_use(view)
        if in_use and not self.require_root():
            return
        self._undo = None
        rules.insert(min(index, len(rules)), rule)
        self.cfg.save()
        self.log_line(f"restored [b]{escape(rule.target)}[/b] to the {self.list_name(view)}",
                      "green")
        if in_use:
            self.apply_rule(rule)
        self.show_list(view)
        self.refresh_rules(force=True)
        self.move_to_rule(view, rule)

    def action_transfer_rule(self) -> None:
        rule, src = self.selected_rule(), self.view
        if rule is None:
            return
        dst = "vpn" if src == "bypass" else "bypass"
        if any(r.target == rule.target for r in self.rules_for(dst)):
            self.notify(f"{rule.target} is already on the {self.list_name(dst)}.",
                        severity="warning")
            return
        touches_routes = self.list_in_use(src) or self.list_in_use(dst)
        if touches_routes and not self.require_root():
            return
        if self.list_in_use(src):
            self.apply_rule(rule, remove=True, poll=False)
        self.rules_for(src).remove(rule)
        self.rules_for(dst).append(rule)
        self.cfg.save()
        self.log_line(f"moved [b]{escape(rule.target)}[/b] from the {self.list_name(src)} "
                      f"to the {self.list_name(dst)}", "green")
        if self.list_in_use(dst):
            self.apply_rule(rule)
        else:
            self.saved_not_applied(dst)
        self.refresh_rules(force=True)

    def action_toggle_rule(self) -> None:
        rule = self.selected_rule()
        if rule is None:
            return
        in_use = self.list_in_use(self.view)
        if in_use and not self.require_root():
            return
        rule.enabled = not rule.enabled
        self.cfg.save()
        if in_use:
            self.apply_rule(rule)
        self.refresh_rules()

    def apply_rule(self, rule: R.Rule, *, remove: bool = False, poll: bool = True) -> None:
        """Install or withdraw one rule's routes, the way the current mode wants.

        vpn mode sends the rule direct via the physical gateway; direct mode sends
        it into the tunnel. Links are read fresh from the routing table - the
        snapshot can be a poll behind, and a stale gateway is worse than a slow one.
        """
        tunnelled = self.direct_mode
        install = rule.enabled and not remove
        link = None
        if install:
            link = netinfo.tunnel_link() if tunnelled else netinfo.physical_link()
            if link is None:
                self.log_line(
                    f"VPN is not connected - cannot send {escape(rule.target)} through it"
                    if tunnelled else "no non-tunnel default route - cannot bypass", "red")
                return
        nets = rule.networks()
        quiet = len(nets) > 8                   # a service: summarise, don't list 300 lines
        done = 0
        for net in nets:
            if install:
                if tunnelled:
                    ok, out = R.add_tunnel_route(net, link.iface)
                    msg = f"{net} via vpn ({link.iface})"
                else:
                    ok, out = R.add_route(net, link.gateway)
                    msg = f"{net} bypass via {link.gateway} ({link.iface})"
            else:
                ok, out = R.delete_route(net)
                if not ok and R.was_absent(out):
                    continue                    # nothing to withdraw - not an error
                msg = f"{net} {'back to direct' if tunnelled else 'restored to vpn'}"
            if ok:
                done += 1
                if not quiet:
                    self.log_line(msg, "green" if install else "yellow")
            else:
                self.log_line(f"{net} failed [dim]{escape(out)}[/dim]", "red")
        if quiet and done:
            where = ("via vpn" if tunnelled else "bypassing the vpn") if install else (
                "back to direct" if tunnelled else "restored to vpn")
            self.log_line(f"{escape(rule.note or rule.target)}: {done} ranges {where}",
                          "green" if install else "yellow")
        if poll:
            self.poll()

    def action_apply(self) -> None:
        if not self.require_root():
            return
        if self.direct_mode:
            self.log_line("applying direct mode", "bold")
            self.apply_direct()
        else:
            self.log_line("applying all rules", "bold")
            self.remove_direct()        # leftovers would quietly override vpn mode
            for rule in self.cfg.rules:
                self.apply_rule(rule, poll=False)
        self.poll()

    # --------------------------------------------------------------- modes

    @property
    def direct_mode(self) -> bool:
        return self.cfg.mode == MODE_DIRECT

    def update_mode_ui(self) -> None:
        wrap = self.query_one("#rules-wrap")
        if self.direct_mode:
            wrap.border_title = "Rules · direct by default — the VPN list is in use"
        else:
            wrap.border_title = "Rules · VPN by default — the bypass list is in use"
        wrap.set_class(self.direct_mode, "direct")
        self.render_status()

    def action_toggle_mode(self) -> None:
        if not self.require_root():
            return
        going_direct = not self.direct_mode
        if going_direct:
            if netinfo.tunnel_link() is None:
                self.notify("Connect the VPN first - direct mode sends your VPN list "
                            "through it.", severity="error", title="No tunnel")
                return
            listed = sum(1 for r in self.cfg.vpn_rules if r.enabled)
            heading = "Switch to direct by default?"
            detail = (f"Everything leaves over your real connection except the {listed} "
                      "target(s) on your VPN list. DNS stays on the VPN. Connections open "
                      "through the tunnel right now will drop - including any app that "
                      "only works over the VPN.")
            if listed == 0:
                detail += " Your VPN list is empty, so nothing will use the VPN."
        else:
            heading = "Switch back to VPN by default?"
            detail = ("Everything goes through the VPN again, except your bypass list. "
                      "Connections open over your real connection right now will drop.")

        def confirmed(yes: bool) -> None:
            if yes:
                self.set_mode(MODE_DIRECT if going_direct else MODE_VPN)

        self.push_screen(ConfirmScreen(heading, detail, "Switch"), confirmed)

    def set_mode(self, mode: str) -> None:
        if mode == self.cfg.mode:
            return
        if mode == MODE_DIRECT:
            for rule in self.cfg.rules:          # bypass routes mean nothing now
                self.apply_rule(rule, remove=True, poll=False)
            self.cfg.mode = MODE_DIRECT
            self.cfg.save()
            self.log_line("switched to DIRECT by default", "bold magenta")
            self.apply_direct()
        else:
            self.remove_direct()                 # VPN is the default again at once
            for rule in self.cfg.vpn_rules:
                self.apply_rule(rule, remove=True, poll=False)
            self.cfg.mode = MODE_VPN
            self.cfg.save()
            self.log_line("switched to VPN by default", "bold cyan")
            for rule in self.cfg.rules:
                self.apply_rule(rule, poll=False)
        self.update_mode_ui()
        self.show_list("vpn" if mode == MODE_DIRECT else "bypass")
        self.refresh_rules(force=True)
        self.poll()

    def apply_direct(self) -> None:
        """Make everything go direct, except DNS and the VPN list.

        Order matters: DNS and the VPN list go into the tunnel first, and only then
        do the two half-default routes take everything else. The other way round
        there is a moment where DNS leaks out over the real connection.
        """
        tunnel, physical = netinfo.tunnel_link(), netinfo.physical_link()
        if tunnel is None or physical is None:
            self.log_line("direct mode is waiting for " +
                          ("the VPN to connect" if tunnel is None else "a network"), "yellow")
            return
        # 1. DNS stays on the VPN, so lookups are not answered by your ISP.
        state = load_state()
        pins = set(state.get("dns_pins", []))
        for server in netinfo.dns_servers():
            try:
                ipaddress.IPv4Address(server)
            except ValueError:
                continue
            if netinfo.reached_via_router(server):   # a LAN resolver stays local
                pins.add(server)
        for server in sorted(pins):
            ok, out = R.add_tunnel_route(ipaddress.ip_network(f"{server}/32"), tunnel.iface)
            self.log_line(f"dns {server} kept on vpn ({tunnel.iface})" if ok
                          else f"dns {server} failed [dim]{escape(out)}[/dim]",
                          "cyan" if ok else "red")
        save_state({**state, "dns_pins": sorted(pins)})
        # 2. The VPN list.
        for rule in self.cfg.vpn_rules:
            self.apply_rule(rule, poll=False)
        # 3. Everything else.
        failed = False
        for half in netinfo.HALF_DEFAULTS:
            ok, out = R.add_route(ipaddress.ip_network(half), physical.gateway)
            if not ok:
                failed = True
                self.log_line(f"{half} failed [dim]{escape(out)}[/dim]", "red")
        if not failed:
            self.log_line(f"everything else direct via {physical.gateway} "
                          f"({physical.iface})", "magenta")

    def remove_direct(self) -> None:
        """Undo apply_direct: the half-default routes and our DNS pins."""
        for half, link in netinfo.half_default_routes().items():
            if netinfo.is_tunnel(link.iface):
                continue                         # not ours - leave the VPN's alone
            ok, out = R.delete_route(ipaddress.ip_network(half))
            self.log_line(f"{half} removed - vpn is the default again" if ok
                          else f"{half} failed [dim]{escape(out)}[/dim]",
                          "cyan" if ok else "red")
        state = load_state()
        for server in state.get("dns_pins", []):
            R.delete_route(ipaddress.ip_network(f"{server}/32"))
        if state.get("dns_pins"):
            save_state({**state, "dns_pins": []})

    def action_clear_routes(self) -> None:
        if not self.require_root():
            return

        def confirmed(yes: bool) -> None:
            if not yes:
                return
            for rule in self.cfg.active_rules:
                for net in rule.networks():
                    ok, _ = R.delete_route(net)
                    if ok:
                        self.log_line(f"{net} removed from routing table", "yellow")
            self.poll()

        if self.direct_mode:
            screen = ConfirmScreen(
                "Remove every VPN-list route?",
                "Listed traffic goes out over your real connection like everything "
                "else. Direct mode itself stays on - press m to leave it. The rules "
                "stay in your config and can be re-applied with p.", "Remove", danger=True)
        else:
            screen = ConfirmScreen(
                "Remove every bypass route?",
                "All listed traffic goes back through the VPN. The rules stay in your "
                "config and can be re-applied with p.", "Remove", danger=True)
        self.push_screen(screen, confirmed)

    def action_refresh(self) -> None:
        """Re-poll, and pick up any edits made to the config file elsewhere."""
        mode_before = self.cfg.mode

        def lists(cfg: Config) -> tuple[list, list]:
            return ([(r.target, r.enabled) for r in cfg.rules],
                    [(r.target, r.enabled) for r in cfg.vpn_rules])

        before = lists(self.cfg)
        self.cfg = Config.load()
        after = lists(self.cfg)
        self.update_mode_ui()
        self.refresh_rules(force=True)
        self.poll()
        if self.cfg.mode != mode_before:
            self.log_line(f"mode changed on disk to {self.cfg.mode} - press p to apply",
                          "yellow")
        elif before != after:
            self.log_line(f"config reloaded - {len(self.cfg.rules)} bypass, "
                          f"{len(self.cfg.vpn_rules)} vpn rule(s) on disk", "green")
        else:
            self.log_line("refreshed", "dim")

    def account(self) -> str:
        return kc.account_for(self.cfg.profile.server, self.cfg.profile.user)

    def known_password(self) -> str | None:
        """A password we can use without asking: keychain, or none."""
        if not self.cfg.profile.save_password:
            return None
        return kc.load(self.account())

    def ask_to_connect(self, title: str, then) -> None:
        """Collect what openconnect needs, unless we already have it."""
        profile = self.cfg.profile
        if profile.auth_command:                # your own command supplies it
            then(profile.server, profile.user, None, False)
            return
        saved = self.known_password()
        if saved is not None:
            then(profile.server, profile.user, saved, False)
            return
        if profile.save_password:               # ticked, but the keychain said no
            self.log_line("could not read the saved password - asking instead", "yellow")

        def entered(result: tuple[str, str, str, bool] | None) -> None:
            if result:
                then(*result)

        self.push_screen(ConnectScreen(profile.server, profile.user,
                                       profile.save_password, title), entered)

    def action_connect(self) -> None:
        """Ask for what openconnect needs, then connect without blocking the panel."""
        if self.snap.session is not None or self._connecting:
            self.notify("openconnect is already running.", severity="warning")
            return
        self.ask_to_connect("Connect", self.start_connect)

    def action_reconnect(self) -> None:
        """Take the tunnel down and bring it straight back up."""
        if self._connecting:
            return
        session = self.snap.session

        def go(server: str, user: str, password: str | None, remember: bool) -> None:
            if session is None:
                self.start_connect(server, user, password, remember)
                return

            def confirmed(yes: bool) -> None:
                if yes:
                    self.start_connect(server, user, password, remember,
                                       replace=session.pid)

            self.push_screen(ConfirmScreen(
                f"Reconnect to {server}?",
                f"openconnect (pid {session.pid}) is stopped and started again. "
                "Every connection going through the tunnel right now will drop, "
                "and the panel re-applies your routes once it is back.",
                "Reconnect"), confirmed)

        self.ask_to_connect("Reconnect", go)

    def action_forget_password(self) -> None:
        gone, detail = kc.forget(self.account())
        self.cfg.profile.save_password = False
        self.cfg.save()
        self.log_line(f"saved password: {escape(detail)}", "yellow" if gone else "dim")
        self.notify(detail, title="Saved password")
        self.render_panels()
        self.refresh_bindings()

    def start_connect(self, server: str, user: str, password: str | None,
                      remember: bool = False, replace: int | None = None) -> None:
        if not server:
            self.notify(f"No server set. Add one to {CONFIG_FILE}", severity="error")
            return
        profile = self.cfg.profile
        if (server, user) != (profile.server, profile.user):
            profile.server, profile.user = server, user     # remember the correction
            self.cfg.save()
            self.log_line(f"profile updated: {escape(user or chr(45))}@{escape(server)}", "dim")
        self._connecting = True
        self.refresh_bindings()
        self.render_status()
        if replace:
            self.log_line(f"reconnecting to {escape(server)}…", "bold")
        else:
            self.log_line(f"connecting to {escape(server)} as "
                          f"{escape(user or 'the default user')}…", "bold")
        self._connect_worker(password, remember, replace)

    @work(exclusive=True, thread=True, group="connect")
    def _connect_worker(self, password: str | None, remember: bool,
                        replace: int | None) -> None:
        if replace:                              # reconnect: out with the old one first
            ok, detail = vpn.disconnect(replace)
            self.call_from_thread(self.log_line, f"disconnect: {escape(detail)}",
                                  "yellow" if ok else "red")
            if ok and not vpn.wait_gone(replace):
                self.call_from_thread(self.connect_finished, vpn.Attempt(
                    False, f"openconnect (pid {replace}) did not stop"), None)
                return
        attempt = vpn.connect(self.cfg.profile, password)
        stored = None
        if attempt.ok and remember and password:
            saved, detail = kc.save(self.account(), password)
            stored = (saved, detail)
        password = None                          # not kept a moment longer
        self.call_from_thread(self.connect_finished, attempt, stored)

    def connect_finished(self, attempt: vpn.Attempt,
                         stored: tuple[bool, str] | None = None) -> None:
        self._connecting = False
        self.refresh_bindings()
        if stored is not None:
            saved, detail = stored
            self.cfg.profile.save_password = bool(saved)
            self.cfg.save()
            self.log_line(f"password {escape(detail)}", "green" if saved else "red")
        if attempt.ok:
            self.log_line("connected - openconnect is running in the background", "green")
        else:
            self.log_line(f"connect failed: {escape(attempt.summary)}", "red")
            for line in attempt.output[-6:]:     # why, in openconnect's own words
                self.log_line(escape(line), "dim")
            self.notify(attempt.summary, severity="error", title="Not connected",
                        timeout=12)
        self.poll()
        if attempt.ok and R.is_root():
            self.action_apply()

    def action_connect_in_terminal(self) -> None:
        """Fallback: let openconnect talk to the terminal, for 2FA and the like."""
        if self.snap.session is not None or self._connecting:
            self.notify("openconnect is already running.", severity="warning")
            return
        profile = self.cfg.profile
        if not profile.server:
            self.notify(f"No server set. Add one to {CONFIG_FILE}", severity="error")
            return
        with self.suspend():                    # give openconnect the terminal
            print(f"\nConnecting to {profile.server} ...")
            print("Answer openconnect's questions here. It returns to the panel "
                  "once the tunnel is up.\n")
            attempt = vpn.connect_in_terminal(profile)
            if not attempt.ok:
                print(f"\n  failed: {attempt.summary}")
            input("\nPress Enter to return to the panel. ")
        self.log_line(f"connect: {escape(attempt.summary)}",
                      "green" if attempt.ok else "red")
        self.poll()
        if attempt.ok and R.is_root():
            self.action_apply()

    def action_quit(self) -> None:
        """Offer to take the VPN down with the panel, as configured."""
        if isinstance(self.screen, ModalScreen) or self._quitting:
            return                               # a dialog is already asking something
        if not (self.cfg.disconnect_on_quit and self.snap.session is not None):
            self.exit()
            return

        def chosen(choice: str | None) -> None:
            if choice == "leave":
                self.exit()
            elif choice == "disconnect":
                self._quitting = True
                self.log_line("disconnecting before quitting…", "bold")
                self._quit_worker(self.snap.session.pid, self.direct_mode)

        self.push_screen(QuitScreen(self.snap.session.server or
                                    self.cfg.profile.server or "the VPN"), chosen)

    @work(thread=True, group="quit")
    def _quit_worker(self, pid: int, direct: bool) -> None:
        if direct and R.is_root():
            # Half-default routes with no tunnel behind them are a trap: they
            # point at a gateway that will be wrong on the next network.
            self.call_from_thread(self.remove_direct)
        ok, detail = vpn.disconnect(pid)
        self.call_from_thread(self.log_line, f"disconnect: {escape(detail)}",
                              "yellow" if ok else "red")
        if ok:
            vpn.wait_gone(pid, timeout=10)
        self.call_from_thread(self.exit)

    def action_disconnect(self) -> None:
        session = self.snap.session
        if session is None:
            self.notify("Nothing to disconnect.", severity="warning")
            return

        def confirmed(yes: bool) -> None:
            if not yes:
                return
            ok, detail = vpn.disconnect(session.pid)
            self.log_line(f"disconnect: {escape(detail)}", "yellow" if ok else "red")
            self.poll()

        self.push_screen(ConfirmScreen(
            f"Disconnect {session.server}?",
            f"This stops openconnect (pid {session.pid}). Every connection going "
            "through the tunnel right now will drop.", "Disconnect", danger=True),
            confirmed)


def reset_routes() -> int:
    """Leave direct mode without the UI - for when it has cut off your network."""
    if not R.is_root():
        print("needs root:  sudo ~/.local/bin/ocpanel --reset")
        return 1
    for half, link in netinfo.half_default_routes().items():
        if not netinfo.is_tunnel(link.iface):
            ok, out = R.delete_route(ipaddress.ip_network(half))
            print(f"  {half}: {'removed' if ok else out}")
    state = load_state()
    for server in state.get("dns_pins", []):
        R.delete_route(ipaddress.ip_network(f"{server}/32"))
    save_state({**state, "dns_pins": []})
    cfg = Config.load()
    cfg.mode = MODE_VPN
    cfg.save()
    print("back to VPN by default. Your rule lists were not changed.")
    return 0


def main() -> None:
    if "--reset" in sys.argv[1:]:
        sys.exit(reset_routes())
    app = OCPanel()
    app.run()
    if app.cfg.mode == MODE_DIRECT:
        print("ocpanel: direct mode is still on - its routes stay in place after quitting.\n"
              "If you switch networks, reopen the panel so it can re-point them, or undo "
              "it with:\n  sudo ~/.local/bin/ocpanel --reset")


if __name__ == "__main__":
    main()
