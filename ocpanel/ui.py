"""Screens, panels and the keymap for ocpanel.

Everything here is presentation. Routing decisions live in app.py; this module
only draws state and turns keys into actions.
"""
from __future__ import annotations

from dataclasses import dataclass

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.color import Color
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import (Button, Checkbox, Input, Label, SelectionList, Sparkline,
                             Static)
from textual.widgets.selection_list import Selection

from . import rules as R


# ------------------------------------------------------------------- keymap
#
# One table drives the key bindings, the footer, the help screen and the
# command palette, so they can never disagree. Each entry is
#   (binding keys, action, description, footer label or None)

@dataclass(frozen=True)
class Key:
    keys: str
    action: str
    description: str
    footer: str | None = None


KEYMAP: list[tuple[str, list[Key]]] = [
    ("Rules", [
        Key("a", "add_rule", "Add a site, address or subnet", "Add"),
        Key("e", "edit_rule", "Edit the selected rule (or press Enter)", "Edit"),
        Key("space", "toggle_rule", "Turn the selected rule on or off", "On/Off"),
        Key("d,delete", "delete_rule", "Delete the selected rule", "Delete"),
        Key("u", "undo", "Undo the last delete"),
        Key("t", "transfer_rule", "Move the selected rule to the other list"),
        Key("s", "add_service", "Add a whole service by its published ranges", "Services"),
        Key("v", "verify_rule", "Test whether the selected rule's target really answers", "Test"),
        Key("V", "verify_all", "Test every host/address rule on this list"),
        Key("g", "add_relays", "Add Dota 2 relay clusters to the bypass list"),
        Key("f", "find_live", "Find what a running game is connected to"),
    ]),
    ("Lists", [
        Key("1", "show_list('bypass')", "Show the bypass list"),
        Key("2", "show_list('vpn')", "Show the VPN list"),
        Key("l", "switch_list", "Switch to the other list"),
        Key("slash", "filter", "Filter both lists", "Filter"),
        Key("j", "cursor(1)", "Move down (also ↓)"),
        Key("k", "cursor(-1)", "Move up (also ↑)"),
    ]),
    ("Routing", [
        Key("m", "toggle_mode", "Switch between VPN by default and direct by default", "Mode"),
        Key("p", "apply", "Re-apply every route for the current mode"),
        Key("x", "clear_routes", "Remove the routes of the list in use"),
        Key("r", "refresh", "Refresh, and reload the config file from disk"),
    ]),
    ("Connection", [
        Key("c", "connect", "Connect - openconnect or your subscription, "
            "whichever this profile uses"),
        Key("o", "choose_server",
            "Pick a server, or add a subscription URL / a single vless:// link"),
        Key("C", "connect_in_terminal",
            "Connect in the terminal, if the server asks for more than a password"),
        Key("R", "reconnect", "Reconnect the current tunnel (openconnect or a system VPN)"),
        Key("D", "disconnect", "Disconnect the current tunnel"),
        Key("F", "forget_password", "Forget the saved password"),
    ]),
    ("App", [
        Key("question_mark", "help", "Show every key", "Help"),
        Key("q", "quit", "Quit - routes stay in place", "Quit"),
    ]),
]

KEY_NAMES = {"space": "Space", "slash": "/", "question_mark": "?", "delete": "Del",
             "escape": "Esc", "enter": "Enter", "tab": "Tab"}


def pretty_keys(keys: str) -> str:
    return " / ".join(KEY_NAMES.get(k, k) for k in keys.split(","))


def bindings() -> list[Binding]:
    """One Binding per key, so an action with two keys shows once in the footer."""
    out = []
    for _, group in KEYMAP:
        for k in group:
            for i, key in enumerate(k.keys.split(",")):
                out.append(Binding(key, k.action, k.footer or k.description,
                                   show=k.footer is not None and i == 0))
    return out


# ------------------------------------------------------------------ palette

@dataclass
class Palette:
    """Theme colours as plain hex, for Rich text drawn outside the stylesheet."""
    ok: str = "green"
    bad: str = "red"
    warn: str = "yellow"
    vpn: str = "cyan"
    direct: str = "magenta"
    info: str = "blue"
    fg: str = "white"
    muted: str = "grey50"
    bg: str = "black"

    @classmethod
    def from_variables(cls, v: dict[str, str]) -> "Palette":
        def get(name: str, fallback: str) -> str:
            try:
                return Color.parse(v[name]).hex
            except Exception:
                return fallback
        fg, bg = get("foreground", "#dddddd"), get("background", "#111111")
        return cls(ok=get("success", "green"), bad=get("error", "red"),
                   warn=get("warning", "yellow"), vpn=get("secondary", "cyan"),
                   direct=get("accent", "magenta"), info=get("primary", "blue"),
                   fg=fg, bg=bg,
                   muted=Color.parse(fg).blend(Color.parse(bg), 0.45).hex)


def keycap(key: str, pal: Palette) -> Text:
    return Text(f" {key} ", style=f"bold {pal.bg} on {pal.muted}")


def key_hints(pairs: list[tuple[str, str]], pal: Palette) -> Text:
    """ ` y  confirm   n  cancel` - the keys a dialog answers to."""
    out = Text()
    for i, (key, what) in enumerate(pairs):
        if i:
            out.append("    ")
        out.append_text(keycap(key, pal))
        out.append(f" {what}", style=pal.muted)
    return out


# ------------------------------------------------------------------ panels

class StatusBar(Horizontal):
    """One line across the top: identity, mode, connection, access, clock."""

    def compose(self) -> ComposeResult:
        yield Static(id="sb-left")
        yield Static(id="sb-right")

    def show(self, left: Text, right: Text) -> None:
        self.query_one("#sb-left", Static).update(left)
        self.query_one("#sb-right", Static).update(right)


class InfoPanel(Static):
    """A framed block of aligned label / value rows."""

    def __init__(self, title: str, **kw) -> None:
        super().__init__(**kw)
        self.border_title = title
        self.rows: list[tuple[str, Text | str]] = []

    def set_rows(self, rows: list[tuple[str, Text | str]], pal: Palette) -> None:
        self.rows = rows
        width = max((len(label) for label, _ in rows), default=0) + 2
        body = Text()
        for i, (label, value) in enumerate(rows):
            if i:
                body.append("\n")
            body.append(f"{label:<{width}}", style=pal.muted)
            body.append_text(value if isinstance(value, Text) else Text(str(value)))
        self.update(body)


class TrafficPanel(Vertical):
    """Throughput through the tunnel and around it, with a short history."""

    HISTORY = 60

    def __init__(self, **kw) -> None:
        super().__init__(**kw)
        self.border_title = "Traffic"
        self.history = {"tun": [0.0] * self.HISTORY, "dir": [0.0] * self.HISTORY}

    def compose(self) -> ComposeResult:
        for key in ("tun", "dir"):
            yield Static(id=f"{key}-label", classes="traffic-label")
            yield Sparkline(self.history[key], id=f"{key}-spark", classes="traffic-spark")

    def push(self, key: str, rate: float, label: Text) -> None:
        series = self.history[key]
        series.append(rate)
        del series[:-self.HISTORY]
        self.query_one(f"#{key}-label", Static).update(label)
        self.query_one(f"#{key}-spark", Sparkline).data = list(series)


class FilterInput(Input):
    """The / filter. Esc clears it, Enter goes back to the list."""

    BINDINGS = [Binding("escape", "app.clear_filter", "Clear filter", show=False)]


# ----------------------------------------------------------------- dialogs

class Dialog(ModalScreen):
    """Shared frame: title, body, key hints, buttons."""

    def pal(self) -> Palette:
        return getattr(self.app, "pal", Palette())


class ConfirmScreen(Dialog):
    """Yes / no. Answers to y and n (or Esc); the buttons still work with the mouse."""

    BINDINGS = [
        Binding("y", "answer(True)", "Yes", show=False),
        Binding("n,escape", "answer(False)", "No", show=False),
    ]

    def __init__(self, title: str, body: str, confirm: str = "Confirm", *,
                 danger: bool = False) -> None:
        super().__init__()
        self._title, self._body, self._confirm, self._danger = title, body, confirm, danger

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog", classes="danger" if self._danger else ""):
            yield Label(self._title, classes="title")
            yield Static(self._body, classes="body")
            yield Static(key_hints([("y", self._confirm.lower()), ("n", "cancel")],
                                   self.pal()), classes="keys")
            with Horizontal(classes="footer"):
                yield Button("Cancel", id="no")
                yield Button(self._confirm, id="yes",
                             variant="error" if self._danger else "primary")

    def on_mount(self) -> None:
        # Enter presses the focused button: for something destructive that is Cancel.
        self.query_one("#no" if self._danger else "#yes", Button).focus()

    def action_answer(self, yes: bool) -> None:
        self.dismiss(yes)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "yes")


class RuleScreen(Dialog):
    """Add or edit one rule. Enter saves, Tab moves between fields, Esc cancels."""

    BINDINGS = [Binding("escape", "cancel", "Cancel", show=False)]

    def __init__(self, title: str, hint: str, target: str = "", note: str = "") -> None:
        super().__init__()
        self._title, self._hint, self._target, self._note = title, hint, target, note

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog"):
            yield Label(self._title, classes="title")
            yield Static(self._hint, classes="body")
            yield Label("Target", classes="field")
            yield Input(self._target, placeholder="example.com  ·  203.0.113.42  "
                        "·  203.0.113.0/24", id="target")
            yield Static(id="kind", classes="kind")
            yield Label("Note", classes="field")
            yield Input(self._note, placeholder="optional", id="note")
            yield Static(key_hints([("Enter", "save"), ("Tab", "next field"),
                                    ("Esc", "cancel")], self.pal()), classes="keys")
            with Horizontal(classes="footer"):
                yield Button("Cancel", id="no")
                yield Button("Save", id="yes", variant="primary")

    def on_mount(self) -> None:
        self.query_one("#target", Input).focus()
        self._describe(self._target)

    def _describe(self, value: str) -> None:
        """Say what the typed target will be treated as, before it is saved."""
        pal = self.pal()
        value = value.strip()
        kind = self.query_one("#kind", Static)
        if not value:
            kind.update(Text("hostname, IPv4 address, subnet, or service:google",
                             style=pal.muted))
            return
        if " " in value:
            kind.update(Text("no spaces allowed", style=pal.bad))
            return
        what = {"host": "hostname - resolved to its current addresses when saved",
                "address": "single address", "subnet": "subnet",
                "service": "whole service by published ranges"}[R.Rule(target=value).kind]
        kind.update(Text(f"→ {what}", style=pal.muted))

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "target":
            self._describe(event.value)

    def _save(self) -> None:
        target = self.query_one("#target", Input).value.strip()
        if not target or " " in target:
            self.query_one("#target", Input).focus()
            self.app.bell()
            return
        self.dismiss((target, self.query_one("#note", Input).value.strip()))

    def on_input_submitted(self) -> None:
        self._save()

    def action_cancel(self) -> None:
        self.dismiss(None)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self._save() if event.button.id == "yes" else self.dismiss(None)


class ConnectScreen(Dialog):
    """Server, user and password. Enter connects; the panel keeps running."""

    BINDINGS = [
        # Enter must connect from any field. The Remember checkbox binds Enter to
        # "toggle me", so take it first and let Space do the ticking.
        Binding("enter", "submit", "Connect", show=False, priority=True),
        Binding("escape", "cancel", "Cancel", show=False),
    ]

    def action_submit(self) -> None:
        if isinstance(self.focused, Button):      # tabbed onto a button: press it
            self.focused.press()
            return
        self._submit()

    def __init__(self, server: str, user: str, remember: bool = False,
                 title: str = "Connect") -> None:
        super().__init__()
        self._server, self._user, self._remember = server, user, remember
        self._title = title

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog"):
            yield Label(self._title, classes="title")
            yield Static("openconnect runs in the background, so the panel stays "
                         "usable. The password goes straight to it. Remembered "
                         "passwords live in your login keychain, never in the "
                         "config file.", classes="body")
            yield Label("Server", classes="field")
            yield Input(self._server, placeholder="vpn.example.com", id="server")
            yield Label("Username", classes="field")
            yield Input(self._user, placeholder="your account", id="user")
            yield Label("Password", classes="field")
            yield Input(placeholder="not shown", password=True, id="password")
            yield Checkbox("Remember it in my macOS login keychain",
                           value=self._remember, id="remember")
            yield Static(key_hints([("Enter", "connect"), ("Tab", "next field"),
                                    ("Space", "tick remember"),
                                    ("Esc", "cancel")], self.pal()), classes="keys")
            with Horizontal(classes="footer"):
                yield Button("Cancel", id="no")
                yield Button("Connect", id="yes", variant="primary")

    def on_mount(self) -> None:
        # Straight to the password when the server and user are already known.
        field = "password" if self._server and self._user else "server"
        self.query_one(f"#{field}", Input).focus()

    def _submit(self) -> None:
        server = self.query_one("#server", Input).value.strip()
        user = self.query_one("#user", Input).value.strip()
        if not server:
            self.query_one("#server", Input).focus()
            self.app.bell()
            return
        self.dismiss((server, user, self.query_one("#password", Input).value,
                      self.query_one("#remember", Checkbox).value))

    def on_input_submitted(self) -> None:
        self._submit()

    def action_cancel(self) -> None:
        self.dismiss(None)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self._submit() if event.button.id == "yes" else self.dismiss(None)


class PromptScreen(Dialog):
    """One line of text. Used for the subscription URL, which is a credential."""

    BINDINGS = [
        Binding("enter", "submit", "OK", show=False, priority=True),
        Binding("escape", "cancel", "Cancel", show=False),
    ]

    def __init__(self, title: str, hint: str, value: str = "",
                 placeholder: str = "", secret: bool = False) -> None:
        super().__init__()
        self._title, self._hint = title, hint
        self._value, self._placeholder, self._secret = value, placeholder, secret

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog"):
            yield Label(self._title, classes="title")
            yield Static(self._hint, classes="body")
            yield Input(self._value, placeholder=self._placeholder,
                        password=self._secret, id="value")
            yield Static(key_hints([("Enter", "ok"), ("Esc", "cancel")], self.pal()),
                         classes="keys")
            with Horizontal(classes="footer"):
                yield Button("Cancel", id="no")
                yield Button("OK", id="yes", variant="primary")

    def on_mount(self) -> None:
        self.query_one("#value", Input).focus()

    def action_submit(self) -> None:
        if isinstance(self.focused, Button):
            self.focused.press()
            return
        value = self.query_one("#value", Input).value.strip()
        self.dismiss(value or None)

    def on_input_submitted(self) -> None:
        self.action_submit()

    def action_cancel(self) -> None:
        self.dismiss(None)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "yes":
            self.action_submit()
        else:
            self.dismiss(None)


class QuitScreen(Dialog):
    """Quitting with a tunnel up: take it down, leave it up, or stay."""

    BINDINGS = [
        Binding("y", "answer('disconnect')", "Disconnect and quit", show=False),
        Binding("l", "answer('leave')", "Leave it running", show=False),
        Binding("n,escape", "answer('cancel')", "Stay", show=False),
    ]

    def __init__(self, server: str) -> None:
        super().__init__()
        self._server = server

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog", classes="danger"):
            yield Label("Quit ocpanel", classes="title")
            yield Static(f"You are connected to {self._server}. Disconnecting takes "
                         "the tunnel down for everything on this Mac, and any direct "
                         "routes the panel added are removed with it.", classes="body")
            yield Static(key_hints([("y", "disconnect and quit"),
                                    ("l", "quit, leave the VPN up"),
                                    ("n", "stay")], self.pal()), classes="keys")
            with Horizontal(classes="footer"):
                yield Button("Stay", id="cancel")
                yield Button("Leave VPN up", id="leave")
                yield Button("Disconnect & quit", id="disconnect", variant="error")

    def on_mount(self) -> None:
        self.query_one("#cancel", Button).focus()

    def action_answer(self, choice: str) -> None:
        self.dismiss(choice)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id if event.button.id != "cancel" else "cancel")


class PickerScreen(Dialog):
    """Tick entries from a list. Space ticks, a/n select all/none, Enter adds."""

    BINDINGS = [
        # Enter must add, not toggle - the list would otherwise take it first.
        Binding("enter", "submit", "Add selected", show=False, priority=True),
        Binding("a", "all", "All", show=False),
        Binding("n", "none", "None", show=False),
        Binding("escape", "cancel", "Cancel", show=False),
    ]

    def __init__(self, title: str, hint: str, choices: list[tuple[str, str, bool]],
                 confirm: str = "Add selected") -> None:
        super().__init__()
        self._title, self._hint, self._choices, self._confirm = title, hint, choices, confirm

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog", classes="wide"):
            yield Label(self._title, classes="title")
            yield Static(self._hint, classes="body")
            if self._choices:
                yield SelectionList[str](
                    *[Selection(label, value, on) for label, value, on in self._choices],
                    id="picks")
                yield Static(id="count", classes="kind")
            else:
                yield Static("Nothing found.", classes="body")
            yield Static(key_hints([("Space", "tick"), ("a", "all"), ("n", "none"),
                                    ("Enter", "use ticked / highlighted"),
                                    ("Esc", "cancel")], self.pal()),
                         classes="keys")
            with Horizontal(classes="footer"):
                yield Button("Cancel", id="no")
                yield Button(self._confirm, id="yes", variant="primary",
                             disabled=not self._choices)

    def on_mount(self) -> None:
        if self._choices:
            self.query_one("#picks", SelectionList).focus()
            self._count()

    def _count(self) -> None:
        picks = self.query_one("#picks", SelectionList)
        self.query_one("#count", Static).update(Text(
            f"{len(picks.selected)} of {picks.option_count} selected", style=self.pal().muted))

    def on_selection_list_selected_changed(self) -> None:
        self._count()

    def action_all(self) -> None:
        if self._choices:
            self.query_one("#picks", SelectionList).select_all()

    def action_none(self) -> None:
        if self._choices:
            self.query_one("#picks", SelectionList).deselect_all()

    def action_submit(self) -> None:
        if isinstance(self.focused, Button):        # Tabbed onto a button: press it
            self.focused.press()
            return
        self.dismiss(self.chosen())

    def chosen(self) -> list[str] | None:
        """What Enter should act on.

        Ticked entries, or - when nothing is ticked - the highlighted row. In a
        pick-one list that is what Enter obviously means, and without it Enter
        silently does nothing at all.
        """
        if not self._choices:
            return None
        picks = self.query_one("#picks", SelectionList)
        selected = list(picks.selected)
        if selected:
            return selected
        index = picks.highlighted
        if index is None:
            return None
        return [picks.get_option_at_index(index).value]

    def action_cancel(self) -> None:
        self.dismiss(None)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(self.chosen() if event.button.id == "yes" else None)


class HelpScreen(Dialog):
    """Every key, grouped - generated from KEYMAP."""

    BINDINGS = [
        Binding("escape,question_mark,q", "close", "Close", show=False),
        Binding("j", "scroll(3)", "Down", show=False),
        Binding("k", "scroll(-3)", "Up", show=False),
    ]

    def compose(self) -> ComposeResult:
        pal = self.pal()
        body = Text()
        for i, (group, keys) in enumerate(KEYMAP):
            if i:
                body.append("\n")
            body.append(f"{group}\n", style=f"bold {pal.info}")
            for k in keys:
                body.append(f"  {pretty_keys(k.keys):<12}", style=f"bold {pal.fg}")
                body.append(f"{k.description}\n", style=pal.fg)
        body.append("\n")
        body.append("Anywhere\n", style=f"bold {pal.info}")
        for key, what in (("Ctrl+P", "Command palette - type any action by name, or change theme"),
                          ("Enter", "Edit the selected rule"),
                          ("Tab", "Move between fields in a dialog")):
            body.append(f"  {key:<12}", style=f"bold {pal.fg}")
            body.append(f"{what}\n", style=pal.fg)
        with Vertical(id="dialog", classes="wide help"):
            yield Label("Keyboard", classes="title")
            with VerticalScroll(id="help-body"):
                yield Static(body)
            yield Static(key_hints([("j / k", "scroll"), ("Esc", "close")], pal),
                         classes="keys")

    def on_mount(self) -> None:
        self.query_one("#help-body", VerticalScroll).focus()

    def action_scroll(self, lines: int) -> None:
        self.query_one("#help-body", VerticalScroll).scroll_relative(y=lines, animate=False)

    def action_close(self) -> None:
        self.dismiss(None)
