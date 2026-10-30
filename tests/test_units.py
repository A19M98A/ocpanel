"""Unit tests for the parts that can be tested without root, network or a VPN.

Everything that changes the routing table is deliberately not exercised here;
that is done against a simulated routing table, never a real one.
"""
import os
import tempfile
import unittest

# config reads this at import time, so keep the tests away from a real config.
os.environ.setdefault("OCPANEL_HOME", tempfile.mkdtemp(prefix="ocpanel-test-"))

from ocpanel import netinfo, vpn                      # noqa: E402
from ocpanel.app import human_bytes, human_secs       # noqa: E402
from ocpanel.config import Config, MODE_DIRECT, Profile  # noqa: E402
from ocpanel.rules import Rule, _spec                 # noqa: E402
from ocpanel.ui import KEYMAP, bindings, pretty_keys  # noqa: E402


class TestRouteParsing(unittest.TestCase):
    def test_netstat_destinations_are_expanded(self):
        cases = {"0/1": "0.0.0.0/1", "128.0/1": "128.0.0.0/1",
                 "198.51.100/24": "198.51.100.0/24", "default": "0.0.0.0/0"}
        for text, expected in cases.items():
            self.assertEqual(str(netinfo._expand_dest(text)), expected, text)

    def test_junk_destination_is_ignored(self):
        self.assertIsNone(netinfo._expand_dest("bogus"))

    def test_tunnel_interfaces_are_recognised(self):
        for iface in ("utun0", "utun4", "ppp0", "ipsec1"):
            self.assertTrue(netinfo.is_tunnel(iface), iface)
        for iface in ("en0", "en1", "bridge0", ""):
            self.assertFalse(netinfo.is_tunnel(iface), iface)


class TestRules(unittest.TestCase):
    def test_target_kinds(self):
        cases = {"203.0.113.4": "address", "203.0.113.0/24": "subnet",
                 "example.com": "host", "service:google": "service"}
        for target, kind in cases.items():
            self.assertEqual(Rule(target=target).kind, kind, target)

    def test_route_arguments(self):
        import ipaddress
        self.assertEqual(_spec(ipaddress.ip_network("203.0.113.4/32")),
                         ["-host", "203.0.113.4"])
        self.assertEqual(_spec(ipaddress.ip_network("203.0.113.0/24")),
                         ["-net", "203.0.113.0", "-netmask", "255.255.255.0"])

    def test_bad_subnet_reports_an_error_instead_of_raising(self):
        rule = Rule(target="203.0.113.0/99")
        self.assertEqual(rule.networks(), [])
        self.assertTrue(rule.error)

    def test_unknown_service_is_an_error(self):
        rule = Rule(target="service:nope")
        self.assertEqual(rule.networks(), [])
        self.assertIn("unknown service", rule.error)


class TestOpenconnectArgv(unittest.TestCase):
    def profile(self, **kw):
        return Profile(server="vpn.example.com", user="alice", **kw)

    def test_never_blocks_on_a_prompt(self):
        argv = vpn.build_argv(self.profile(), on_stdin=True)
        self.assertIn("--background", argv)
        self.assertIn("--non-inter", argv)
        self.assertIn("--passwd-on-stdin", argv)

    def test_terminal_mode_stays_interactive(self):
        argv = vpn.build_argv(self.profile(), on_stdin=False, interactive=True)
        self.assertNotIn("--non-inter", argv)
        self.assertNotIn("--passwd-on-stdin", argv)

    def test_extra_args_and_server_order(self):
        argv = vpn.build_argv(self.profile(extra_args=["--protocol=anyconnect"]),
                              on_stdin=False)
        self.assertEqual(argv[-1], "vpn.example.com")
        self.assertIn("--protocol=anyconnect", argv)

    def test_no_server_is_refused(self):
        with self.assertRaises(ValueError):
            vpn.build_argv(Profile(), on_stdin=False)


class TestFailureSummary(unittest.TestCase):
    def test_reports_the_cause_not_the_consequence(self):
        out = ["POST https://vpn.example.com/", "Connected to 203.0.113.1:443",
               "Login failed.", "Failed to complete authentication"]
        self.assertEqual(vpn._summarise(1, out), "Login failed.")

    def test_a_hostname_containing_invalid_is_not_an_error(self):
        out = ["POST https://host.invalid/", "getaddrinfo failed for host 'host.invalid'",
               "Failed to complete authentication"]
        self.assertIn("getaddrinfo failed", vpn._summarise(1, out))

    def test_falls_back_to_the_exit_status(self):
        self.assertEqual(vpn._summarise(2, ["POST https://x/"]),
                         "openconnect exited with status 2")

    def test_success(self):
        self.assertEqual(vpn._summarise(0, []), "connected")


class TestConfig(unittest.TestCase):
    def test_round_trip_keeps_both_lists_and_the_mode(self):
        cfg = Config()
        cfg.mode = MODE_DIRECT
        cfg.profile.server = "vpn.example.com"
        cfg.rules.append(Rule(target="203.0.113.0/24", note="bypass"))
        cfg.vpn_rules.append(Rule(target="service:google", note="via vpn"))
        cfg.save()
        again = Config.load()
        self.assertEqual(again.mode, MODE_DIRECT)
        self.assertEqual([r.target for r in again.rules], ["203.0.113.0/24"])
        self.assertEqual([r.target for r in again.vpn_rules], ["service:google"])
        self.assertIs(again.active_rules, again.vpn_rules)

    def test_an_unknown_mode_falls_back_to_vpn(self):
        import json
        from ocpanel.config import CONFIG_FILE
        CONFIG_FILE.write_text(json.dumps({"mode": "sideways"}))
        self.assertEqual(Config.load().mode, "vpn")


class TestKeymap(unittest.TestCase):
    def test_every_key_has_an_action_and_a_description(self):
        for group, keys in KEYMAP:
            for key in keys:
                self.assertTrue(key.keys and key.action and key.description, key)

    def test_no_key_is_bound_twice(self):
        keys = [b.key for b in bindings()]
        self.assertEqual(len(keys), len(set(keys)), f"duplicate: {keys}")

    def test_only_the_first_key_of_an_action_shows_in_the_footer(self):
        shown = [b for b in bindings() if b.show and b.action == "delete_rule"]
        self.assertEqual(len(shown), 1)

    def test_key_names_are_readable(self):
        self.assertEqual(pretty_keys("d,delete"), "d / Del")
        self.assertEqual(pretty_keys("question_mark"), "?")


class TestFormatting(unittest.TestCase):
    def test_bytes(self):
        self.assertEqual(human_bytes(512), "512B")
        self.assertEqual(human_bytes(1536), "1.5K")
        self.assertEqual(human_bytes(5 * 1024 ** 3), "5.0G")

    def test_seconds(self):
        self.assertEqual(human_secs(0), "-")
        self.assertEqual(human_secs(75), "1:15")
        self.assertEqual(human_secs(3725), "1:02:05")


if __name__ == "__main__":
    unittest.main()


class TestProviders(unittest.TestCase):
    """Recognising who owns the tunnel: openconnect, a system VPN, or nobody."""

    SCUTIL = (
        'Available network connection services in the current set (*=enabled):\n'
        '* (Connected)      9BFD2714-233E-420A-A673-55534FB0AC18 VPN '
        '(hossin.asaadi.V2Box) "V2BOX"                          [VPN:hossin.asaadi.V2Box]\n'
        '  (Disconnected)   1A2B3C4D-0000-0000-0000-000000000000 VPN '
        '(com.example.wg) "Work WG"                             [VPN:com.example.wg]\n')

    def parse(self, text):
        from ocpanel.netinfo import NE_LIST, NEService
        out = []
        for line in text.splitlines():
            m = NE_LIST.match(line)
            if m:
                out.append(NEService(name=m["name"], status=m["status"],
                                     identifier=m["id"], bundle=m["bundle"],
                                     enabled=m["enabled"] == "*"))
        return out

    def test_scutil_list_is_parsed(self):
        services = self.parse(self.SCUTIL)
        self.assertEqual([s.name for s in services], ["V2BOX", "Work WG"])
        self.assertEqual([s.connected for s in services], [True, False])
        self.assertEqual(services[0].bundle, "hossin.asaadi.V2Box")

    def test_header_line_is_not_a_service(self):
        self.assertEqual(self.parse(self.SCUTIL.splitlines()[0]), [])

    def test_a_system_vpn_can_be_stopped_but_has_no_pid(self):
        from ocpanel.netinfo import Provider
        p = Provider(kind="ne-vpn", name="V2BOX", service="V2BOX")
        self.assertTrue(p.controllable)
        self.assertIsNone(p.pid)
        self.assertIn("system VPN", p.label)

    def test_an_unknown_tunnel_is_shown_but_not_controllable(self):
        from ocpanel.netinfo import Provider
        self.assertFalse(Provider(kind="unknown", name="utun7", iface="utun7").controllable)

    def test_openconnect_is_controllable_by_pid(self):
        from ocpanel.netinfo import Provider
        self.assertTrue(Provider(kind="openconnect", name="openconnect", pid=42).controllable)
        self.assertFalse(Provider(kind="openconnect", name="openconnect").controllable)
