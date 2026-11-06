"""Unit tests for the parts that can be tested without root, network or a VPN.

Everything that changes the routing table is deliberately not exercised here;
that is done against a simulated routing table, never a real one.
"""
import ipaddress
import os
import pathlib
import tempfile
import unittest

# config reads this at import time, so keep the tests away from a real config.
os.environ.setdefault("OCPANEL_HOME", tempfile.mkdtemp(prefix="ocpanel-test-"))

from ocpanel import netinfo, plat, vpn                # noqa: E402
from ocpanel.app import human_bytes, human_secs       # noqa: E402
from ocpanel.config import Config, MODE_DIRECT, Profile  # noqa: E402
from ocpanel.rules import Rule                        # noqa: E402
from ocpanel.ui import KEYMAP, bindings, pretty_keys  # noqa: E402


class TestRouteParsing(unittest.TestCase):
    def test_destinations_are_expanded(self):
        native = ({"0/1": "0.0.0.0/1", "128.0/1": "128.0.0.0/1",
                   "198.51.100/24": "198.51.100.0/24", "default": "0.0.0.0/0"}
                  if plat.MACOS else
                  {"0.0.0.0/1": "0.0.0.0/1", "128.0.0.0/1": "128.0.0.0/1",
                   "198.51.100.0/24": "198.51.100.0/24", "default": "0.0.0.0/0"})
        for text, expected in native.items():
            self.assertEqual(str(netinfo._expand_dest(text)), expected, text)

    def test_netstat_abbreviations_are_expanded(self):
        cases = {"0/1": "0.0.0.0/1", "128.0/1": "128.0.0.0/1",
                 "198.51.100/24": "198.51.100.0/24", "default": "0.0.0.0/0"}
        for text, expected in cases.items():
            self.assertEqual(str(plat.expand_dest(text, macos=True)), expected, text)

    def test_junk_destination_is_ignored(self):
        self.assertIsNone(netinfo._expand_dest("bogus"))

    def test_tunnel_interfaces_are_recognised(self):
        for iface in ("utun0", "utun4", "ppp0", "ipsec1",    # macOS
                      "tun0", "tap1", "wg0", "nordlynx"):    # Linux
            self.assertTrue(netinfo.is_tunnel(iface), iface)
        for iface in ("en0", "en1", "bridge0", "eth0", "enp3s0", "wlan0", ""):
            self.assertFalse(netinfo.is_tunnel(iface), iface)


class TestRules(unittest.TestCase):
    def test_target_kinds(self):
        cases = {"203.0.113.4": "address", "203.0.113.0/24": "subnet",
                 "example.com": "host", "service:google": "service"}
        for target, kind in cases.items():
            self.assertEqual(Rule(target=target).kind, kind, target)


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


class TestProbe(unittest.TestCase):
    """A route being right is not the same as the target answering."""

    def test_refused_port_is_reported_not_raised(self):
        from ocpanel.netinfo import probe
        p = probe("127.0.0.1", port=9, timeout=3)      # discard port, nothing listening
        self.assertFalse(p.ok)
        self.assertIn("no connection", p.detail)
        self.assertLess(p.seconds, 3)

    def test_a_plain_port_answering_counts_as_reachable(self):
        import socket
        import threading
        from ocpanel.netinfo import probe
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]

        def answer():
            conn, _ = srv.accept()
            conn.recv(64)
            conn.sendall(b"HTTP/1.0 200 OK\r\n\r\n")
            conn.close()

        t = threading.Thread(target=answer, daemon=True)
        t.start()
        try:
            p = probe("127.0.0.1", port=port, timeout=5)
            self.assertTrue(p.ok, p.detail)
            self.assertEqual(p.detail, "answered")
        finally:
            srv.close()

    def test_accepting_then_staying_silent_is_a_failure(self):
        """The case that broke a real site: the connection is accepted, then dropped."""
        import socket
        import threading
        from ocpanel.netinfo import probe
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        held = []

        def swallow():
            conn, _ = srv.accept()
            held.append(conn)          # accept and never answer

        threading.Thread(target=swallow, daemon=True).start()
        try:
            p = probe("127.0.0.1", port=port, timeout=2)
            self.assertFalse(p.ok)
            self.assertIn("silence", p.detail)      # the intercepted-looking case
        finally:
            for c in held:
                c.close()
            srv.close()

    def test_a_peer_that_closes_at_once_is_a_failure_too(self):
        import socket
        import threading
        from ocpanel.netinfo import probe
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]

        def hangup():
            conn, _ = srv.accept()
            conn.close()

        threading.Thread(target=hangup, daemon=True).start()
        try:
            p = probe("127.0.0.1", port=port, timeout=3)
            self.assertFalse(p.ok)
            self.assertTrue("dropped" in p.detail or "no reply" in p.detail, p.detail)
        finally:
            srv.close()


class TestRouteEnforcement(unittest.TestCase):
    """A route can be installed and still be ignored by the system."""

    def test_effective_source_is_a_local_address(self):
        from ocpanel.netinfo import effective_source
        src = effective_source("127.0.0.1")
        self.assertEqual(src, "127.0.0.1")

    def test_effective_source_survives_an_unroutable_target(self):
        from ocpanel.netinfo import effective_source
        self.assertIsInstance(effective_source("0.0.0.0"), str)   # no crash

    def test_captured_is_false_when_the_source_matches_the_physical_link(self):
        from ocpanel import netinfo
        self.assertFalse(netinfo.captured("127.0.0.1", "127.0.0.1"))

    def test_captured_is_true_when_something_else_takes_the_traffic(self):
        from ocpanel import netinfo
        # The physical link is not the address the kernel would use, so the
        # traffic is leaving somewhere else - the includeAllNetworks case.
        self.assertTrue(netinfo.captured("127.0.0.1", "192.0.2.77"))

    def test_unknown_physical_address_is_not_reported_as_captured(self):
        from ocpanel import netinfo
        self.assertFalse(netinfo.captured("127.0.0.1", ""))


class TestSubscription(unittest.TestCase):
    """Parsing a subscription and turning it into a sing-box config."""

    VLESS_TCP = "vless://11111111-2222-3333-4444-555555555555@vpn.example.com:443?encryption=none&security=none&type=tcp#tcp-one"
    VLESS_WS_TLS = "vless://11111111-2222-3333-4444-555555555555@vpn.example.com:2096?encryption=none&security=tls&type=ws&path=%2Fws&host=cdn.example.com&sni=cdn.example.com#ws-one"
    VLESS_PQ = "vless://11111111-2222-3333-4444-555555555555@vpn.example.com:2095?encryption=mlkem768x25519plus.native.0rtt.AAAA&security=none&type=ws&path=%2F#pq-one"

    def test_tcp_entry(self):
        from ocpanel.proxy import parse_uri
        s = parse_uri(self.VLESS_TCP)
        self.assertEqual((s.protocol, s.host, s.port, s.transport, s.tls),
                         ("vless", "vpn.example.com", 443, "tcp", False))
        self.assertEqual(s.name, "tcp-one")
        self.assertEqual(s.unsupported, "")

    def test_websocket_with_tls_keeps_path_host_and_sni(self):
        from ocpanel.proxy import parse_uri
        s = parse_uri(self.VLESS_WS_TLS)
        out = s.outbound()
        self.assertEqual(out["transport"], {"type": "ws", "path": "/ws",
                                            "headers": {"Host": "cdn.example.com"}})
        self.assertTrue(out["tls"]["enabled"])
        self.assertEqual(out["tls"]["server_name"], "cdn.example.com")

    def test_xray_only_encryption_is_refused_rather_than_silently_broken(self):
        from ocpanel.proxy import parse_uri
        s = parse_uri(self.VLESS_PQ)
        self.assertIn("Xray", s.unsupported)

    def test_base64_subscription_is_decoded(self):
        import base64
        from ocpanel.proxy import parse_subscription
        body = base64.b64encode(f"{self.VLESS_TCP}\n{self.VLESS_PQ}".encode()).decode()
        servers = parse_subscription(body)
        self.assertEqual([s.name for s in servers], ["tcp-one", "pq-one"])

    def test_plain_text_subscription_also_works(self):
        from ocpanel.proxy import parse_subscription
        self.assertEqual(len(parse_subscription(self.VLESS_TCP)), 1)

    def test_junk_is_ignored_not_raised(self):
        from ocpanel.proxy import parse_subscription
        self.assertEqual(parse_subscription("not a uri\n\nhttp://example.com"), [])

    def test_tunnel_config_keeps_the_routing_table_ordinary(self):
        from ocpanel.proxy import build_config, parse_uri
        cfg = build_config(parse_uri(self.VLESS_TCP))
        tun = cfg["inbounds"][0]
        self.assertEqual(tun["type"], "tun")
        self.assertTrue(tun["auto_route"])
        # strict_route would install firewall rules that defeat ocpanel's own routes
        self.assertFalse(tun["strict_route"])
        self.assertTrue(cfg["route"]["auto_detect_interface"])

    def test_socks_mode_has_no_tunnel(self):
        from ocpanel.proxy import build_config, parse_uri
        cfg = build_config(parse_uri(self.VLESS_TCP), socks_port=1080)
        self.assertEqual([i["type"] for i in cfg["inbounds"]], ["socks"])

    def test_singbox_provider_can_be_stopped(self):
        from ocpanel.netinfo import Provider
        self.assertTrue(Provider(kind="sing-box", name="sing-box", pid=10).controllable)
        self.assertFalse(Provider(kind="sing-box", name="sing-box").controllable)


class TestSingBoxSchema(unittest.TestCase):
    """The generated config must be valid for the installed sing-box.

    A TUN config that `check` rejects is a connection that fails the moment the
    user presses c, so this validates the mode that actually runs - not just the
    SOCKS one that is convenient to test.
    """

    URI = ("vless://11111111-2222-3333-4444-555555555555@vpn.example.com:443"
           "?encryption=none&security=none&type=tcp#tcp-one")

    def setUp(self):
        from ocpanel import proxy
        if not proxy.binary():
            self.skipTest("sing-box is not installed")

    def test_tun_inbound_has_no_legacy_fields(self):
        from ocpanel.proxy import build_config, parse_uri
        tun = build_config(parse_uri(self.URI))["inbounds"][0]
        # Removed in sing-box 1.13; leaving them in makes the runtime refuse.
        for gone in ("sniff", "sniff_override_destination", "domain_strategy",
                     "inet4_address", "inet6_address"):
            self.assertNotIn(gone, tun)

    def test_sniffing_is_a_route_action(self):
        from ocpanel.proxy import build_config, parse_uri
        rules = build_config(parse_uri(self.URI))["route"]["rules"]
        self.assertIn({"action": "sniff"}, rules)

    def _check(self, **kwargs):
        import tempfile
        from pathlib import Path
        from ocpanel.proxy import check_config, parse_uri, write_config
        with tempfile.TemporaryDirectory() as d:
            path = write_config(parse_uri(self.URI), path=Path(d) / "c.json", **kwargs)
            return check_config(path)

    def test_tun_config_passes_sing_box_check(self):
        ok, detail = self._check()
        self.assertTrue(ok, detail)

    def test_socks_config_passes_sing_box_check(self):
        ok, detail = self._check(socks_port=11080)
        self.assertTrue(ok, detail)


class TestSources(unittest.TestCase):
    """Servers can come from a subscription URL or from one pasted link."""

    LINK = ("vless://11111111-2222-3333-4444-555555555555@one.example.com:443"
            "?encryption=none&security=none&type=tcp#just-one")

    def test_a_pasted_uri_is_recognised_as_a_link(self):
        from ocpanel.proxy import looks_like_link
        self.assertTrue(looks_like_link(self.LINK))
        self.assertTrue(looks_like_link("  TROJAN://x@h:443#n  "))
        self.assertFalse(looks_like_link("https://example.com/sub/abc"))

    def test_a_link_source_needs_no_network(self):
        from ocpanel.proxy import servers_from
        servers, err = servers_from("link", self.LINK)
        self.assertEqual(err, "")
        self.assertEqual([s.name for s in servers], ["just-one"])

    def test_a_broken_link_is_reported(self):
        from ocpanel.proxy import servers_from
        servers, err = servers_from("link", "vless://nonsense")
        self.assertEqual(servers, [])
        self.assertTrue(err)

    def test_a_link_pasted_into_the_subscription_slot_still_works(self):
        from ocpanel.proxy import servers_from
        servers, err = servers_from("subscription", self.LINK)
        self.assertEqual([s.name for s in servers], ["just-one"])

    def test_sources_round_trip_without_the_secret(self):
        import json
        from ocpanel.config import CONFIG_FILE, Config, Source
        cfg = Config()
        cfg.sources = [Source(id="1", name="subscription", kind="subscription"),
                       Source(id="2", name="link", kind="link")]
        cfg.save()
        again = Config.load()
        self.assertEqual([(s.id, s.kind) for s in again.sources],
                         [("1", "subscription"), ("2", "link")])
        raw = json.loads(CONFIG_FILE.read_text())
        self.assertNotIn("http", json.dumps(raw["sources"]))   # no URL on disk

    def test_keychain_account_is_per_source(self):
        from ocpanel.keychain import source_account
        self.assertNotEqual(source_account("1"), source_account("2"))
        self.assertIn("1", source_account("1"))


class TestTunnelDetection(unittest.TestCase):
    """Not every client installs a default route."""

    def test_a_default_route_through_a_tunnel_is_found(self):
        from ocpanel import netinfo
        saved = netinfo.default_routes
        netinfo.default_routes = lambda: [netinfo.Link("10.0.0.1", "utun4"),
                                          netinfo.Link("192.168.1.1", "en0")]
        try:
            self.assertEqual(netinfo.tunnel_link().iface, "utun4")
        finally:
            netinfo.default_routes = saved

    def test_a_tunnel_without_a_default_route_is_still_found(self):
        """sing-box covers the space with 1, 2/7, 4/6 ... 128.0/1 instead."""
        from ocpanel import netinfo
        saved = (netinfo.default_routes, netinfo.iface_addresses,
                 netinfo.effective_source, netinfo.route_info, netinfo._TUNNEL_CACHE)
        netinfo.default_routes = lambda: [netinfo.Link("192.168.1.1", "en0")]
        netinfo.iface_addresses = lambda: {"en0": "192.168.1.5", "utun5": "172.19.0.1"}
        netinfo.effective_source = lambda target, port=443: "172.19.0.1"
        netinfo.route_info = lambda t: {"interface": "utun5", "gateway": "172.19.0.1"}
        netinfo._TUNNEL_CACHE = (0.0, None)
        try:
            link = netinfo.tunnel_link()
            self.assertEqual((link.iface, link.gateway), ("utun5", "172.19.0.1"))
        finally:
            (netinfo.default_routes, netinfo.iface_addresses, netinfo.effective_source,
             netinfo.route_info, netinfo._TUNNEL_CACHE) = saved

    def test_no_tunnel_when_traffic_uses_the_physical_link(self):
        from ocpanel import netinfo
        saved = (netinfo.default_routes, netinfo.iface_addresses,
                 netinfo.effective_source, netinfo._TUNNEL_CACHE)
        netinfo.default_routes = lambda: [netinfo.Link("192.168.1.1", "en0")]
        netinfo.iface_addresses = lambda: {"en0": "192.168.1.5", "utun5": "172.19.0.1"}
        netinfo.effective_source = lambda target, port=443: "192.168.1.5"
        netinfo._TUNNEL_CACHE = (0.0, None)
        try:
            self.assertIsNone(netinfo.tunnel_link())
        finally:
            (netinfo.default_routes, netinfo.iface_addresses,
             netinfo.effective_source, netinfo._TUNNEL_CACHE) = saved

    def test_a_root_owned_singbox_counts_as_running(self):
        """os.kill raises PermissionError for another user's process."""
        import os
        from ocpanel import proxy
        saved_kill, saved_file = os.kill, proxy.PID_FILE
        import tempfile, pathlib
        with tempfile.TemporaryDirectory() as d:
            proxy.PID_FILE = pathlib.Path(d) / "pid"
            proxy.PID_FILE.write_text("4242")

            def denied(pid, sig):
                raise PermissionError

            os.kill = denied
            try:
                self.assertEqual(proxy.running_pid(), 4242)
            finally:
                os.kill, proxy.PID_FILE = saved_kill, saved_file


class TestDnsHandling(unittest.TestCase):
    """On a network that poisons DNS, every answer must come from the proxy."""

    URI = ("vless://11111111-2222-3333-4444-555555555555@vpn.example.com:443"
           "?encryption=none&security=none&type=tcp#one")

    def config(self):
        from ocpanel.proxy import build_config, parse_uri
        return build_config(parse_uri(self.URI))

    def test_dns_is_hijacked_before_private_addresses_go_direct(self):
        rules = self.config()["route"]["rules"]
        hijack = [i for i, r in enumerate(rules) if r.get("action") == "hijack-dns"]
        private = [i for i, r in enumerate(rules) if r.get("ip_is_private")]
        self.assertTrue(hijack, "DNS must be hijacked")
        self.assertTrue(private, "private addresses should still go direct")
        # Resolvers handed out by DHCP are usually LAN addresses: if the private
        # rule came first, every query would leave unprotected.
        self.assertLess(max(hijack), min(private))

    def test_both_dns_over_port_53_and_sniffed_dns_are_caught(self):
        rules = self.config()["route"]["rules"]
        self.assertIn({"protocol": "dns", "action": "hijack-dns"}, rules)
        self.assertIn({"port": 53, "action": "hijack-dns"}, rules)

    def test_answers_come_from_the_proxy_by_default(self):
        dns = self.config()["dns"]
        remote = next(s for s in dns["servers"] if s["tag"] == "remote")
        self.assertEqual(remote["detour"], "proxy")
        self.assertEqual(dns["final"], "remote")

    def test_the_proxy_hostname_resolves_without_the_proxy(self):
        dns = self.config()["dns"]
        rule = next(r for r in dns["rules"] if "domain" in r)
        self.assertEqual(rule["domain"], ["vpn.example.com"])
        self.assertEqual(rule["server"], "local")


NETSTAT = """Routing tables

Internet:
Destination        Gateway            Flags        Netif Expire
default            172.30.36.1        UGScg          en1
0/1                172.19.0.1         UGSc         utun5
10.10.34.36        172.19.0.1         UGHS         utun5
128.0/1            172.19.0.1         UGSc         utun5
198.51.100/24      172.30.36.1        UGSc           en1
"""

IP_ROUTE = """default via 192.168.1.1 dev eth0 proto dhcp metric 100
0.0.0.0/1 dev tun0 scope link
10.10.34.36 via 192.168.1.1 dev eth0
128.0.0.0/1 dev tun0 scope link
198.51.100.0/24 via 192.168.1.1 dev eth0
"""


class TestPlatformRoutes(unittest.TestCase):
    """Both platforms' output, parsed from whichever one is running the tests."""

    def test_netstat_rows(self):
        rows = plat.parse_routes(NETSTAT, macos=True)
        self.assertIn(("default", "172.30.36.1", "en1"), rows)
        self.assertIn(("128.0/1", "172.19.0.1", "utun5"), rows)
        self.assertNotIn("Destination", [r[0] for r in rows])

    def test_ip_route_rows(self):
        rows = plat.parse_routes(IP_ROUTE, macos=False)
        self.assertIn(("default", "192.168.1.1", "eth0"), rows)
        self.assertIn(("128.0.0.0/1", "", "tun0"), rows)       # dev-only, no gateway

    def test_both_find_the_same_halves(self):
        for text, macos in ((NETSTAT, True), (IP_ROUTE, False)):
            halves = {str(plat.expand_dest(d, macos=macos))
                      for d, _, i in plat.parse_routes(text, macos=macos)
                      if plat.is_tunnel(i)}
            self.assertEqual({"0.0.0.0/1", "128.0.0.0/1"} & halves,
                             {"0.0.0.0/1", "128.0.0.0/1"}, macos)

    def test_linux_destinations_are_already_expanded(self):
        self.assertEqual(str(plat.expand_dest("128.0.0.0/1", macos=False)), "128.0.0.0/1")
        self.assertEqual(str(plat.expand_dest("default", macos=False)), "0.0.0.0/0")
        self.assertIsNone(plat.expand_dest("bogus", macos=False))

    def test_route_get_both_ways(self):
        bsd = plat.parse_route_get("""   route to: 1.1.1.1
destination: 1.0.0.0
       mask: 255.0.0.0
    gateway: 172.19.0.1
  interface: utun5
""", macos=True)
        self.assertEqual(bsd["interface"], "utun5")
        self.assertEqual(bsd["gateway"], "172.19.0.1")
        linux = plat.parse_route_get(
            "1.1.1.1 via 192.168.1.1 dev eth0 src 192.168.1.5 uid 1000", macos=False)
        self.assertEqual(linux["interface"], "eth0")
        self.assertEqual(linux["gateway"], "192.168.1.1")
        self.assertEqual(linux["source"], "192.168.1.5")

    def test_addresses_both_ways(self):
        bsd = plat.parse_addresses("""lo0: flags=8049<UP> mtu 16384
\tinet 127.0.0.1 netmask 0xff000000
en1: flags=8863<UP> mtu 1500
\tinet 172.30.36.17 netmask 0xfffffc00 broadcast 172.30.39.255
utun5: flags=8051<UP> mtu 1399
\tinet 172.19.0.1 --> 172.19.0.1 netmask 0xffffffff
""", macos=True)
        self.assertEqual(bsd, {"lo0": "127.0.0.1", "en1": "172.30.36.17",
                               "utun5": "172.19.0.1"})
        linux = plat.parse_addresses(
            "1: lo    inet 127.0.0.1/8 scope host lo\n"
            "2: eth0    inet 192.168.1.5/24 brd 192.168.1.255 scope global eth0\n"
            "3: tun0    inet 10.8.0.2/24 scope global tun0\n", macos=False)
        self.assertEqual(linux, {"lo": "127.0.0.1", "eth0": "192.168.1.5",
                                 "tun0": "10.8.0.2"})

    def test_dns_both_ways(self):
        self.assertEqual(plat.parse_dns(
            "resolver #1\n  nameserver[0] : 192.168.20.14\n"
            "  nameserver[1] : 192.168.20.15\n", macos=True),
            ["192.168.20.14", "192.168.20.15"])
        self.assertEqual(plat.parse_dns("""Global
       Protocols: -LLMNR
  resolv.conf mode: stub

Link 2 (eth0)
    DNS Servers: 192.168.1.1 1.1.1.1
         DNS Domain: lan
""", macos=False), ["1.1.1.1", "192.168.1.1"])
        self.assertEqual(plat.parse_resolv_conf(
            "# comment\nnameserver 1.1.1.1\nnameserver 8.8.8.8\nsearch lan\n"),
            ["1.1.1.1", "8.8.8.8"])

    def test_route_commands_per_platform(self):
        host = ipaddress.ip_network("203.0.113.4/32")
        net = ipaddress.ip_network("203.0.113.0/24")
        self.assertEqual(plat.add_route_command(host, "192.0.2.1", macos=True),
                         ["route", "-n", "add", "-host", "203.0.113.4", "192.0.2.1"])
        self.assertEqual(plat.add_route_command(net, "192.0.2.1", macos=True),
                         ["route", "-n", "add", "-net", "203.0.113.0",
                          "-netmask", "255.255.255.0", "192.0.2.1"])
        self.assertEqual(plat.add_route_command(net, "192.0.2.1", macos=False),
                         ["ip", "route", "replace", "203.0.113.0/24", "via", "192.0.2.1"])
        self.assertEqual(plat.add_tunnel_route_command(net, "tun0", macos=False),
                         ["ip", "route", "replace", "203.0.113.0/24", "dev", "tun0"])
        self.assertEqual(plat.delete_route_command(net, macos=False),
                         ["ip", "route", "del", "203.0.113.0/24"])
        # `ip route replace` adds or changes, so Linux needs no separate change.
        self.assertEqual(plat.change_route_command(net, "192.0.2.1", macos=False),
                         plat.add_route_command(net, "192.0.2.1", macos=False))
        self.assertNotEqual(plat.change_route_command(net, "192.0.2.1", macos=True),
                            plat.add_route_command(net, "192.0.2.1", macos=True))

    def test_route_outcomes_are_recognised_on_both(self):
        for text in ("add net 203.0.113.0: gateway 192.0.2.1: File exists",
                     "RTNETLINK answers: File exists"):
            self.assertTrue(plat.route_exists(text), text)
        for text in ("delete net 203.0.113.0: not in table",
                     "RTNETLINK answers: No such process"):
            self.assertTrue(plat.route_absent(text), text)
        self.assertFalse(plat.route_exists("ok"))
        self.assertFalse(plat.route_absent("ok"))


class TestPlatformSockets(unittest.TestCase):
    LSOF = ("COMMAND  PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME\n"
            "dota2   5123 amin   50u  IPv4 0x1234     0t0  UDP "
            "172.30.36.17:52000->155.133.250.1:27017\n"
            "sshd     900 root    3u  IPv4 0x1236     0t0  TCP *:22 (LISTEN)\n")
    SS = ("Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n"
          "udp   ESTAB 0      0      172.30.36.17:52000 155.133.250.1:27017 "
          'users:(("dota2",pid=5123,fd=50))\n'
          "tcp   LISTEN 0     128    0.0.0.0:22         0.0.0.0:* "
          'users:(("sshd",pid=900,fd=3))\n')

    def test_both_tools_give_the_same_peer(self):
        want = ("dota2", 5123, "UDP", "172.30.36.17:52000", "155.133.250.1:27017")
        self.assertIn(want, plat.parse_sockets(self.LSOF, "lsof"))
        self.assertIn(want, plat.parse_sockets(self.SS, "ss"))

    def test_listeners_are_not_peers(self):
        # lsof drops them for want of "->"; ss keeps 0.0.0.0:*, which is not routable.
        self.assertEqual([r[0] for r in plat.parse_sockets(self.LSOF, "lsof")], ["dota2"])
        self.assertFalse(netinfo._routable("0.0.0.0"))

    def test_ss_rows_without_a_process_are_skipped(self):
        self.assertEqual(plat.parse_sockets(
            "tcp ESTAB 0 0 10.0.0.1:1 10.0.0.2:443\n", "ss"), [])


class TestSecretStore(unittest.TestCase):
    def test_file_store_round_trip(self):
        import tempfile as tf
        from unittest import mock
        from ocpanel import keychain as kc
        path = pathlib.Path(tf.mkdtemp()) / "secrets.json"
        with mock.patch.object(plat, "secret_store", lambda: "file"), \
             mock.patch.object(kc, "_secrets_path", lambda: path):
            self.assertTrue(kc.save("a@b", "hunter2")[0])
            self.assertEqual(kc.load("a@b"), "hunter2")
            self.assertTrue(kc.has("a@b"))
            self.assertIsNone(kc.load("missing"))
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)   # private to its owner
            self.assertTrue(kc.forget("a@b")[0])
            self.assertFalse(kc.forget("a@b")[0])
            self.assertFalse(kc.encrypted())                       # and the panel says so

    def test_keyring_commands_run_as_the_invoking_user(self):
        from unittest import mock
        from ocpanel import keychain as kc
        import types
        with mock.patch.object(kc, "_invoking_user", lambda: "someone"), \
             mock.patch.object(plat, "MACOS", False), \
             mock.patch.object(kc.pwd, "getpwnam",
                               lambda n: types.SimpleNamespace(pw_uid=1000)), \
             mock.patch.dict(os.environ, {}, clear=True):
            cmd = kc._as_user(["secret-tool", "lookup"])
        self.assertEqual(cmd[:3], ["sudo", "-u", "someone"])
        self.assertIn("XDG_RUNTIME_DIR=/run/user/1000", cmd)
        self.assertIn("env", cmd)                   # not `sudo VAR=...`, sudoers may refuse
        self.assertIn("DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus", cmd)

    def test_macos_needs_no_session_bus(self):
        from unittest import mock
        from ocpanel import keychain as kc
        with mock.patch.object(kc, "_invoking_user", lambda: "someone"), \
             mock.patch.object(plat, "MACOS", True):
            self.assertEqual(kc._as_user(["security", "find-generic-password"]),
                             ["sudo", "-u", "someone", "security",
                              "find-generic-password"])
