#!/usr/bin/env python3
"""
tools/test_plugin.py — the plugin's own unit checks, run by CI after
tools/verify.py. Loads plugin.py with importlib against a stub `jen`
package and fake Flask/flask_login modules so nothing here needs Jen, a
database, or a network; every check exercises a PURE function of the
plugin with hand-built inputs, structurally comparing MQTT packet
bytes against the verified OASIS spec (a byte-range assertion per
field, not one giant hex literal — lower risk of a hand-transcription
error while still checking every byte's meaning), plus an end-to-end
call of register(app) against a stub jen.plugin_api (the Q89 lesson).

Run: `python3 tools/test_plugin.py` (exit 1 on the first failing check).
"""

import importlib.util
import os
import re
import sys
import types

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _stub_modules():
    """Enough of flask / flask_login for plugin.py to import."""
    flask = types.ModuleType("flask")

    class Blueprint:
        def __init__(self, *a, **k):
            pass

        def route(self, *a, **k):
            def deco(fn):
                return fn

            return deco

        def add_url_rule(self, *a, **k):
            pass

    flask.Blueprint = Blueprint
    for name in ("flash", "jsonify", "make_response", "redirect", "render_template", "url_for"):
        setattr(flask, name, lambda *a, **k: None)
    flask.request = None
    sys.modules["flask"] = flask
    fl = types.ModuleType("flask_login")
    fl.current_user = types.SimpleNamespace(username="tester", all_subnets=True, role="admin")
    fl.login_required = lambda fn: fn
    sys.modules["flask_login"] = fl


class _FakeApp:
    def register_blueprint(self, bp):
        pass


def _stub_normalize_mac(raw):
    """Same contract as jen/services/plugin_helpers.py::normalize_mac — a MAC as lowercase
    colon-separated, or None for anything that isn't twelve hex digits once separators are
    dropped."""
    if not isinstance(raw, str) or not raw.strip():
        return None
    cleaned = re.sub(r"[^0-9a-fA-F]", "", raw).lower()
    if len(cleaned) != 12:
        return None
    return ":".join(cleaned[i : i + 2] for i in range(0, 12, 2))


def _stub_jen_plugin_api():
    """A stub `jen`/`jen.plugin_api` sufficient for register(app) to run
    end to end, with register_row_action enforcing the same 'surface
    must be one of SURFACES' rule Jen's real one does. Returns the
    list every register_row_action() call is recorded into."""
    row_action_calls = []
    _SURFACES = ("lease", "reservation", "device")

    def register_row_action(plugin_id, surface, **kwargs):
        if surface not in _SURFACES:
            raise ValueError(f"surface must be one of {_SURFACES}, got {surface!r}")
        row_action_calls.append((plugin_id, surface, kwargs))

    def register_periodic(plugin_id, name, fn, every_minutes):
        if every_minutes < 5:
            raise ValueError("every_minutes must be at least 5")

    jen_pkg = types.ModuleType("jen")
    plugin_api = types.ModuleType("jen.plugin_api")
    plugin_api.register_row_action = register_row_action
    plugin_api.register_periodic = register_periodic
    plugin_api.subscribe = lambda kind, fn: SUBSCRIBED.append(kind)
    plugin_api.normalize_mac = _stub_normalize_mac
    jen_pkg.plugin_api = plugin_api
    sys.modules["jen"] = jen_pkg
    sys.modules["jen.plugin_api"] = plugin_api
    return row_action_calls


def load_plugin():
    _stub_modules()
    spec = importlib.util.spec_from_file_location("presence_plugin", os.path.join(ROOT, "plugin.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


failures = []
SUBSCRIBED = []  # every kind register() subscribed to


def check(cond, msg):
    if cond:
        print(f"ok    {msg}")
    else:
        failures.append(msg)
        print(f"FAIL  {msg}")


def main():
    p = load_plugin()
    _stub_jen_plugin_api()

    # ── Remaining Length encoding (OASIS §2.2.3) ─────────────────────────────
    check(p.encode_remaining_length(0) == b"\x00", "encode_remaining_length: 0")
    check(p.encode_remaining_length(127) == b"\x7f", "encode_remaining_length: 127, the largest single-byte value")
    check(
        p.encode_remaining_length(128) == b"\x80\x01",
        "encode_remaining_length: 128 needs a second byte, continuation bit set on the first",
    )
    check(
        p.encode_remaining_length(16383) == b"\xff\x7f",
        "encode_remaining_length: 16383, the largest two-byte value",
    )

    # ── UTF-8 string encoding (OASIS §1.5.3) ──────────────────────────────────
    check(p.encode_utf8_string("MQTT") == b"\x00\x04MQTT", "encode_utf8_string: length-prefixed, no terminator")
    check(p.encode_utf8_string("") == b"\x00\x00", "encode_utf8_string: an empty string is a zero length prefix")

    # ── CONNECT packet (OASIS §3.1), structural byte-range checks ────────────
    packet = p.build_connect_packet("jen", keep_alive=60)
    check(packet[0] == 0x10, "CONNECT: fixed header type byte is 0x10")
    check(packet[1] == 15, f"CONNECT: remaining length is 15 for client id 'jen', no auth (got {packet[1]})")
    check(packet[2:4] == b"\x00\x04", "CONNECT: protocol name length prefix is 4")
    check(packet[4:8] == b"MQTT", "CONNECT: protocol name is literally 'MQTT'")
    check(packet[8] == 0x04, "CONNECT: protocol level byte is 0x04 (v3.1.1)")
    check(packet[9] == 0x02, f"CONNECT: connect flags are clean-session-only (0x02), no auth (got {packet[9]:#04x})")
    check(packet[10:12] == (60).to_bytes(2, "big"), "CONNECT: keep alive is big-endian 60")
    check(packet[12:14] == b"\x00\x03", "CONNECT: client id length prefix is 3")
    check(packet[14:17] == b"jen", "CONNECT: client id payload bytes are 'jen'")
    check(len(packet) == 17, f"CONNECT: total length is 2 (fixed header) + 15 (remaining) = 17 (got {len(packet)})")

    with_auth = p.build_connect_packet("jen", username="bob", password="secret", keep_alive=30)
    check(
        with_auth[9] == 0xC2,
        f"CONNECT: username+password+clean-session flags are 0x80|0x40|0x02=0xC2 (got {with_auth[9]:#04x})",
    )
    check(with_auth[10:12] == (30).to_bytes(2, "big"), "CONNECT: keep alive is big-endian 30")
    # client id (2+3) + username (2+3) + password (2+6) = 18 bytes of payload after a 10-byte variable header
    check(with_auth[12:17] == b"\x00\x03jen", "CONNECT: client id field, with auth present")
    check(with_auth[17:22] == b"\x00\x03bob", "CONNECT: username field follows the client id")
    check(with_auth[22:30] == b"\x00\x06secret", "CONNECT: password field follows the username")
    check(len(with_auth) == 30, f"CONNECT with auth: total length is 30 (got {len(with_auth)})")

    # ── PUBLISH packet at QoS 0 (OASIS §3.3) ──────────────────────────────────
    pub = p.build_publish_packet("jen/presence/aa-bb", b"online", retain=False)
    check(pub[0] == 0x30, f"PUBLISH: fixed header is 0x30 (QoS 0, DUP 0, no retain) (got {pub[0]:#04x})")
    check(pub[1] == 2 + len("jen/presence/aa-bb") + len(b"online"), "PUBLISH: remaining length covers topic + payload")
    check(pub[2:4] == (len("jen/presence/aa-bb")).to_bytes(2, "big"), "PUBLISH: topic name length prefix")
    check(pub[-6:] == b"online", "PUBLISH: the payload is the raw bytes, un-length-prefixed, at the very end")

    pub_retained = p.build_publish_packet("t", b"x", retain=True)
    check(pub_retained[0] == 0x31, f"PUBLISH: retain=True sets bit 0 -> 0x31 (got {pub_retained[0]:#04x})")

    # ── DISCONNECT packet (OASIS §3.14) ───────────────────────────────────────
    check(p.build_disconnect_packet() == b"\xe0\x00", "DISCONNECT: fixed, 2-byte packet, no variable header/payload")

    # ── MQTT URL parsing ───────────────────────────────────────────────────────
    check(
        p.parse_mqtt_url("mqtt://mosquitto.local:1883")
        == {"host": "mosquitto.local", "port": 1883, "use_tls": False, "username": None, "password": None},
        "parse_mqtt_url: plain mqtt:// with an explicit port",
    )
    check(
        p.parse_mqtt_url("mqtts://mqtt.example.com")
        == {"host": "mqtt.example.com", "port": 8883, "use_tls": True, "username": None, "password": None},
        "parse_mqtt_url: mqtts:// defaults to port 8883",
    )
    check(
        p.parse_mqtt_url("mqtt://user@host") is not None and p.parse_mqtt_url("mqtt://user@host")["username"] == "user",
        "parse_mqtt_url: a username in the URI is captured",
    )
    check(p.parse_mqtt_url("mqtt://") is None, "parse_mqtt_url: no hostname is refused, not guessed")
    check(p.parse_mqtt_url("http://host") is None, "parse_mqtt_url: a non-mqtt scheme is refused")
    check(p.parse_mqtt_url("") is None, "parse_mqtt_url: an empty string is refused")

    # ── neighbour-table parsing (the same shape Network Discovery reads) ─────
    neigh_text = (
        "10.0.0.5 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE\n"
        "10.0.0.6 dev eth0 lladdr 11:22:33:44:55:66 STALE\n"
        "10.0.0.7 dev eth0 lladdr 77:88:99:aa:bb:cc DELAY\n"
        "10.0.0.8 dev eth0  FAILED\n"
    )
    seen = p.parse_neighbor_table(neigh_text)
    check(seen.get("aa:bb:cc:dd:ee:ff") is True, "parse_neighbor_table: REACHABLE is seen")
    check(
        seen.get("11:22:33:44:55:66") is False,
        "parse_neighbor_table: STALE is NOT seen (stricter than Discovery's own definition)",
    )
    check(seen.get("77:88:99:aa:bb:cc") is True, "parse_neighbor_table: DELAY is seen")
    check("FAILED" not in seen, "parse_neighbor_table: a line with no lladdr contributes nothing")

    # ── the offline debounce state machine ────────────────────────────────────
    state, misses, transitioned = p.next_presence_state("offline", 0, True)
    check(
        (state, misses, transitioned) == ("online", 0, True),
        "next_presence_state: any sighting flips offline -> online at once",
    )
    state, misses, transitioned = p.next_presence_state("online", 0, False)
    check(
        (state, misses, transitioned) == ("online", 1, False),
        "next_presence_state: a lone miss does not flip online early",
    )
    state, misses, transitioned = p.next_presence_state("online", 1, False)
    check(
        (state, misses, transitioned) == ("online", 2, False),
        "next_presence_state: a second miss still doesn't flip it",
    )
    state, misses, transitioned = p.next_presence_state("online", 2, False)
    check(
        (state, misses, transitioned) == ("offline", 3, True),
        "next_presence_state: the third consecutive miss flips it offline",
    )
    state, misses, transitioned = p.next_presence_state("offline", 9, False)
    check(
        (state, misses, transitioned) == ("offline", 10, False),
        "next_presence_state: staying offline never re-transitions",
    )
    state, misses, transitioned = p.next_presence_state("online", 0, True)
    check(
        (state, misses, transitioned) == ("online", 0, False),
        "next_presence_state: already online + seen is not a transition",
    )

    # ── sink payload/topic builders ────────────────────────────────────────────
    check(
        p.mqtt_state_topic("jen/presence", "aa:bb:cc:dd:ee:ff") == "jen/presence/aa-bb-cc-dd-ee-ff",
        "mqtt_state_topic: colons become dashes",
    )
    check(
        p.mqtt_attributes_topic("jen/presence", "aa:bb:cc:dd:ee:ff") == "jen/presence/aa-bb-cc-dd-ee-ff/attributes",
        "mqtt_attributes_topic: the state topic plus /attributes",
    )
    check(
        p.mqtt_discovery_topic("aa:bb:cc:dd:ee:ff") == "homeassistant/device_tracker/jen_aabbccddeeff/config",
        "mqtt_discovery_topic: the standard HA discovery topic shape",
    )
    disc = p.mqtt_discovery_payload("aa:bb:cc:dd:ee:ff", "Phone", "jen/presence")
    check(
        disc["payload_home"] == "online" and disc["payload_not_home"] == "offline",
        "mqtt_discovery_payload: payload_home/not_home match what this plugin actually publishes, not HA's defaults",
    )
    check(
        disc["state_topic"] == "jen/presence/aa-bb-cc-dd-ee-ff",
        "mqtt_discovery_payload: state_topic matches mqtt_state_topic exactly",
    )

    # ── topic prefix validation (v1.0.3) ──────────────────────────────────────
    check(p._valid_topic_prefix("jen/presence") is True, "_valid_topic_prefix: a normal prefix is accepted")
    check(p._valid_topic_prefix("jen/#") is False, "_valid_topic_prefix: the '#' wildcard is refused")
    check(p._valid_topic_prefix("jen/+/x") is False, "_valid_topic_prefix: the '+' wildcard is refused")
    check(p._valid_topic_prefix("jen presence") is False, "_valid_topic_prefix: a space is refused")
    check(p._valid_topic_prefix("") is False, "_valid_topic_prefix: empty is refused")

    payload = p.build_sink_payload("aa:bb:cc:dd:ee:ff", "Phone", True, "2026-09-24T00:00:00+00:00", "10.0.0.5", "phone")
    check(
        payload
        == {
            "mac": "aa:bb:cc:dd:ee:ff",
            "label": "Phone",
            "online": True,
            "since": "2026-09-24T00:00:00+00:00",
            "ip": "10.0.0.5",
            "hostname": "phone",
        },
        f"build_sink_payload: the exact JSON body every HTTP sink gets (got {payload})",
    )

    # ── MAC normalisation ─────────────────────────────────────────────────────
    check(p._normalize_mac("AA:BB:CC:DD:EE:FF") == "aa:bb:cc:dd:ee:ff", "_normalize_mac: uppercase colon form")
    check(p._normalize_mac("not-a-mac") == "", "_normalize_mac: garbage is refused, not raised")

    # ── _current_ip_hostname / _current_ip_hostname_bulk: expiry + ordering (v1.0.3) ─────
    class _KeaDB:
        def __init__(self, rows):
            self.rows = rows
            self.statements = []

        def cursor(self):
            return self

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def execute(self, sql, params=()):
            self.statements.append((sql, params))

        def fetchone(self):
            return self.rows[0] if self.rows else None

        def fetchall(self):
            return self.rows

        def close(self):
            pass

    kdb = _KeaDB([{"ip": "10.1.0.5", "hostname": "phone"}])
    p._get_kea_db = lambda: kdb
    ip, hostname = p._current_ip_hostname("aa:bb:cc:dd:ee:01")
    check((ip, hostname) == ("10.1.0.5", "phone"), "_current_ip_hostname: still returns the lease's ip/hostname")
    check(
        "expire > NOW()" in kdb.statements[0][0] and "ORDER BY expire DESC" in kdb.statements[0][0],
        f"_current_ip_hostname: not-past-expiry and newest-first, same rule as _has_active_lease (got {kdb.statements[0][0]!r})",
    )

    check(p._current_ip_hostname_bulk([]) == {}, "_current_ip_hostname_bulk: no MACs, no query at all")
    kdb = _KeaDB(
        [
            # aa:...:01 has two active leases; ORDER BY expire DESC means the FIRST row per MAC wins
            {"mac_hex": "AABBCCDDEE01", "ip": "10.1.0.9", "hostname": "newest"},
            {"mac_hex": "AABBCCDDEE01", "ip": "10.1.0.5", "hostname": "older"},
            {"mac_hex": "AABBCCDDEE02", "ip": "10.1.0.6", "hostname": "phone2"},
        ]
    )
    p._get_kea_db = lambda: kdb
    got = p._current_ip_hostname_bulk(["aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02", "aa:bb:cc:dd:ee:03"])
    check(
        got == {"aa:bb:cc:dd:ee:01": ("10.1.0.9", "newest"), "aa:bb:cc:dd:ee:02": ("10.1.0.6", "phone2")},
        f"_current_ip_hostname_bulk: ONE query for every MAC, the newest lease per MAC, a MAC with none is absent (got {got})",
    )
    check(
        len(kdb.statements) == 1,
        f"_current_ip_hostname_bulk: exactly one query for three MACs (got {len(kdb.statements)})",
    )
    kdb2 = _KeaDB([])
    kdb2.cursor = lambda: (_ for _ in ()).throw(RuntimeError("down"))
    p._get_kea_db = lambda: kdb2
    check(
        p._current_ip_hostname_bulk(["aa:bb:cc:dd:ee:01"]) == {},
        "_current_ip_hostname_bulk: an unreadable lease table degrades to an empty map, never raises",
    )

    # ── write gate — viewers can look at Presence but not change it ─────────
    p.current_user.role = "viewer"
    check(p._is_admin() is False, "a viewer is not admin")
    check(p._require_write() is False, "a viewer cannot write")
    for fn, args in (
        (p.track, ()),
        (p.untrack, ("aa:bb:cc:dd:ee:ff",)),
        (p.track_from_row, ()),
        (p.add_sink, ()),
        (p.toggle_sink, (1,)),
        (p.delete_sink, (1,)),
        (p.test_sink, (1,)),
    ):
        try:
            fn(*args)
            gated = True
        except Exception:
            gated = False
        check(gated, f"{fn.__name__} refuses a viewer before touching the request")
    p.current_user.role = "admin"
    check(p._is_admin() is True, "admin role restored for the rest of the run")

    # ── 1.0.1: parse_mqtt_url — a bad port is a refusal, not a 500 ───────────
    for bad in ("mqtt://host:abc", "mqtt://host:99999", "mqtt://host:0", "mqtts://host:-1"):
        try:
            got = p.parse_mqtt_url(bad)
            raised = False
        except Exception:
            got, raised = "raised", True
        check(got is None and not raised, f"parse_mqtt_url: {bad!r} returns None instead of raising")
    check(p.parse_mqtt_url("mqtt://host:65535")["port"] == 65535, "parse_mqtt_url: the largest valid port")
    check(
        p.parse_mqtt_url("mqtt://bob:s3cret@host")["password"] == "s3cret",
        "parse_mqtt_url: a password in the URL is returned",
    )
    check(
        p.strip_url_password("mqtt://bob:s3cret@host:1883/x") == "mqtt://bob@host:1883/x",
        "strip_url_password: the password leaves the URL, the user name stays",
    )
    check(
        p.strip_url_password("mqtt://bob@host") == "mqtt://bob@host",
        "strip_url_password: a URL without a password is unchanged",
    )
    check(
        p.strip_url_password("mqtts://:pw@host") == "mqtts://host",
        "strip_url_password: a password with no user name leaves a bare host",
    )

    # ── 1.0.1: URL schemes and the MQTT credential pair ──────────────────────
    check(p.valid_http_url("https://ha.local:8123/api/webhook/x") is True, "valid_http_url: https is accepted")
    check(p.valid_http_url("http://10.0.0.5/hook") is True, "valid_http_url: http is accepted")
    for bad in ("file:///etc/passwd", "ftp://host/x", "javascript:alert(1)", "//host/x", "http://", ""):
        check(p.valid_http_url(bad) is False, f"valid_http_url: {bad!r} is refused")
    try:
        p.build_connect_packet("jen", username=None, password="pw")
        refused = False
    except ValueError:
        refused = True
    check(
        refused,
        "build_connect_packet: a password without a user name is refused (MQTT-3.1.2-22), not sent with the flag unset",
    )
    check(
        len(p.mqtt_client_id("aa:bb:cc:dd:ee:ff")) <= 23,
        "mqtt_client_id: within the 23 characters every broker must accept",
    )
    check(
        p.mqtt_client_id("aa:bb:cc:dd:ee:ff") == "jen-pr-aabbccddeeff",
        "mqtt_client_id: stable and derived from the MAC",
    )
    disc = p.mqtt_discovery_payload("aa:bb:cc:dd:ee:ff", "Phone", "jen/presence")
    check(
        disc["json_attributes_topic"] == p.mqtt_attributes_topic("jen/presence", "aa:bb:cc:dd:ee:ff"),
        "mqtt_discovery_payload: json_attributes_topic points at the attributes topic",
    )

    # ── 1.0.1: which devices can the neighbour table see at all ──────────────
    ip_addr_out = (
        "1: lo    inet 127.0.0.1/8 scope host lo\n"
        "2: eth0    inet 10.1.0.5/24 brd 10.1.0.255 scope global eth0\n"
        "3: docker0    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0\n"
        "4: eth1    inet6 fe80::1/64 scope link\n"
    )
    nets = p.parse_interface_networks(ip_addr_out)
    check(
        [str(n) for n in nets] == ["10.1.0.0/24", "172.17.0.0/16"],
        f"parse_interface_networks: the host's own IPv4 subnets, loopback and v6 skipped (got {[str(n) for n in nets]})",
    )
    check(
        p.parse_interface_networks("") == [] and p.parse_interface_networks("garbage") == [],
        "parse_interface_networks: nothing parseable is an empty list",
    )
    check(p.mac_is_local("10.1.0.77", None, nets) is True, "mac_is_local: an address on an interface subnet is local")
    check(
        p.mac_is_local("10.2.0.77", "10.1.0.0/24", nets) is False,
        "mac_is_local: a current address elsewhere wins over a stale stored subnet",
    )
    check(
        p.mac_is_local(None, "10.1.0.0/24", nets) is True, "mac_is_local: with no address, the device's subnet decides"
    )
    check(
        p.mac_is_local(None, "10.2.0.0/24", nets) is False,
        "mac_is_local: a subnet the host has no interface on is not local",
    )
    check(p.mac_is_local(None, None, nets) is False, "mac_is_local: nothing known is not local")

    # ── a fake database and request, to run the impure routes ────────────────
    class FakeDB:
        def __init__(self, selects=None):
            self.statements = []
            self.selects = list(selects or [])

        def cursor(self):
            return self

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def execute(self, sql, params=()):
            self.statements.append((sql.split()[0].upper(), sql, params))

        def fetchone(self):
            return self.selects.pop(0) if self.selects else None

        def fetchall(self):
            return self.selects.pop(0) if self.selects else []

        def commit(self):
            pass

        def close(self):
            pass

        def kinds(self):
            return [s[0] for s in self.statements]

    only_one = lambda sid: sid == 1  # noqa: E731 - a subnet-restricted caller: subnet 1; None is not theirs
    everything = lambda sid: True  # noqa: E731 - an unrestricted caller
    flashed = []
    p.flash = lambda msg, cat="message": flashed.append(msg)
    p.redirect = lambda where: "redirect"
    p.url_for = lambda *a, **k: "/x"
    p._require_write = lambda: True
    mac_subnet = {"aa:bb:cc:dd:ee:01": 1, "aa:bb:cc:dd:ee:02": 2}
    p._current_subnet_for_mac = lambda mac: mac_subnet.get(mac)

    # ── 1.0.1: sinks are superadmin-only, on every sink route ────────────────
    p.current_user.role = "admin"
    p.request = types.SimpleNamespace(form={"name": "x", "kind": "http", "url": "http://192.0.2.1/x"}, args={})
    p._get_db = lambda: (_ for _ in ()).throw(AssertionError("the database was touched"))
    for fn, args in ((p.add_sink, ()), (p.toggle_sink, (1,)), (p.delete_sink, (1,)), (p.test_sink, (1,))):
        flashed.clear()
        check(
            fn(*args) == "redirect" and flashed and "superadmin" in flashed[-1],
            f"{fn.__name__}: an admin who is not a superadmin is refused before any database access",
        )
    p.current_user.role = "superadmin"
    check(p._is_superadmin() is True, "a superadmin passes the sink gate")
    p.current_user.role = "admin"

    # ── 1.0.1: adding a sink validates URL, scheme and the credential pair ───
    p.current_user.role = "superadmin"
    cases = (
        ("an http sink with a file:// URL", {"name": "x", "kind": "http", "url": "file:///etc/passwd"}, False),
        ("an MQTT sink with a bad port", {"name": "x", "kind": "mqtt", "url": "mqtt://host:abc"}, False),
        (
            "an MQTT password with no user name",
            {"name": "x", "kind": "mqtt", "url": "mqtt://host:1883", "credential": "pw"},
            False,
        ),
        ("an MQTT URL password with no user name", {"name": "x", "kind": "mqtt", "url": "mqtt://:pw@host:1883"}, False),
        ("a good webhook", {"name": "x", "kind": "ha_webhook", "url": "https://ha.local/api/webhook/x"}, True),
        ("a good MQTT sink", {"name": "x", "kind": "mqtt", "url": "mqtt://bob@host:1883", "credential": "pw"}, True),
        (
            "a topic prefix with a wildcard '#'",
            {"name": "x", "kind": "http", "url": "http://192.0.2.1/x", "topic_prefix": "jen/#"},
            False,
        ),
        (
            "a topic prefix with a wildcard '+'",
            {"name": "x", "kind": "http", "url": "http://192.0.2.1/x", "topic_prefix": "jen/+/x"},
            False,
        ),
        (
            "a topic prefix with a space",
            {"name": "x", "kind": "http", "url": "http://192.0.2.1/x", "topic_prefix": "jen presence"},
            False,
        ),
    )
    jen_api = types.ModuleType("jen.plugin_api")
    jen_api.encrypt_secret = lambda s: "enc:" + s
    jen_api.normalize_mac = _stub_normalize_mac
    sys.modules["jen"] = types.ModuleType("jen")
    sys.modules["jen.plugin_api"] = jen_api
    sys.modules["jen"].plugin_api = jen_api
    for label, form, should_store in cases:
        fdb = FakeDB()
        p._get_db = lambda fdb=fdb: fdb
        p.request = types.SimpleNamespace(form=form, args={})
        p.add_sink()
        check(
            ("INSERT" in fdb.kinds()) == should_store,
            f"add_sink: {label} is {'stored' if should_store else 'refused, nothing stored'}",
        )
    fdb = FakeDB()
    p._get_db = lambda: fdb
    p.request = types.SimpleNamespace(form={"name": "x", "kind": "mqtt", "url": "mqtt://bob:s3cret@host:1883"}, args={})
    p.add_sink()
    stored = [s for s in fdb.statements if s[0] == "INSERT"][0][2]
    check(
        stored[2] == "mqtt://bob@host:1883" and stored[3] == "enc:s3cret",
        f"add_sink: a password typed into the URL is moved to the encrypted credential (got url={stored[2]!r}, credential={stored[3]!r})",
    )
    p.current_user.role = "admin"

    # ── 1.0.1: tracking takes the subnet from the MAC and authorises the existing row ─
    p._can = only_one
    for label, mac, existing in (
        ("a MAC in subnet 2", "aa:bb:cc:dd:ee:02", None),
        ("a MAC Jen has never seen", "aa:bb:cc:dd:ee:99", None),
        (
            "a MAC already tracked in subnet 2 (a hidden device), whose current subnet is now subnet 1",
            "aa:bb:cc:dd:ee:01",
            {"mac": "aa:bb:cc:dd:ee:01", "subnet_id": 2},
        ),
    ):
        fdb = FakeDB([existing])
        p._get_db = lambda fdb=fdb: fdb
        p.request = types.SimpleNamespace(form={"mac": mac, "label": "hijack", "ip": "10.1.0.5"}, args={})
        p.track()
        check("INSERT" not in fdb.kinds(), f"track: {label} is refused, nothing written")
    fdb = FakeDB([None])
    p._get_db = lambda: fdb
    p.request = types.SimpleNamespace(form={"mac": "aa:bb:cc:dd:ee:01", "label": "Phone", "ip": "10.2.0.5"}, args={})
    p.track()
    ins = [s for s in fdb.statements if s[0] == "INSERT"]
    check(
        len(ins) == 1 and ins[0][2][2] == 1,
        "track: a new device is stored on the MAC's own subnet (1), whatever address was typed",
    )
    check(
        "subnet_id=VALUES" not in ins[0][1], "track: the upsert can only change the label — it never rewrites subnet_id"
    )
    fdb = FakeDB([{"mac": "aa:bb:cc:dd:ee:01", "subnet_id": 1}])
    p._get_db = lambda: fdb
    p.track()
    ins = [s for s in fdb.statements if s[0] == "INSERT"]
    check(
        len(ins) == 1 and ins[0][2][2] == 1, "track: re-tracking an accessible device keeps its subnet and relabels it"
    )

    # ── 1.0.1: track-row ignores the query-string subnet ─────────────────────
    fdb = FakeDB([None])
    p._get_db = lambda: fdb
    p.request = types.SimpleNamespace(
        form={}, args={"mac": "aa:bb:cc:dd:ee:02", "subnet_id": "1", "hostname": "hijack"}
    )
    p.track_from_row()
    check(
        "INSERT" not in fdb.kinds(),
        "track_from_row: a MAC in subnet 2 is refused even though the query string names subnet 1",
    )
    fdb = FakeDB([None])
    p._get_db = lambda: fdb
    p.request = types.SimpleNamespace(form={}, args={"mac": "aa:bb:cc:dd:ee:01", "subnet_id": "2", "hostname": "Phone"})
    p.track_from_row()
    ins = [s for s in fdb.statements if s[0] == "INSERT"]
    check(
        len(ins) == 1 and ins[0][2][2] == 1,
        "track_from_row: the stored subnet is the MAC's own (1), not the one in the URL (2)",
    )

    # ── 1.0.1: untrack is judged on the row ──────────────────────────────────
    for label, row, can, deleted in (
        (
            "a device in subnet 2, for a caller scoped to subnet 1",
            {"mac": "aa:bb:cc:dd:ee:02", "subnet_id": 2},
            only_one,
            False,
        ),
        (
            "a device with no subnet, for a scoped caller",
            {"mac": "aa:bb:cc:dd:ee:02", "subnet_id": None},
            only_one,
            False,
        ),
        ("a device in the caller's own subnet", {"mac": "aa:bb:cc:dd:ee:01", "subnet_id": 1}, only_one, True),
        (
            "a device with no subnet, for an unrestricted caller",
            {"mac": "aa:bb:cc:dd:ee:02", "subnet_id": None},
            everything,
            True,
        ),
    ):
        fdb = FakeDB([row])
        p._get_db = lambda fdb=fdb: fdb
        p._can = can
        p.untrack(row["mac"])
        check(("DELETE" in fdb.kinds()) == deleted, f"untrack: {label} is {'removed' if deleted else 'not removed'}")

    # ── 1.0.1: a renewal is not a transition ─────────────────────────────────
    applied = []
    p._apply_transition = lambda mac, online: applied.append((mac, online))
    p._tracked_macs = lambda: {"aa:bb:cc:dd:ee:01"}
    p._has_active_lease = lambda mac: False
    p._refresh_subnet = lambda mac: None
    for recorded, kind, expect in (
        (True, "lease.new", []),
        (False, "lease.new", [("aa:bb:cc:dd:ee:01", True)]),
        (None, "lease.new", [("aa:bb:cc:dd:ee:01", True)]),
        (False, "lease.expired", []),
        (True, "lease.expired", [("aa:bb:cc:dd:ee:01", False)]),
    ):
        applied.clear()
        p._recorded_online = lambda mac, recorded=recorded: recorded
        p._on_lease_event({"mac": "AA:BB:CC:DD:EE:01", "kind": kind})
        check(applied == expect, f"_on_lease_event: {kind} for a device recorded {recorded} -> {expect}")

    # ── 1.0.2: the lease path follows the client ─────────────────────────────
    # (a) lease.ip_changed is now handled: the client is present at a new address
    applied.clear()
    p._recorded_online = lambda mac: False
    p._on_lease_event({"mac": "aa:bb:cc:dd:ee:01", "kind": "lease.ip_changed"})
    check(applied == [("aa:bb:cc:dd:ee:01", True)], "_on_lease_event: lease.ip_changed brings an offline device online")
    # (b) lease.expired is offline ONLY when no active lease remains
    for has_lease, expect in ((True, []), (False, [("aa:bb:cc:dd:ee:01", False)])):
        applied.clear()
        p._recorded_online = lambda mac: True
        p._has_active_lease = lambda mac, has_lease=has_lease: has_lease
        p._on_lease_event({"mac": "aa:bb:cc:dd:ee:01", "kind": "lease.expired"})
        check(applied == expect, f"_on_lease_event: lease.expired with another active lease={has_lease} -> {expect}")
    # (c) the subnet is refreshed on every handled event, even when nothing transitions
    refreshed = []
    p._refresh_subnet = lambda mac: refreshed.append(mac)
    p._recorded_online = lambda mac: True
    p._has_active_lease = lambda mac: True
    p._on_lease_event({"mac": "aa:bb:cc:dd:ee:01", "kind": "lease.new"})
    p._on_lease_event({"mac": "aa:bb:cc:dd:ee:01", "kind": "lease.expired"})
    check(
        len(refreshed) == 2,
        "_on_lease_event: pr_tracked.subnet_id is refreshed on every handled event, transition or not",
    )
    refreshed.clear()
    p._on_lease_event({"mac": "aa:bb:cc:dd:ee:77", "kind": "lease.new"})
    check(refreshed == [], "_on_lease_event: an untracked MAC is ignored entirely")
    # the REAL functions, on a fresh load (the tests above replaced several on `p`)
    fresh = load_plugin()

    # the move A -> B: the stored subnet follows the client
    fresh._current_subnet_for_mac = lambda mac: 2
    fdb = FakeDB()
    fresh._get_db = lambda: fdb
    fresh._refresh_subnet("aa:bb:cc:dd:ee:01")
    upd = [s for s in fdb.statements if s[0] == "UPDATE"]
    check(
        len(upd) == 1 and upd[0][2][0] == 2 and "pr_tracked" in upd[0][1],
        "_refresh_subnet: a client that moved to subnet 2 is re-filed under subnet 2",
    )
    fresh._current_subnet_for_mac = lambda mac: None
    fdb = FakeDB()
    fresh._get_db = lambda: fdb
    fresh._refresh_subnet("aa:bb:cc:dd:ee:01")
    check(fdb.statements == [], "_refresh_subnet: a MAC with no known subnet keeps its last one")

    # the two-leases case: one of two leases ending leaves the device online
    for n, expect in ((2, True), (1, True), (0, False)):
        kfdb = FakeDB([{"n": n}])
        fresh._get_kea_db = lambda kfdb=kfdb: kfdb
        check(
            fresh._has_active_lease("aa:bb:cc:dd:ee:01") is expect,
            f"_has_active_lease: {n} active lease(s) -> {expect}",
        )
        check(
            "expire > NOW()" in kfdb.statements[0][1],
            "_has_active_lease: active means state 0 AND not past its expiry - Jen's own definition",
        )
    kfdb = FakeDB()
    kfdb.cursor = lambda: (_ for _ in ()).throw(RuntimeError("down"))
    fresh._get_kea_db = lambda: kfdb
    check(
        fresh._has_active_lease("aa:bb:cc:dd:ee:01") is False,
        "_has_active_lease: an unreadable lease table falls back to 'no other lease'",
    )

    # the subnet comes from Jen's ONE precedence
    jen_api = types.ModuleType("jen.plugin_api")
    jen_api.client_subnet_for_mac = lambda mac: {"aa:bb:cc:dd:ee:09": 4}.get(mac)
    jen_api.normalize_mac = _stub_normalize_mac
    sys.modules["jen"] = types.ModuleType("jen")
    sys.modules["jen.plugin_api"] = jen_api
    sys.modules["jen"].plugin_api = jen_api
    check(
        load_plugin()._current_subnet_for_mac("aa:bb:cc:dd:ee:09") == 4
        and load_plugin()._current_subnet_for_mac("aa:bb:cc:dd:ee:10") is None,
        "_current_subnet_for_mac: answered by plugin_api.client_subnet_for_mac, not a private copy",
    )

    # ── 1.0.1: the test button publishes nothing durable ─────────────────────
    published = []
    p._mqtt_publish = lambda info, user, pw, cid, messages: published.append((cid, messages))
    sink = {
        "kind": "mqtt",
        "url": "mqtt://bob@host:1883",
        "credential": None,
        "topic_prefix": "jen/presence",
        "retain": 1,
        "discovery": 1,
    }
    p._send_to_sink(sink, "aa:bb:cc:dd:ee:ff", "Test device", True, "2026-09-25T00:00:00+00:00", None, None, test=True)
    cid, messages = published[0]
    check(
        len(messages) == 1 and messages[0][0] == "jen/presence/test" and messages[0][2] is False,
        f"_send_to_sink(test): ONE non-retained message on <prefix>/test, no discovery, nothing on the device topics (got {[(m[0], m[2]) for m in messages]})",
    )
    check(len(cid) <= 23, "_send_to_sink(test): the client id fits 23 characters")
    published.clear()
    p._send_to_sink(sink, "aa:bb:cc:dd:ee:ff", "Phone", True, "2026-09-25T00:00:00+00:00", None, None)
    topics = [m[0] for m in published[0][1]]
    check(
        topics[0].startswith("homeassistant/device_tracker/") and len(topics) == 3,
        f"_send_to_sink: a real transition still publishes discovery + state + attributes (got {topics})",
    )
    posted = []
    p._http_post_json = lambda url, body, bearer=None: posted.append((url, body, bearer))
    jen_api.decrypt_secret = lambda s: "token"
    p._send_to_sink(
        {"kind": "ha_webhook", "url": "https://ha/x", "credential": "enc"},
        "aa:bb:cc:dd:ee:ff",
        "T",
        True,
        "s",
        None,
        None,
        test=True,
    )
    check(
        posted[0][2] == "token" and posted[0][1].get("test") is True,
        "_send_to_sink: a webhook sink now sends its bearer token, and a test body is marked test",
    )

    # ── 1.0.1: the neighbour pass only counts misses for hosts on its own segments ─
    transitions = []
    p._tracked_macs = lambda: {"aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"}
    p._ip_binary = lambda: "ip"
    p._local_networks = lambda ip_bin: nets
    p._tracked_subnets = lambda: {"aa:bb:cc:dd:ee:01": 1, "aa:bb:cc:dd:ee:02": 2}
    p._subnet_map = lambda: {1: {"cidr": "10.1.0.0/24"}, 2: {"cidr": "10.2.0.0/24"}}
    p._current_ip_hostname_bulk = lambda macs: {}

    class _Result:
        returncode = 0
        stdout = ""  # nobody answers: every LOCAL device misses

    p.subprocess = types.SimpleNamespace(run=lambda *a, **k: _Result(), TimeoutExpired=Exception)
    fdb = FakeDB([[{"mac": "aa:bb:cc:dd:ee:01", "online": 1, "misses": 2}]])
    p._get_db = lambda: fdb
    p._apply_transition = lambda mac, online: transitions.append((mac, online))
    p._neighbor_tick()
    check(
        transitions == [("aa:bb:cc:dd:ee:01", False)],
        f"_neighbor_tick: the device on the host's own segment goes offline after its third miss, the one behind a router is never judged (got {transitions})",
    )
    state_reads = [s for s in fdb.statements if s[0] == "SELECT"]
    check(
        len(state_reads) == 1 and state_reads[0][2] == ("aa:bb:cc:dd:ee:01",),
        "_neighbor_tick: only the local device's state is read at all",
    )
    transitions.clear()
    p._local_networks = lambda ip_bin: None
    fdb = FakeDB()
    p._get_db = lambda: fdb
    p._neighbor_tick()
    check(
        transitions == [] and fdb.statements == [],
        "_neighbor_tick: when the host's own subnets cannot be read, the pass counts nothing",
    )
    rows = [{"mac": "aa:bb:cc:dd:ee:01"}, {"mac": "aa:bb:cc:dd:ee:02"}]
    p._local_networks = lambda ip_bin: nets
    marked = p._mark_lease_based([dict(r) for r in rows])
    check(
        [r["lease_based"] for r in marked] == [False, True],
        "the page marks the device behind a router 'lease-based' and leaves the local one alone",
    )
    p._local_networks = lambda ip_bin: None
    check(
        all(r["lease_based"] is None for r in p._mark_lease_based([dict(r) for r in rows])),
        "the page says nothing when it cannot tell",
    )

    # ── register(): runs end to end against a stub jen.plugin_api ───────────
    row_action_calls = _stub_jen_plugin_api()
    try:
        p.register(_FakeApp())
        registered = True
    except Exception as e:
        registered = False
        print(f"      register() raised: {e}")
    check(registered, "register(): runs end to end without raising against a real-rule stub")
    check(
        sorted(SUBSCRIBED) == ["lease.expired", "lease.ip_changed", "lease.new"],
        f"register(): subscribes to lease.new, lease.expired AND lease.ip_changed (got {sorted(SUBSCRIBED)})",
    )
    surfaces = sorted(c[1] for c in row_action_calls)
    check(
        surfaces == ["device", "lease"],
        f"register(): a Track presence row action is registered on lease + device only, not reservation (got {surfaces})",
    )
    check(
        p._publish_thread is None,
        "register(): the publish worker is never started here — only lazily, on the first transition",
    )

    # ── the publish worker (v1.0.3): a bounded queue, its own thread, started lazily ─────
    fresh = load_plugin()
    sent = []
    fresh._send_to_sink = lambda sink, mac, label, online, since_iso, ip, hostname: sent.append(
        (sink["name"], mac, online)
    )
    fresh._record_sink_error = lambda sid, err: None
    fresh._queue_publish(
        {"id": 1, "name": "S"}, "aa:bb:cc:dd:ee:01", "L", True, "2026-09-27T00:00:00+00:00", None, None
    )
    fresh._publish_queue.join()
    check(
        sent == [("S", "aa:bb:cc:dd:ee:01", True)],
        f"_queue_publish: the plugin's own worker thread actually calls _send_to_sink (got {sent})",
    )
    check(
        fresh._publish_thread is not None and fresh._publish_thread.is_alive(),
        "_queue_publish: the worker thread is running (daemon, started on demand)",
    )
    sent.clear()
    fresh._queue_publish({"id": 1, "name": "S2"}, "aa:bb:cc:dd:ee:02", "L2", False, "iso", None, None)
    fresh._publish_queue.join()
    check(
        sent == [("S2", "aa:bb:cc:dd:ee:02", False)],
        "_queue_publish: a second transition reuses the same worker instead of starting another",
    )

    # ── 1.0.4 (Q101 c, system scenario 13): a successful send clears a sink's last_error ──
    cleared = []
    failed = []
    fresh._clear_sink_error = lambda sid: cleared.append(sid)
    fresh._record_sink_error = lambda sid, err: failed.append((sid, err))
    fresh._send_to_sink = lambda *a, **k: (_ for _ in ()).throw(fresh._PresenceError("broker unreachable"))
    fresh._queue_publish({"id": 7, "name": "Flaky"}, "aa:bb:cc:dd:ee:04", "L4", True, "iso", None, None)
    fresh._publish_queue.join()
    check(
        failed == [(7, "broker unreachable")] and cleared == [],
        f"_queue_publish: a failed send records the error and does NOT clear it (got failed={failed}, cleared={cleared})",
    )
    fresh._send_to_sink = lambda *a, **k: None  # the broker recovered
    fresh._queue_publish({"id": 7, "name": "Flaky"}, "aa:bb:cc:dd:ee:04", "L4", True, "iso", None, None)
    fresh._publish_queue.join()
    check(
        cleared == [7],
        f"_queue_publish: a successful send clears the sink's last_error - it used to stay stuck forever once set (got {cleared})",
    )

    # a full queue drops the update and logs, rather than blocking the caller
    fresh._publish_thread = types.SimpleNamespace(is_alive=lambda: True)  # _ensure_publish_worker short-circuits
    full_q = fresh.queue.Queue(maxsize=1)
    full_q.put_nowait(("dummy",))
    fresh._publish_queue = full_q
    warnings = []
    fresh.logger = types.SimpleNamespace(
        warning=lambda msg: warnings.append(msg), error=lambda msg: None, info=lambda msg: None
    )
    fresh._queue_publish({"id": 1, "name": "Full"}, "aa:bb:cc:dd:ee:03", "L3", True, "iso", None, None)
    check(
        full_q.qsize() == 1 and any("full" in w for w in warnings),
        f"_queue_publish: a full queue drops the update and logs a warning instead of blocking (got warnings={warnings})",
    )

    # ── _mqtt_publish: a refused/unreachable connect raises _PresenceError, not a bare OSError ──
    fresh = load_plugin()
    fresh.socket = types.SimpleNamespace(
        create_connection=lambda *a, **k: (_ for _ in ()).throw(ConnectionRefusedError("refused"))
    )
    try:
        fresh._mqtt_publish({"host": "h", "port": 1883, "use_tls": False}, None, None, "cid", [])
        caught = None
    except Exception as e:
        caught = e
    check(
        isinstance(caught, fresh._PresenceError),
        f"_mqtt_publish: a connection failure (create_connection, not just the CONNECT itself) raises _PresenceError (got {type(caught).__name__ if caught else None})",
    )

    # ── test_sink: only a _PresenceError is a caller-visible 'Test failed'; a real bug is not ──
    fresh = load_plugin()
    fresh.current_user.role = "superadmin"
    ts_flashed = []
    fresh.flash = lambda msg, cat="message": ts_flashed.append(msg)
    fresh.redirect = lambda where: "redirect"
    fresh.url_for = lambda *a, **k: "/x"
    sink_row = {
        "id": 1,
        "name": "Sink1",
        "kind": "http",
        "url": "http://x",
        "credential": None,
        "topic_prefix": "jen/presence",
        "retain": 0,
        "discovery": 0,
    }
    fdb = FakeDB([sink_row])
    fresh._get_db = lambda: fdb
    fresh._send_to_sink = lambda *a, **k: (_ for _ in ()).throw(fresh._PresenceError("broker unreachable"))
    ts_recorded = []
    fresh._record_sink_error = lambda sid, err: ts_recorded.append((sid, err))
    fresh.test_sink(1)
    check(
        bool(ts_flashed) and "Test failed" in ts_flashed[-1] and ts_recorded == [(1, "broker unreachable")],
        f"test_sink: a _PresenceError is caught, flashed and recorded (got flashed={ts_flashed}, recorded={ts_recorded})",
    )
    fdb2 = FakeDB([sink_row])
    fresh._get_db = lambda: fdb2
    fresh._send_to_sink = lambda *a, **k: (_ for _ in ()).throw(KeyError("a bug, not a sink failure"))
    try:
        fresh.test_sink(1)
        propagated = False
    except KeyError:
        propagated = True
    except Exception:
        propagated = False
    check(
        propagated,
        "test_sink: a bug in _send_to_sink (KeyError, not _PresenceError) is NOT swallowed as 'Test failed' — it propagates",
    )

    # ── _existing_tracked: a DB failure degrades to 'no existing row', never an uncaught crash ──
    class _BadTrackedDB:
        def cursor(self):
            raise RuntimeError("db down")

        def close(self):
            pass

    fresh._get_db = lambda: _BadTrackedDB()
    check(
        fresh._existing_tracked("aa:bb:cc:dd:ee:01") is None,
        "_existing_tracked: a DB failure degrades to None instead of propagating uncaught",
    )

    if failures:
        print(f"\n{len(failures)} check(s) failed")
        return 1
    print("\nall plugin checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
