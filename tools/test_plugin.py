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

import functools
import importlib.util
import math
import os
import pathlib
import random
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


# The role gate the real jen.plugin_api provides (`is_admin_or_above`, `is_superadmin`, `require_write`), reading the
# stub current_user's role LIVE so a check can flip it. plugin.py imports them at the top, so they must exist before it
# is loaded. A refusal is recorded (message, endpoint) and the route is not run, which is what the real decorator does
# for a page request: flash, redirect, never touch the request.
GATE_REFUSALS = []


def _gate_is_admin_or_above():
    return getattr(sys.modules["flask_login"].current_user, "role", None) in ("superadmin", "admin")


def _gate_is_superadmin():
    return getattr(sys.modules["flask_login"].current_user, "role", None) == "superadmin"


def _gate_require_write(message="Viewers can look at this but not change it.", redirect_endpoint="dashboard.dashboard"):
    def deco(fn):
        @functools.wraps(fn)
        def wrapped(*a, **k):
            if _gate_is_admin_or_above():
                return fn(*a, **k)
            GATE_REFUSALS.append((message, redirect_endpoint))
            return "refused"

        return wrapped

    return deco


def _install_gate_api(plugin_api=None):
    """Put the gate functions on the stub jen.plugin_api (creating the stub package when none exists yet)."""
    if plugin_api is None:
        plugin_api = sys.modules.get("jen.plugin_api")
        if plugin_api is None:
            jen_pkg = types.ModuleType("jen")
            plugin_api = types.ModuleType("jen.plugin_api")
            jen_pkg.plugin_api = plugin_api
            sys.modules["jen"] = jen_pkg
            sys.modules["jen.plugin_api"] = plugin_api
    plugin_api.is_admin_or_above = _gate_is_admin_or_above
    plugin_api.is_superadmin = _gate_is_superadmin
    plugin_api.require_write = _gate_require_write


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
    plugin_api.register_investigation_provider = lambda *a, **k: INVESTIGATION_CALLS.append((a, k))
    plugin_api.normalize_mac = _stub_normalize_mac
    plugin_api.ACTIVE_LEASE4 = "state = 0 AND expire > NOW()"
    _install_gate_api(plugin_api)
    jen_pkg.plugin_api = plugin_api
    sys.modules["jen"] = jen_pkg
    sys.modules["jen.plugin_api"] = plugin_api
    return row_action_calls


def load_plugin():
    _stub_modules()
    _install_gate_api()
    spec = importlib.util.spec_from_file_location("presence_plugin", os.path.join(ROOT, "plugin.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


failures = []
SUBSCRIBED = []  # every kind register() subscribed to
INVESTIGATION_CALLS = []  # every register_investigation_provider() call


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
    try:
        p._current_ip_hostname_bulk(["aa:bb:cc:dd:ee:01"], strict=True)
        strict_raised = False
    except p._LeaseLookupFailed:
        strict_raised = True
    check(
        strict_raised,
        "_current_ip_hostname_bulk (BG2): asked strictly, an unreadable lease table raises _LeaseLookupFailed, not an empty map",
    )
    check(
        p._current_ip_hostname_bulk([], strict=True) == {},
        "_current_ip_hostname_bulk (BG2): asked strictly about no MACs, the answer is still an empty map and no query",
    )

    # ── write gate — viewers can look at Presence but not change it ─────────
    p.current_user.role = "viewer"
    check(p.is_admin_or_above() is False, "a viewer is not admin")
    for fn, args in (
        (p.track, ()),
        (p.untrack, ("aa:bb:cc:dd:ee:ff",)),
        (p.move_subnet, ("aa:bb:cc:dd:ee:ff",)),
        (p.track_from_row, ()),
    ):
        del GATE_REFUSALS[:]
        try:
            got = fn(*args)
            gated = got == "refused"
        except Exception:
            gated = False
        check(gated, f"{fn.__name__} refuses a viewer before touching the request")
        check(
            GATE_REFUSALS == [("Viewers can look at Presence but not change it.", "presence.index")],
            f"{fn.__name__}: the viewer is told the plugin's own sentence and sent to the Presence page (got {GATE_REFUSALS})",
        )
    for fn, args in (
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
    check(p.is_admin_or_above() is True, "admin role restored for the rest of the run")
    check(
        all(fn.__name__ == fn.__wrapped__.__name__ for fn in (p.track, p.untrack, p.move_subnet, p.track_from_row)),
        "the four write routes carry the plugin_api require_write decorator (functools.wraps)",
    )
    src = pathlib.Path(ROOT, "plugin.py").read_text(encoding="utf-8")
    check(
        "def _is_admin" not in src and "def _require_write" not in src and "def _is_superadmin" not in src,
        "plugin.py no longer carries its own copies of the admin check, the superadmin check or the write gate",
    )

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
        def __init__(self, selects=None, hook=None):
            self.statements = []
            self.selects = list(selects or [])
            self.rowcount = 1
            self.rolled_back = 0
            self.hook = (
                hook  # called with (db, kind, sql, params) after the statement is recorded; may raise or set rowcount
            )

        def cursor(self):
            return self

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def execute(self, sql, params=()):
            kind = sql.split()[0].upper()
            self.statements.append((kind, sql, params))
            self.rowcount = 1
            if self.hook:
                self.hook(self, kind, sql, params)

        def rollback(self):
            self.rolled_back += 1

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
    check(p.is_superadmin() is True, "a superadmin passes the sink gate")
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
    jen_api.ACTIVE_LEASE4 = "state = 0 AND expire > NOW()"
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
    check("ON DUPLICATE" not in ins[0][1], "track: a new device is a plain INSERT, never an upsert (1.2.2)")
    fdb = FakeDB([{"mac": "aa:bb:cc:dd:ee:01", "subnet_id": 1}])
    p._get_db = lambda: fdb
    p.track()
    upd = [s for s in fdb.statements if s[0] == "UPDATE"]
    check(
        len(upd) == 1
        and upd[0][2] == ("Phone", "aa:bb:cc:dd:ee:01", 1)
        and "INSERT" not in fdb.kinds()
        and "subnet_id=%s" not in upd[0][1].split("WHERE")[0],
        "track: re-tracking an accessible device keeps its subnet and relabels it - under the judged owner, never setting subnet_id",
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
    # (c) v1.2.0: a lease event updates STATE only - the owner subnet is never re-filed under the client's current one
    check(
        not hasattr(p, "_refresh_subnet"),
        "_refresh_subnet is deleted: no code path re-files a tracking under the client's current subnet",
    )
    applied.clear()
    p._on_lease_event({"mac": "aa:bb:cc:dd:ee:77", "kind": "lease.new"})
    check(applied == [], "_on_lease_event: an untracked MAC is ignored entirely")
    # the REAL functions, on a fresh load (the tests above replaced several on `p`)
    fresh = load_plugin()
    lease_p = load_plugin()  # its own copy: the checks below keep using `fresh` with its real functions
    # the client has moved to subnet 2; a lease event of every kind must leave pr_tracked alone
    lease_p._current_subnet_for_mac = lambda mac: 2
    owner_fdb = FakeDB()
    lease_p._get_db = lambda: owner_fdb
    lease_p._tracked_macs = lambda: {"aa:bb:cc:dd:ee:01"}
    lease_p._recorded_online = lambda mac: None
    lease_p._has_active_lease = lambda mac: False
    moved_applied = []
    lease_p._apply_transition = lambda mac, online: moved_applied.append((mac, online))
    for kind in ("lease.new", "lease.ip_changed", "lease.expired"):
        lease_p._on_lease_event({"mac": "aa:bb:cc:dd:ee:01", "kind": kind})
    check(
        len(moved_applied) == 3 and owner_fdb.statements == [],
        f"_on_lease_event: three lease events for a client now in subnet 2 change state and write NOTHING to the database (got {owner_fdb.statements})",
    )

    # ── 1.2.0: ownership and location are separate ───────────────────────────
    import ipaddress as _ip

    names = {1: {"name": "A", "cidr": "10.1.0.0/24"}, 2: {"name": "B", "cidr": "10.2.0.0/24"}}
    real_is_admin, real_mark = p.is_admin_or_above, p._mark_lease_based
    p._subnet_map = lambda: names
    p._mark_lease_based = lambda rows: rows
    p.is_admin_or_above = lambda: False
    p.render_template = lambda name, **kw: kw
    owned_b = {
        "mac": "aa:bb:cc:dd:ee:01",
        "label": "tv",
        "subnet_id": 2,
        "online": True,
        "since": None,
        "last_seen": None,
    }
    p._tracked_rows = lambda: [dict(owned_b)]
    p._current_subnet_for_mac = lambda mac: 1  # tracked in B, and the client has since moved to A
    for label, can, expected in (
        ("an A-scoped caller", only_one, []),
        (
            "a B-scoped caller: the owner sees it, and is not told the client is in A",
            lambda sid: sid == 2,
            [("tv", "")],
        ),
        ("an unrestricted caller: sees it and where the client is now", everything, [("tv", "A (10.1.0.0/24)")]),
    ):
        p._can = can
        got = [(r["label"], r["now_in"]) for r in p.index()["rows"]]
        check(got == expected, f"index: tracked in B, client now in A - {label} gets {expected} (got {got})")
    p._can = only_one
    owned_a = dict(owned_b, mac="aa:bb:cc:dd:ee:02", label="phone", subnet_id=1)
    p._tracked_rows = lambda: [dict(owned_a)]
    p._current_subnet_for_mac = lambda mac: 2  # tracked in A, now in B
    page = p.index()
    check(
        [(r["label"], r["subnet_name"], r["now_in"]) for r in page["rows"]] == [("phone", "A", "")],
        "index: tracked in A, client now in B - an A caller keeps it, filed under A, with no word of B",
    )
    p.is_admin_or_above = lambda: True
    p._sink_rows = list
    p._candidate_hosts = list
    p._can = lambda sid: sid in (1, 2)
    check(
        [c["id"] for c in p.index()["move_choices"]] == [1, 2],
        "index: an admin is offered the subnets they can see as move targets",
    )
    p._can = only_one
    check(
        [c["id"] for c in p.index()["move_choices"]] == [1],
        "index: ...and only those (a scoped admin is not offered B)",
    )
    p.is_admin_or_above, p._mark_lease_based = real_is_admin, real_mark

    # the explicit move: both subnets in scope, audited, and nothing else changes the owner subnet
    check(
        p.move_refusal(2, 1, only_one, names) == "Device not found."
        and p.move_refusal(None, 1, only_one, names) == "Device not found."
        and p.move_refusal(1, 2, only_one, names) == "That subnet is not available to you."
        and p.move_refusal(1, 99, everything, names) == "That subnet is not available to you."
        and p.move_refusal(1, None, everything, names) == "That subnet is not available to you."
        and p.move_refusal(1, 1, only_one, names) == "That device already belongs to that subnet."
        and p.move_refusal(1, 2, lambda s: s in (1, 2), names) == ""
        and p.move_refusal(None, 1, everything, names) == "",
        "move_refusal: both subnets must be the caller's, the target must be a known subnet, and a no-op is not a move",
    )
    audits = []
    p._audit = lambda action, target, detail: audits.append((action, target, detail))
    for label, can, owner, target, moved in (
        ("both subnets in scope", lambda sid: sid in (1, 2), 1, "2", True),
        ("a caller scoped to A moving A's device to B", only_one, 1, "2", False),
        ("a caller scoped to B, the device owned by A", lambda sid: sid == 2, 1, "2", False),
        ("a target that is not a number", everything, 1, "x", False),
        ("a target Jen does not know", everything, 1, "77", False),
    ):
        audits.clear()
        fdb = FakeDB([{"mac": "aa:bb:cc:dd:ee:01", "subnet_id": owner}])
        p._get_db = lambda fdb=fdb: fdb
        p._can = can
        p.request = types.SimpleNamespace(form={"subnet_id": target}, args={})
        p.move_subnet("aa:bb:cc:dd:ee:01")
        updates = [s for s in fdb.statements if s[0] == "UPDATE"]
        check(
            bool(updates) == moved and (updates[0][2] == (2, "aa:bb:cc:dd:ee:01", owner) if moved else True),
            f"move_subnet: {label} -> {'moved' if moved else 'refused, nothing written'} (got {fdb.kinds()})",
        )
        check(
            (audits == [("PRESENCE_MOVE", "aa:bb:cc:dd:ee:01", "subnet_id 1 -> 2")]) == moved
            and (moved or audits == []),
            f"move_subnet: {label} -> {'one audit row naming both subnets' if moved else 'no audit row'} (got {audits})",
        )
    fdb = FakeDB([None])
    p._get_db = lambda fdb=fdb: fdb
    p._can = everything
    p.request = types.SimpleNamespace(form={"subnet_id": "2"}, args={})
    p.move_subnet("aa:bb:cc:dd:ee:01")
    check("UPDATE" not in fdb.kinds(), "move_subnet: a device that is not tracked is not found")
    p.request = None

    # the neighbour pass asks where the device is NOW; the owner subnet is only the last resort
    p._tracked_subnets = lambda: {"aa:bb:cc:dd:ee:01": 2}
    p._current_ip_hostname_bulk = lambda macs: dict.fromkeys(macs, (None, None))
    nets = [_ip.IPv4Network("10.1.0.0/24")]
    p._current_subnet_for_mac = lambda mac: 1
    check(
        p._local_macs({"aa:bb:cc:dd:ee:01"}, nets) == {"aa:bb:cc:dd:ee:01"},
        "_local_macs: a device owned by subnet 2 that is NOW in the Jen host's own subnet 1 is local",
    )
    p._current_subnet_for_mac = lambda mac: None
    check(
        p._local_macs({"aa:bb:cc:dd:ee:01"}, nets) == set(),
        "_local_macs: with no current subnet the owner subnet is the fallback (2: not local)",
    )

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
    p._current_ip_hostname_bulk = lambda macs, strict=False: {}

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
    # ── 1.2.6 (PR-1): a device the first read does not show is asked before it is a miss ─
    stale = "10.1.0.50 dev eth0 lladdr aa:bb:cc:dd:ee:01 STALE\n"
    reachable = "10.1.0.50 dev eth0 lladdr aa:bb:cc:dd:ee:01 REACHABLE\n"
    check(
        p.confirmed_macs(
            reachable
            + "10.1.0.51 dev eth0 lladdr aa:bb:cc:dd:ee:09 DELAY\n10.1.0.52 dev eth0 lladdr aa:bb:cc:dd:ee:08 PROBE\n"
        )
        == {"aa:bb:cc:dd:ee:01"},
        "confirmed_macs: after a probe only REACHABLE counts; DELAY and PROBE are a question with no answer yet",
    )
    check(
        p.confirmed_macs(stale + "10.1.0.60 dev eth0 FAILED\n") == set(),
        "confirmed_macs: STALE and FAILED confirm nothing",
    )

    def neighbor_pass(tables, leases, misses=2, sendable=True):
        """Run the real `_neighbor_tick` for one local device recorded online with `misses`: `tables` are the answers of `ip -4 neigh show`
        in call order, `leases` what `_current_ip_hostname_bulk` answers. Returns (transitions, statements, probed addresses, table reads)."""
        answers, probed, moved = list(tables), [], []
        m = load_plugin()  # its own copy: the checks after this block need the shared one's real functions

        class _Neigh:
            returncode = 0

            def __init__(self):
                self.stdout = answers.pop(0)

        m._tracked_macs = lambda: {"aa:bb:cc:dd:ee:01"}
        m._ip_binary = lambda: "ip"
        m._local_networks = lambda ip_bin: nets
        m._local_macs = lambda tracked, local_nets: set(tracked)
        m._current_ip_hostname_bulk = lambda macs, strict=False: dict(leases)
        m._send_probes = lambda addresses: (probed.extend(addresses), len(addresses) if sendable else 0)[1]
        m._PROBE_WAIT_S = 0
        m.subprocess = types.SimpleNamespace(run=lambda *a, **k: _Neigh(), TimeoutExpired=Exception)
        db = FakeDB([[{"mac": "aa:bb:cc:dd:ee:01", "online": 1, "misses": misses}]])
        m._get_db = lambda: db
        m._apply_transition = lambda mac, online: moved.append((mac, online))
        m._neighbor_tick()
        return moved, db.statements, probed, len(tables) - len(answers)

    lease = {"aa:bb:cc:dd:ee:01": ("10.1.0.50", "phone")}
    moved, statements, probed, reads = neighbor_pass([stale, reachable], lease)
    check(
        moved == [] and probed == ["10.1.0.50"] and reads == 2,
        f"_neighbor_tick (PR-1): a STALE device that answers the probe is not a miss and stays online (got {moved}, {probed}, {reads} reads)",
    )
    check(
        [st[2] for st in statements if st[0] == "UPDATE" and "misses" in st[1]] == [(0, "aa:bb:cc:dd:ee:01")],
        f"_neighbor_tick (PR-1): the answered probe puts the miss count back to 0 (got {[st for st in statements if st[0] == 'UPDATE']})",
    )
    moved, _statements, probed, reads = neighbor_pass([stale, stale], lease)
    check(
        moved == [("aa:bb:cc:dd:ee:01", False)] and probed == ["10.1.0.50"] and reads == 2,
        f"_neighbor_tick (PR-1): a device that does not answer is offline at its third miss, as before (got {moved})",
    )
    moved, _statements, probed, reads = neighbor_pass([stale], {})
    check(
        moved == [("aa:bb:cc:dd:ee:01", False)] and probed == [] and reads == 1,
        f"_neighbor_tick (PR-1): a device with no lease has no address to ask and is a miss as before (got {moved}, {probed}, {reads} reads)",
    )
    moved, statements, probed, reads = neighbor_pass([stale], lease, sendable=False)
    check(
        moved == [] and statements == [] and probed == ["10.1.0.50"] and reads == 1,
        f"_neighbor_tick (BH3): when nothing could be sent the table is not read again and the device takes no miss - 1.2.6 to 1.2.8 called it offline here (got {moved}, {reads} reads, {len(statements)} statements)",
    )
    moved, _statements, probed, reads = neighbor_pass([reachable], lease)
    check(
        moved == [] and probed == [] and reads == 1,
        "_neighbor_tick (PR-1): a device the first read shows is not asked",
    )
    probe_module = load_plugin()
    check(
        probe_module._send_probes(["127.0.0.1", "not an address"]) == 1,
        "_send_probes: the real function sends one datagram to an address and passes over one that is not",
    )
    check(
        (probe_module._PROBE_PORT, probe_module._PROBE_WAIT_S, probe_module._PROBE_MAX) == (9, 9, 64),
        "the probe goes to the discard port, waits nine seconds and asks at most 64 devices a pass",
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
    check(
        len(INVESTIGATION_CALLS) == 1
        and INVESTIGATION_CALLS[0][0] == ("presence",)
        and INVESTIGATION_CALLS[0][1]["fn"] is p._investigate,
        "register(): exactly one investigation provider, the plugin's own",
    )

    # ── 1.1.0: the investigation provider ────────────────────────────────────
    check(
        p.in_scope(1, [1], False) and not p.in_scope(2, [1], False) and not p.in_scope(None, [1], False),
        "in_scope: a restricted caller sees only its own subnets, and None is never allow",
    )
    check(p.in_scope(None, [], True), "in_scope: an unrestricted caller sees an unattributed MAC")
    check(p.investigation_card(None) is None, "investigation_card: a client that is not tracked adds no card")
    import datetime as _dt

    t1, t0 = _dt.datetime(2026, 10, 1, 8, 30), _dt.datetime(2026, 10, 1, 7, 0)
    tracked_on = {"label": "Phone", "subnet_id": 1, "online": 1, "since": t1, "last_seen": t1}
    card = p.investigation_card(tracked_on)
    check(
        card["summary"] == "Online since 2026-10-01 08:30 UTC" and card["status"] == "ok",
        f"investigation_card: an online device says since when (got {card['summary']!r})",
    )
    off = p.investigation_card(dict(tracked_on, online=0, since=t0, last_seen=t0))
    check(
        off["summary"] == "Offline, last seen 2026-10-01 07:00 UTC",
        f"investigation_card: an offline device says when it was last seen (got {off['summary']!r})",
    )
    fresh_row = p.investigation_card({"label": "", "subnet_id": 1, "online": None, "since": None, "last_seen": None})
    check("no state recorded yet" in fresh_row["summary"], "investigation_card: tracked but never judged says so")
    check(
        all(r["label"] != "Published to" for r in card["rows"]),
        "investigation_card: where it is published is withheld unless the caller may see sinks",
    )
    shown = p.investigation_card(tracked_on, ["HA", "Broker"])
    check(
        {"label": "Published to", "value": "HA, Broker"} in shown["rows"],
        "investigation_card: an admin sees the enabled sinks' names",
    )
    check(
        {"label": "Published to", "value": "no enabled destination"} in p.investigation_card(tracked_on, [])["rows"],
        "investigation_card: no enabled destination reads as such (1.2.9: the word a person reads for a sink)",
    )
    subject = types.SimpleNamespace(mac="AA:BB:CC:DD:EE:01")
    p._current_subnet_for_mac = lambda mac: 1
    p.is_admin_or_above = lambda: True
    fdb = FakeDB([dict(tracked_on)])
    p._get_db = lambda: fdb
    # the second FakeDB read (the sinks) needs its own answer: one DB object serves both queries in order
    fdb.selects.append([{"name": "HA"}])
    got = p._investigate(subject, [1], False)
    check(
        got is not None and got["href"] == "/management/presence" and "Online since" in got["summary"],
        f"_investigate: the card for a tracked client (got {got})",
    )
    check(
        {"label": "Published to", "value": "HA"} in got["rows"]
        and "pr_tracked t LEFT JOIN pr_state s" in fdb.statements[0][1]
        and fdb.statements[0][2] == ("aa:bb:cc:dd:ee:01",),
        "_investigate: an admin sees the sink names; the lookup is the one parameterised MAC query",
    )
    check(
        all("credential" not in s[1] and "url" not in s[1] for s in fdb.statements),
        "_investigate: the sinks query never reads a credential or an address",
    )
    p.is_admin_or_above = lambda: False
    p._get_db = lambda: FakeDB([dict(tracked_on)])
    check(
        all(r["label"] != "Published to" for r in p._investigate(subject, [1], False)["rows"]),
        "_investigate: a non-admin never sees the sinks",
    )
    p._get_db = lambda: FakeDB([None])
    check(p._investigate(subject, [1], False) is None, "_investigate: a client that is not tracked gets None")
    p._get_db = lambda: FakeDB([dict(tracked_on)])
    check(p._investigate(subject, [2], False) is None, "_investigate: a client outside the caller's set is None")
    # ── 1.1.1: a STORED tracked row is judged by its OWN subnet; where the client is now is only shown ──
    names = {1: {"name": "Servers", "cidr": "10.0.1.0/24"}, 2: {"name": "Lab", "cidr": "10.0.2.0/24"}}
    p._subnet_map = lambda: names
    check(
        p.subnet_label(1, names) == "Servers (10.0.1.0/24)"
        and p.subnet_label(9, names) == ""
        and p.subnet_label(3, {3: {"name": "", "cidr": "10.0.3.0/24"}}) == "10.0.3.0/24",
        "subnet_label: name and CIDR, the CIDR alone when unnamed, nothing for an unknown subnet",
    )
    check(
        p.now_in(2, 1, names, [1, 2], False) == "Lab (10.0.2.0/24)"
        and p.now_in(2, 1, names, [], True) == "Lab (10.0.2.0/24)",
        "now_in: the subnet the client is in now, when the caller may see it and it differs from the stored one",
    )
    check(
        p.now_in(2, 1, names, [1], False) == ""
        and p.now_in(1, 1, names, [1], False) == ""
        and p.now_in(None, 1, names, [1], False) == "",
        "now_in: nothing for a subnet the caller cannot see (naming it is access), an unchanged one, or an unknown one",
    )
    # the leak direction: tracked in B, the client has since moved to A - a caller scoped to A must NOT see what was stored in B
    p._current_subnet_for_mac = lambda mac: 1
    p._get_db = lambda: FakeDB([dict(tracked_on, subnet_id=2)])
    check(
        p._investigate(subject, [1], False) is None,
        "_investigate: a device tracked in B is not shown to a caller scoped to A because the client is now in A",
    )
    p._get_db = lambda: FakeDB([dict(tracked_on, subnet_id=2)])
    check(
        p._investigate(subject, [1, 2], False) is not None and p._investigate(subject, [], True) is not None,
        "_investigate: the same row is shown to a caller who may see B, and to an unrestricted one",
    )
    # the other direction: tracked in A, the client is now in B - A's caller sees the row, but is not told B
    p._current_subnet_for_mac = lambda mac: 2
    p._get_db = lambda: FakeDB([dict(tracked_on)])
    moved = p._investigate(subject, [1], False)
    check(
        moved is not None and all(r["label"] != "Now in" for r in moved["rows"]) and "Lab" not in str(moved),
        "_investigate: tracked in A and now in B, a caller scoped to A sees the row and no word of B",
    )
    p._get_db = lambda: FakeDB([dict(tracked_on)])
    both = p._investigate(subject, [1, 2], False)
    check(
        both is not None and {"label": "Now in", "value": "Lab (10.0.2.0/24)"} in both["rows"],
        "_investigate: a caller who may see both is told where the client is now",
    )
    p._current_subnet_for_mac = lambda mac: None  # no lease or reservation: nothing to add, the row still shows
    p._get_db = lambda: FakeDB([dict(tracked_on)])
    nothing_now = p._investigate(subject, [1], False)
    check(
        nothing_now is not None and all(r["label"] != "Now in" for r in nothing_now["rows"]),
        "_investigate: a client with no current subnet still shows its row, with no Now in row",
    )
    p._current_subnet_for_mac = lambda mac: 1
    p._get_db = lambda: FakeDB([dict(tracked_on)])
    check(
        all(r["label"] != "Now in" for r in p._investigate(subject, [1], False)["rows"]),
        "_investigate: a client still in the subnet it was tracked in has no Now in row",
    )
    p._get_db = lambda: FakeDB([dict(tracked_on, subnet_id=None)])
    check(
        p._investigate(subject, [1], False) is None and p._investigate(subject, [], True) is not None,
        "_investigate: a tracked row with no stored subnet is for an unrestricted caller only - even when the client is now in one",
    )
    check(
        p._investigate(types.SimpleNamespace(mac=""), [1], True) is None
        and p._investigate(types.SimpleNamespace(mac="nope"), [1], True) is None,
        "_investigate: a subject with no (or an invalid) MAC gets None",
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

    # ── _lock_tracked: three states - a row, None, or a FAILED lookup that raises _LookupFailed (never "absent") ──
    class _BadTrackedDB:
        def cursor(self):
            raise RuntimeError("db down")

        def close(self):
            pass

    fresh._get_db = lambda: _BadTrackedDB()
    try:
        fresh._open_txn()
        opened = True
    except fresh._LookupFailed:
        opened = False
    check(
        not opened,
        "_open_txn: not being able to reach the database is a FAILED lookup (not None, not a bare driver error)",
    )
    failing_cur = FakeDB(hook=lambda db, kind, sql, params: (_ for _ in ()).throw(RuntimeError("db down")))
    try:
        fresh._lock_tracked(failing_cur, "aa:bb:cc:dd:ee:01")
        locked = "returned"
    except fresh._LookupFailed:
        locked = "failed"
    check(locked == "failed", "_lock_tracked: a SELECT that raises is a FAILED lookup")
    check(
        fresh._lock_tracked(FakeDB([None]), "aa:bb:cc:dd:ee:01") is None,
        "_lock_tracked: a lookup that worked and found nothing is None",
    )
    locking = FakeDB([{"mac": "aa:bb:cc:dd:ee:01", "subnet_id": 2}])
    check(
        fresh._lock_tracked(locking, "aa:bb:cc:dd:ee:01") == {"mac": "aa:bb:cc:dd:ee:01", "subnet_id": 2}
        and "FOR UPDATE" in locking.statements[0][1],
        "_lock_tracked: a row that exists is the row, read FOR UPDATE",
    )

    # ── 1.2.1: three-state lookups. A hidden object, a client visible in A, the FIRST statement raising, every later write able to
    #    succeed: the route must refuse, write nothing, audit nothing ──
    class _FlakyOnce:
        """get_db() answers a database whose statements fail the first time, a working FakeDB every time after."""

        def __init__(self, selects):
            self.calls, self.dbs, self.selects = 0, [], selects

        def __call__(self):
            self.calls += 1
            if self.calls == 1:
                return _BadTrackedDB()
            db = FakeDB(list(self.selects))
            self.dbs.append(db)
            return db

        def kinds(self):
            return [k for db in self.dbs for k in db.kinds()]

    audits_h = []
    p._audit = lambda action, target, detail: audits_h.append((action, target, detail))
    p._can = only_one
    p._current_subnet_for_mac = lambda mac: 1  # the client is in A; the tracking is owned by B
    p.flash = lambda msg, cat="message": flashed.append(msg)
    for label, call, request in (
        ("track", lambda: p.track(), {"mac": "aa:bb:cc:dd:ee:01", "label": "hijack"}),
        ("track_from_row", lambda: p.track_from_row(), None),
        ("untrack", lambda: p.untrack("aa:bb:cc:dd:ee:01"), {}),
        ("move_subnet", lambda: p.move_subnet("aa:bb:cc:dd:ee:01"), {"subnet_id": "1"}),
    ):
        flaky = _FlakyOnce([{"mac": "aa:bb:cc:dd:ee:01", "subnet_id": 2}])
        p._get_db = flaky
        audits_h.clear()
        flashed.clear()
        if label == "track_from_row":
            p.request = types.SimpleNamespace(form={}, args={"mac": "aa:bb:cc:dd:ee:01", "hostname": "hijack"})
        else:
            p.request = types.SimpleNamespace(form=request, args={})
        call()
        writes = [k for k in flaky.kinds() if k in ("INSERT", "UPDATE", "DELETE")]
        check(
            writes == []
            and audits_h == []
            and flashed == ["Could not check the existing record — nothing was changed."],
            f"{label}: a failed existence lookup refuses, writes nothing and audits nothing (writes={writes}, audits={audits_h}, flashed={flashed})",
        )
    p.request = None

    # ── 1.2.2: judging and writing are ONE transaction. A row owned by B that appears or changes between the judgement and the write
    #    is never modified: the write is conditioned on the judged owner, the count is checked, a lost insert race is re-judged ──
    class _Err(Exception):
        pass

    def driver_error(code):
        err = _Err("driver")
        err.args = (code, "driver")
        return err

    def mutations(db):
        return [k for k in db.kinds() if k in ("INSERT", "UPDATE", "DELETE")]

    p._can = only_one  # an admin of subnet 1 (A); subnet 2 (B) is hidden from them
    p._current_subnet_for_mac = lambda mac: 1
    p._subnet_map = lambda: {1: {"name": "A", "cidr": "10.1.0.0/24"}, 2: {"name": "B", "cidr": "10.2.0.0/24"}}
    mac1 = "aa:bb:cc:dd:ee:01"

    def became_b(db, kind, sql, params):
        if kind in ("UPDATE", "DELETE"):
            db.rowcount = 0  # nothing matches "subnet_id <=> 1" any more
            db.selects[:] = [{"mac": mac1, "subnet_id": 2}]

    for label, call, form in (
        ("track", lambda: p.track(), {"mac": mac1, "label": "x"}),
        ("move_subnet", lambda: p.move_subnet(mac1), {"subnet_id": "2"}),
        ("untrack", lambda: p.untrack(mac1), {}),
    ):
        p._can = (lambda sid: sid in (1, 2)) if label == "move_subnet" else only_one
        race = FakeDB([{"mac": mac1, "subnet_id": 1}], hook=became_b)
        p._get_db = lambda race=race: race
        audits_h.clear()
        flashed.clear()
        p.request = types.SimpleNamespace(form=form, args={})
        call()
        check(
            flashed == [p.CHANGED_UNDERFOOT] and race.rolled_back >= 1 and audits_h == [],
            f"{label}: the row became B's between judge and write - refused, rolled back, nothing audited (flashed={flashed}, audits={audits_h})",
        )
        check(
            all("FOR UPDATE" in s[1] for s in race.statements if s[0] == "SELECT"),
            f"{label}: every SELECT that judges the row is FOR UPDATE",
        )
        check(
            all(
                "subnet_id <=> %s" in s[1]
                for s in race.statements
                if s[0] in ("UPDATE", "DELETE") and "pr_tracked" in s[1]
            ),
            f"{label}: every write to pr_tracked carries the judged owner as a predicate",
        )
    p._can = only_one
    # the label already is what is stored: MySQL counts 0 CHANGED rows, which is a success while the owner is unchanged
    same = FakeDB(
        [{"mac": mac1, "subnet_id": 1}],
        hook=lambda db, kind, sql, params: (
            (setattr(db, "rowcount", 0), db.selects.__setitem__(slice(None), [{"mac": mac1, "subnet_id": 1}]))
            if kind == "UPDATE"
            else None
        ),
    )
    p._get_db = lambda: same
    flashed.clear()
    audits_h.clear()
    p.request = types.SimpleNamespace(form={"mac": mac1, "label": "x"}, args={})
    p.track()
    check(
        flashed == ["Now tracking x."] and same.rolled_back == 0 and [a[0] for a in audits_h] == ["PRESENCE_TRACK"],
        f"track: re-saving the label it already has (0 changed rows) is still a success (flashed={flashed})",
    )

    # a new MAC: the INSERT loses the race (1062) to a B-owned row - the winner is locked and judged, never overwritten
    def lose(owner, code=1062):
        def hook(db, kind, sql, params):
            if kind == "INSERT":
                db.selects[:] = [{"mac": mac1, "subnet_id": owner}]
                raise driver_error(code)

        return hook

    lost = FakeDB([], hook=lose(2))
    p._get_db = lambda: lost
    flashed.clear()
    audits_h.clear()
    p.request = types.SimpleNamespace(form={"mac": mac1, "label": "hijack"}, args={})
    p.track()
    check(
        mutations(lost) == ["INSERT"] and flashed == [p.NOT_YOURS] and audits_h == [],
        f"track: lost the INSERT race to a B-owned row - judged again, refused, never UPDATEd (got {mutations(lost)}, {flashed})",
    )
    lost_a = FakeDB([], hook=lose(1))
    p._get_db = lambda: lost_a
    flashed.clear()
    p.track()
    check(
        mutations(lost_a) == ["INSERT", "UPDATE"]
        and lost_a.statements[-1][2][-1] == 1
        and flashed == ["Now tracking hijack."],
        f"track: lost the INSERT race to a row in the caller's own subnet - relabelled under the owner predicate (got {mutations(lost_a)})",
    )
    dead = FakeDB([], hook=lose(2, code=1213))
    p._get_db = lambda: dead
    flashed.clear()
    p.track()
    check(
        mutations(dead) == ["INSERT"] and dead.rolled_back >= 1 and flashed == [p.NOT_YOURS],
        f"track: a deadlocked INSERT is rolled back and the winner (B's) re-judged and refused (got {mutations(dead)}, {flashed})",
    )

    # ── 1.2.4: ONE refusal text for "a tracked row the caller may not see" and "a MAC in no subnet the caller may see", and it says
    #    nothing about the MAC. The same sentence for hidden and nonexistent: neither route tells which one it was. ──
    check(
        p.NOT_YOURS == "That tracked entry is not yours to change." and "MAC" not in p.NOT_YOURS,
        "NOT_YOURS: exactly the tracked-entry sentence, no claim about the MAC",
    )
    refusals = {}
    for label, now, row in (
        ("hidden row, client visible in A", 1, {"mac": mac1, "subnet_id": 2}),
        ("hidden row, client in B too", 2, {"mac": mac1, "subnet_id": 2}),
        ("no row, client in B", 2, None),
        ("no row, client nowhere", None, None),
    ):
        p._current_subnet_for_mac = lambda mac, now=now: now
        db = FakeDB([row] if row else [])
        p._get_db = lambda db=db: db
        flashed.clear()
        audits_h.clear()
        p.request = types.SimpleNamespace(form={"mac": mac1, "label": "x"}, args={})
        p.track()
        refusals[label] = list(flashed)
        check(
            flashed == [p.NOT_YOURS] and mutations(db) == [] and audits_h == [],
            f"track: {label} - refused with the one sentence, nothing written, nothing audited (got {flashed})",
        )
    check(
        len({tuple(v) for v in refusals.values()}) == 1,
        f"track: hidden and nonexistent entries are refused with the very same text (got {refusals})",
    )
    # the row action goes through the same function
    p._current_subnet_for_mac = lambda mac: 2
    db = FakeDB([])
    p._get_db = lambda db=db: db
    flashed.clear()
    p.request = types.SimpleNamespace(form={}, args={"mac": mac1, "hostname": "x"})
    p.track_from_row()
    check(p.NOT_YOURS in flashed and mutations(db) == [], f"track_from_row: the same refusal (got {flashed})")
    p._current_subnet_for_mac = lambda mac: 1

    # ── 1.2.2: the transition event carries the OWNER subnet (it carried none, so the owner-scoped user never saw it) ──
    emitted_t = []
    q = load_plugin()  # an untouched copy: `p._apply_transition` was replaced by a recorder above
    sys.modules["jen.plugin_api"].emit = lambda kind, **kw: emitted_t.append((kind, kw))
    q._get_db = lambda: FakeDB([])
    owner_rows = {mac1: ("Phone", 1), "aa:bb:cc:dd:ee:02": ("Hidden", None)}
    q._tracked_label_and_subnet = lambda mac: owner_rows.get(mac, ("", None))
    q._current_ip_hostname = lambda mac: (None, None)
    q._enabled_sinks = list
    q._audit = lambda *a: None
    for mac, expect in ((mac1, 1), ("aa:bb:cc:dd:ee:02", None), ("aa:bb:cc:dd:ee:03", None)):
        emitted_t.clear()
        q._apply_transition(mac, True)
        check(
            len(emitted_t) == 1
            and emitted_t[0][0] == "plugin.presence.transition"
            and emitted_t[0][1].get("subnet_id") == expect,
            f"_apply_transition: the event for {mac} carries the owner subnet {expect} (got {emitted_t})",
        )
    p.request = None

    # ── 1.2.3: every lease query asks for a CURRENT lease (Jen's ACTIVE_LEASE4, never a bare state = 0) ──
    q = load_plugin()
    _stub_jen_plugin_api()
    src = pathlib.Path(ROOT, "plugin.py").read_text(encoding="utf-8")
    check(
        "state=0" not in src and "state = 0" not in src,
        "the plugin never spells the current-lease predicate itself",
    )
    current = "state = 0 AND expire > NOW()"
    kdb = FakeDB([{"ip": "10.0.0.8", "hostname": "tv"}])
    q._get_kea_db = lambda: kdb
    check(
        q._current_ip_hostname("aa:bb:cc:dd:ee:08") == ("10.0.0.8", "tv"),
        "_current_ip_hostname: the row is read as before",
    )
    check(current in kdb.statements[0][1], "_current_ip_hostname: asks for a current lease")
    kdb = FakeDB([[{"mac_hex": "AABBCCDDEE08", "ip": "10.0.0.8", "hostname": "tv"}]])
    q._get_kea_db = lambda: kdb
    q._current_ip_hostname_bulk(["aa:bb:cc:dd:ee:08"])
    check(current in kdb.statements[0][1], "_current_ip_hostname_bulk: asks for a current lease")
    kdb = FakeDB([{"n": 1}])
    q._get_kea_db = lambda: kdb
    check(
        q._has_active_lease("aa:bb:cc:dd:ee:08") is True and current in kdb.statements[0][1],
        "_has_active_lease: asks for a current lease",
    )

    # ── 1.2.5: every tracked row carries the Investigate action (Jen's macro) ─────────────────────────────────────
    page = pathlib.Path(ROOT, "templates", "presence", "index.html").read_text(encoding="utf-8")
    check(
        "{% from '_investigate.html' import investigate_link %}" in page and 'investigate_link(r.mac, "icon")' in page,
        "index.html: each tracked row carries Jen's Investigate macro, given its MAC",
    )

    # ── 1.2.7, 1.2.8 (BG4): with more unseen devices than one pass asks, the ones asked longest ago are asked first ──
    check(
        p.probe_batch(["10.0.0.100", "10.0.0.11", "10.0.0.9", "10.0.0.11"], {}, 64)
        == ["10.0.0.9", "10.0.0.11", "10.0.0.100"],
        "probe_batch (BG4): nobody asked yet - distinct addresses, ordered as numbers, not as text, and a short list is asked whole",
    )
    hundred = [f"10.1.0.{n}" for n in range(1, 101)]
    first = p.probe_batch(hundred, {}, 64)
    second = p.probe_batch(hundred, dict.fromkeys(first, 1), 64)
    check(
        first == hundred[:64] and second == hundred[64:] + hundred[:28],
        f"probe_batch (BG4): the 36 never asked go first, then the ones asked longest ago in numeric order (got {second[:2]} .. {second[-2:]})",
    )
    stamps = {"10.1.0.1": 7, "10.1.0.2": 3, "10.1.0.3": 5, "10.1.0.4": 3, "10.1.0.200": 1}
    before = dict(stamps)
    check(
        p.probe_batch(["10.1.0.1", "10.1.0.2", "10.1.0.3", "10.1.0.4", "10.1.0.10", "10.1.0.9"], stamps, 5)
        == ["10.1.0.9", "10.1.0.10", "10.1.0.2", "10.1.0.4", "10.1.0.3"],
        "probe_batch (BG4): never asked first, then the oldest stamp, ties in numeric order, the newest stamp left for a later pass",
    )
    check(
        stamps == before,
        "probe_batch (BG4): it does not change the map it was given, and an address that is not in the unseen set is not asked",
    )
    check(p.probe_batch([], {"10.1.0.1": 4}, 64) == [], "probe_batch: nothing to ask")

    many = load_plugin()
    macs = {f"aa:bb:cc:dd:{n // 256:02x}:{n % 256:02x}": f"10.1.0.{n}" for n in range(1, 101)}
    answering = dict.fromkeys(macs, True)
    asked_log, moved_many, tables = [], [], []

    def _table(state_of):
        return "".join(f"{ip} dev eth0 lladdr {mac} {state_of(mac)}\n" for mac, ip in macs.items())

    class _NeighMany:
        returncode = 0

        def __init__(self):
            self.stdout = tables.pop(0)

    many._tracked_macs = lambda: set(macs)
    many._ip_binary = lambda: "ip"
    many._local_networks = lambda ip_bin: nets
    many._local_macs = lambda tracked, local_nets: set(tracked)
    many._current_ip_hostname_bulk = lambda asked, strict=False: {mac: (macs[mac], "") for mac in asked}
    many._send_probes = lambda addresses: (asked_log.append(list(addresses)), len(addresses))[1]
    many._PROBE_WAIT_S = 0
    many.subprocess = types.SimpleNamespace(run=lambda *a, **k: _NeighMany(), TimeoutExpired=Exception)
    many._apply_transition = lambda mac, online: moved_many.append((mac, online))
    touched = []
    for _pass in range(6):
        asked_now = set()

        def _second_read(mac, asked_now=asked_now):
            return "REACHABLE" if answering[mac] and macs[mac] in asked_now else "STALE"

        tables[:] = [_table(lambda mac: "STALE")]
        real_send = many._send_probes

        def _send(addresses, asked_now=asked_now, real_send=real_send):
            asked_now.update(addresses)
            tables.append(_table(_second_read))
            return real_send(addresses)

        many._send_probes = _send
        db = FakeDB([[{"mac": mac, "online": 1, "misses": 2} for mac in macs]])
        many._get_db = lambda db=db: db
        many._neighbor_tick()
        many._send_probes = real_send
        touched.append({st[2][-1] for st in db.statements if st[0] == "UPDATE"})
    check(
        all(len(batch) == 64 for batch in asked_log) and set(asked_log[0]) | set(asked_log[1]) == set(macs.values()),
        f"_neighbor_tick: 100 unseen devices are asked 64 a pass, and all of them within two passes (got {[len(b) for b in asked_log]})",
    )
    check(
        moved_many == [],
        f"_neighbor_tick: with two misses each already, no device that answers is called offline over six passes (got {len(moved_many)} offline)",
    )
    waiting_first = {mac for mac, ip in macs.items() if ip not in set(asked_log[0])}
    check(
        len(waiting_first) == 36 and not (touched[0] & waiting_first),
        "_neighbor_tick: the 36 devices not asked on the first pass get no miss and no write on that pass",
    )
    gone = "aa:bb:cc:dd:00:64"  # 10.1.0.100: past the first 64, and it has left
    answering[gone] = False
    moved_many.clear()
    many._probe_rotation.update({"pass": 0, "asked": {}})
    for _pass in range(3):
        asked_now = set()

        def _second_read(mac, asked_now=asked_now):
            return "REACHABLE" if answering[mac] and macs[mac] in asked_now else "STALE"

        tables[:] = [_table(lambda mac: "STALE")]
        real_send = many._send_probes

        def _send(addresses, asked_now=asked_now, real_send=real_send):
            asked_now.update(addresses)
            tables.append(_table(_second_read))
            return real_send(addresses)

        many._send_probes = _send
        db = FakeDB([[{"mac": mac, "online": 1, "misses": 2} for mac in macs]])
        many._get_db = lambda db=db: db
        many._neighbor_tick()
        many._send_probes = real_send
    check(
        moved_many == [(gone, False)],
        f"_neighbor_tick: a device past the first 64 that has left is still called offline, on the pass that asks it (got {moved_many})",
    )

    # ── 1.2.8 (BG2): a lease lookup that FAILED is not "no device holds a lease" ───────────────────────────────────
    class _StateDB:
        """pr_state kept across passes: the real pass reads its rows and its writes land in them."""

        def __init__(self, tracked, misses=0):
            self.state = {mac: {"mac": mac, "online": 1, "misses": misses} for mac in tracked}
            self.writes = []
            self._rows = []

        def cursor(self):
            return self

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def execute(self, sql, params=()):
            if sql.startswith("SELECT"):
                self._rows = [dict(self.state[mac]) for mac in params if mac in self.state]
            elif "SET misses" in sql:
                self.state[params[1]]["misses"] = params[0]
                self.writes.append(("misses", params[1], params[0]))
            else:
                self.writes.append(("seen", params[-1]))

        def fetchall(self):
            return self._rows

        def commit(self):
            pass

        def rollback(self):
            pass

        def close(self):
            pass

    def lease_world(devices, kea, passes, shown=(), absent=()):
        """The real `_neighbor_tick`, `_confirmed_by_probe` and `_current_ip_hostname_bulk`, `passes` times. `devices` is {mac: address};
        every one of them answers when it is asked, the ones in `shown` are REACHABLE on the first read already, and the ones in
        `absent` hold no lease. `kea` is what `_get_kea_db` does: only the databases, the sender and `ip neigh` are stood in.
        Returns (transitions, the state store, the addresses that were sent to)."""
        w = load_plugin()
        moved, sent, tables = [], [], []
        store = _StateDB(devices, misses=1 if shown else 0)
        for mac in devices:
            if mac not in shown:
                store.state[mac]["misses"] = 0

        class _Neigh:
            returncode = 0

            def __init__(self):
                self.stdout = tables.pop(0)

        def _first_read():
            return "".join(
                f"{ip} dev eth0 lladdr {mac} {'REACHABLE' if mac in shown else 'STALE'}\n"
                for mac, ip in devices.items()
            )

        def _send(addresses):
            sent.extend(addresses)
            asked = set(addresses)
            tables.append(
                "".join(
                    f"{ip} dev eth0 lladdr {mac} {'REACHABLE' if ip in asked else 'STALE'}\n"
                    for mac, ip in devices.items()
                )
            )
            return len(addresses)

        def _offline(mac, online):
            moved.append((mac, online))
            store.state[mac].update(online=1 if online else 0, misses=0)

        w._tracked_macs = lambda: set(devices)
        w._ip_binary = lambda: "ip"
        w._local_networks = lambda ip_bin: nets
        w._local_macs = lambda tracked, local_nets: set(tracked)
        w._get_kea_db = lambda: kea(
            [
                {"mac_hex": mac.replace(":", "").upper(), "ip": ip, "hostname": ""}
                for mac, ip in devices.items()
                if mac not in absent
            ]
        )
        w._send_probes = _send
        w._PROBE_WAIT_S = 0
        w.subprocess = types.SimpleNamespace(run=lambda *a, **k: _Neigh(), TimeoutExpired=Exception)
        w._get_db = lambda: store
        w._apply_transition = _offline
        for _pass in range(passes):
            tables[:] = [_first_read()]
            w._neighbor_tick()
        return moved, store, sent

    def _kea_away(rows):
        raise RuntimeError("Kea's database is away")

    ten = {f"aa:bb:cc:dd:ee:{n:02x}": f"10.1.0.{n}" for n in range(1, 11)}
    moved, store, sent = lease_world(ten, _kea_away, 3)
    check(
        moved == [] and sent == [],
        f"_neighbor_tick (BG2): with the lease lookup failing, ten unseen devices that would answer are not called offline in three passes (got {len(moved)} offline)",
    )
    check(
        all(row["misses"] == 0 for row in store.state.values()) and store.writes == [],
        f"_neighbor_tick (BG2): with the lease lookup failing no device takes a miss and nothing is written (got {store.writes[:3]})",
    )
    eleven = dict(ten, **{"aa:bb:cc:dd:ee:0b": "10.1.0.11"})
    moved, store, sent = lease_world(eleven, _kea_away, 1, shown={"aa:bb:cc:dd:ee:0b"})
    check(
        moved == []
        and store.state["aa:bb:cc:dd:ee:0b"]["misses"] == 0
        and {w[1] for w in store.writes} == {"aa:bb:cc:dd:ee:0b"},
        f"_neighbor_tick (BG2): with the lease lookup failing, a device the first read shows is still marked seen, and only it is written (got {store.writes})",
    )
    moved, store, sent = lease_world(ten, _KeaDB, 3, absent={"aa:bb:cc:dd:ee:0a"})
    check(
        moved == [("aa:bb:cc:dd:ee:0a", False)] and "10.1.0.10" not in sent and len(sent) == 27,
        f"_neighbor_tick (BG2): when the lookup ANSWERED, a device with no lease is a miss as before and is offline at its third (got {moved}, {len(sent)} sent)",
    )
    moved, store, sent = lease_world(ten, _KeaDB, 1, absent={"aa:bb:cc:dd:ee:0a"})
    check(
        [mac for mac, row in store.state.items() if row["misses"]] == ["aa:bb:cc:dd:ee:0a"]
        and store.state["aa:bb:cc:dd:ee:0a"]["misses"] == 1,
        "_neighbor_tick (BG2): when the lookup answered, the device with no lease takes one miss on one pass and the nine that answer take none",
    )

    # ── 1.2.8 (BG4): the rotation is by least recently asked, whatever the other addresses do ──────────────────────
    def rotation_world(unseen_on_pass, passes, sendable=lambda number: True):
        """The real `_confirmed_by_probe` (the real `probe_batch`, the real stamping) over `passes` passes; `unseen_on_pass(n)` is the
        list of unseen addresses on pass n. Nobody answers, so who is asked depends on the rotation alone. Returns (the batch of each
        pass, the longest wait between two asks of an address that stayed unseen all that time, the module)."""
        r = load_plugin()
        batches = []

        class _Neigh:
            returncode = 0
            stdout = ""

        def _send(addresses):
            batches[-1] = list(addresses)
            return len(addresses) if sendable(len(batches)) else 0

        r._current_ip_hostname_bulk = lambda macs, strict=False: {
            mac: (mac, "") for mac in macs
        }  # the address stands for its MAC
        r._send_probes = _send
        r._PROBE_WAIT_S = 0
        r.subprocess = types.SimpleNamespace(run=lambda *a, **k: _Neigh(), TimeoutExpired=Exception)
        since, longest = {}, 0  # address -> the pass it was last asked on, or joined the unseen set on
        for number in range(1, passes + 1):
            unseen = list(unseen_on_pass(number))
            for ip in [ip for ip in since if ip not in set(unseen)]:
                del since[ip]  # seen again: its wait is over
            batches.append([])
            r._confirmed_by_probe("ip", unseen)
            asked = set(batches[-1]) if sendable(number) else set()
            for ip in unseen:
                since.setdefault(ip, number - 1)
                if ip in asked:
                    longest = max(longest, number - since[ip])
                    since[ip] = number
                else:
                    longest = max(longest, number - since[ip])
        return batches, longest, r

    pool = [f"10.1.{n // 250}.{n % 250 + 1}" for n in range(300)]
    low, high = pool[:126], pool[126:187]
    batches, longest, _r = rotation_world(lambda number: low + high if number % 2 else low, 200)
    asks = {ip: sum(ip in batch for batch in batches) for ip in low}
    check(
        longest <= 4 and all(len(batch) == 64 for batch in batches),
        f"_confirmed_by_probe (BG4): the unseen set alternating between 187 and 126 over 200 passes - no device waits more than 4 passes for its turn (got {longest}; fewest asks {min(asks.values())})",
    )
    check(
        min(asks.values()) >= 50,
        f"_confirmed_by_probe (BG4): in that world every always-unseen device is asked at least every fourth pass (fewest asks {min(asks.values())} of 200)",
    )
    bound = math.ceil(300 / 64) + 1
    worst = []
    for seed in (1, 2, 3):
        rng = random.Random(seed)

        def _churn(number, rng=rng):
            seen = set(rng.sample(pool, rng.randint(0, 200)))
            return [ip for ip in pool if ip not in seen]

        _batches, longest, _r = rotation_world(_churn, 400)
        worst.append(longest)
    check(
        max(worst) <= bound,
        f"_confirmed_by_probe (BG4): 300 devices with 0 to 200 of them seen on each pass, three seeds, 400 passes - a device that stays unseen waits at most {bound} passes (got {worst})",
    )
    batches, _longest, r = rotation_world(lambda number: pool[:100], 3, sendable=lambda number: number != 1)
    check(
        batches[0] == pool[:64] and batches[1] == pool[:64] and batches[2] == pool[64:100] + pool[:28],
        "_confirmed_by_probe (BG4): a pass that could send nothing stamps nobody - the same 64 are asked on the next pass, then the other 36",
    )
    silent = load_plugin()
    silent._current_ip_hostname_bulk = lambda macs, strict=False: {mac: (mac, "") for mac in macs}
    silent._send_probes = lambda addresses: 0
    check(
        silent._confirmed_by_probe("ip", pool[:100]) == (set(), set(pool[:100]))
        and silent._probe_rotation == {"pass": 1, "asked": {}},
        f"_confirmed_by_probe (BG4, BH3): when _send_probes answers 0 the pass is counted, no address is stamped and all 100 wait (got {silent._probe_rotation['pass']}, {len(silent._probe_rotation['asked'])} stamped)",
    )
    _batches, _longest, r = rotation_world(lambda number: pool[:100], 2)
    check(
        r._probe_rotation["pass"] == 2
        and {r._probe_rotation["asked"][ip] for ip in pool[:28]} == {2}
        and {r._probe_rotation["asked"][ip] for ip in pool[28:64]} == {1}
        and {r._probe_rotation["asked"][ip] for ip in pool[64:100]} == {2},
        "_confirmed_by_probe (BG4): each address of a batch that was sent is stamped with the number of its pass",
    )
    full = load_plugin()
    old_addresses = [f"10.{a}.{b}.{c}" for a in (8, 9) for b in range(16) for c in range(1, 129)]
    full._probe_rotation.update({"pass": 5000, "asked": {ip: n + 1 for n, ip in enumerate(old_addresses)}})
    full._current_ip_hostname_bulk = lambda macs, strict=False: {mac: (mac, "") for mac in macs}
    full._send_probes = len
    full._PROBE_WAIT_S = 0

    class _NoTable:
        returncode = 1
        stdout = ""

    full.subprocess = types.SimpleNamespace(run=lambda *a, **k: _NoTable(), TimeoutExpired=Exception)
    full._confirmed_by_probe("ip", pool[:64])
    kept = full._probe_rotation["asked"]
    check(
        (len(old_addresses), full._ASKED_KEEP, len(kept)) == (4096, 4096, 4096)
        and all(kept.get(ip) == 5001 for ip in pool[:64])
        and not any(ip in kept for ip in old_addresses[:64])
        and all(ip in kept for ip in old_addresses[64:]),
        f"_confirmed_by_probe (BG4): the map of asked addresses is kept to 4096, the 64 asked longest ago dropped for the 64 just asked (got {len(kept)})",
    )

    # ── 1.2.9 (BH3): a probe that could not be sent, or whose answer could not be read, asked nobody ───────────────
    def probe_world(count, failure, passes=3, absent=(), shown=(), gone=()):
        """The real `_neighbor_tick`, `_confirmed_by_probe`, `probe_batch` and `_current_ip_hostname_bulk`, `passes` times, over `count`
        devices recorded online. Each holds a lease (but the ones in `absent`) and answers when it is asked (but the ones in `gone`);
        the ones in `shown` are REACHABLE on the first read already. `failure(n)` is what goes wrong on pass n: "send" (the sender
        answers 0), "raise" (the neighbor read after the probe raises), "rc" (it exits non-zero) or None. Only the databases, the
        sender, the wait and `ip neigh` are stood in. Returns (transitions, the state store, the devices)."""
        w = load_plugin()
        devices = {
            f"aa:bb:cc:dd:{n // 256:02x}:{n % 256:02x}": f"10.1.{n // 250}.{n % 250 + 1}" for n in range(1, count + 1)
        }
        moved = []
        store = _StateDB(devices)
        now = {"pass": 0, "reads": 0, "asked": set()}

        def _table(asked):
            return "".join(
                f"{ip} dev eth0 lladdr {mac} {'REACHABLE' if mac in shown or (ip in asked and mac not in gone) else 'STALE'}\n"
                for mac, ip in devices.items()
            )

        def _run(*a, **k):
            now["reads"] += 1
            if now["reads"] == 1:
                return types.SimpleNamespace(returncode=0, stdout=_table(set()))
            if failure(now["pass"]) == "raise":
                raise OSError("ip neigh did not run")
            if failure(now["pass"]) == "rc":
                return types.SimpleNamespace(returncode=1, stdout="")
            return types.SimpleNamespace(returncode=0, stdout=_table(now["asked"]))

        def _send(addresses):
            now["asked"] = set(addresses)
            return 0 if failure(now["pass"]) == "send" else len(addresses)

        def _transition(mac, online):
            moved.append((mac, online))
            store.state[mac].update(online=1 if online else 0, misses=0)

        w._tracked_macs = lambda: set(devices)
        w._ip_binary = lambda: "ip"
        w._local_networks = lambda ip_bin: nets
        w._local_macs = lambda tracked, local_nets: set(tracked)
        w._get_kea_db = lambda: _KeaDB(
            [
                {"mac_hex": mac.replace(":", "").upper(), "ip": ip, "hostname": ""}
                for mac, ip in devices.items()
                if mac not in absent
            ]
        )
        w._send_probes = _send
        w._PROBE_WAIT_S = 0
        w.subprocess = types.SimpleNamespace(run=_run, TimeoutExpired=Exception)
        w._get_db = lambda: store
        w._apply_transition = _transition
        for number in range(1, passes + 1):
            now.update({"pass": number, "reads": 0, "asked": set()})
            w._neighbor_tick()
        return moved, store, devices

    for failure, what in (
        ("send", "the probe could not be sent"),
        ("raise", "the neighbor read after the probe raised"),
        ("rc", "the neighbor read after the probe failed"),
    ):
        moved, store, _devices = probe_world(100, lambda number, failure=failure: failure)
        check(
            moved == [] and store.writes == [] and all(row["misses"] == 0 for row in store.state.values()),
            f"_neighbor_tick (BH3): {what} on three passes - none of 100 present devices with a lease is called offline, none takes a miss "
            f"and nothing is written, the 36 past the batch included (got {len(moved)} offline, {len(store.writes)} writes; 1.2.8: 100 offline)",
        )
    first_mac, last_mac = "aa:bb:cc:dd:00:01", "aa:bb:cc:dd:00:0a"
    moved, store, _devices = probe_world(10, lambda number: "send", passes=1, absent={last_mac}, shown={first_mac})
    check(
        moved == [] and store.writes == [("seen", first_mac)] and store.state[last_mac]["misses"] == 0,
        f"_neighbor_tick (BH3): with the probe unsendable, a device the first read shows is still marked seen, and a device with no lease "
        f"waits like the rest (got {store.writes})",
    )
    moved, store, _devices = probe_world(10, lambda number: None, passes=1, absent={last_mac})
    check(
        moved == [] and [mac for mac, row in store.state.items() if row["misses"]] == [last_mac],
        "_neighbor_tick (BH3): when the probe was sent and its answer read, the device with no lease is a miss as before",
    )
    moved, store, _devices = probe_world(
        100, lambda number: "rc" if number <= 3 else None, passes=3 + 6, gone={"aa:bb:cc:dd:00:64"}
    )
    check(
        moved == [("aa:bb:cc:dd:00:64", False)],
        f"_neighbor_tick (BH3): a device that left while the answer could not be read is called offline once it can be, at its third "
        f"miss of its own, and nobody else is (got {moved})",
    )
    stamped = load_plugin()
    stamped._current_ip_hostname_bulk = lambda macs, strict=False: {mac: (mac, "") for mac in macs}
    stamped._send_probes = lambda addresses: 1  # one datagram of the 64 went out
    stamped._PROBE_WAIT_S = 0
    stamped.subprocess = types.SimpleNamespace(run=lambda *a, **k: _NoTable(), TimeoutExpired=Exception)
    answer = stamped._confirmed_by_probe("ip", pool[:100])
    check(
        answer == (set(), set(pool[:100]))
        and stamped._probe_rotation["asked"] == dict.fromkeys(pool[:64], 1)
        and stamped._probe_rotation["pass"] == 1,
        "_confirmed_by_probe (BH3, BH6): when the read after the probe fails all 100 wait, and the 64 of the batch are stamped as "
        "asked although one datagram of the batch was sent - the stamping is as it was in 1.2.8",
    )
    check(
        "every device is a miss" not in (stamped._confirmed_by_probe.__doc__ or "")
        and "v1.2.9 (BH3)" in (stamped._confirmed_by_probe.__doc__ or ""),
        "_confirmed_by_probe (BH3): its docstring no longer says every device is a miss when nothing could be sent",
    )

    # ── 1.2.9: the page (V52, addition 11 of the look over 7.2.0-beta.5) ───────────────────────────────────────────
    page = pathlib.Path(ROOT, "templates", "presence", "index.html").read_text(encoding="utf-8")
    source = pathlib.Path(ROOT, "plugin.py").read_text(encoding="utf-8")
    check(
        page.count("Track Device") == 5 and "Track a device</" not in page and ">Track</button>" not in page,
        f"index.html: the button is 'Track Device' in the header, the first steps and the dialog (got {page.count('Track Device')})",
    )
    check(
        page.count("Add Destination") == 4
        and "Publish To</h2>" in page
        and not re.search(r"\bSinks?\b", re.sub(r"\{#.*?#\}", "", page, flags=re.S)),
        f"index.html: the section is 'Publish To', its button 'Add Destination', and the page does not say Sink (got {page.count('Add Destination')})",
    )
    head = page[
        page.index('<div class="card-header pr-card-head">') : page.index('<p class="small muted pr-card-note">')
    ]
    check(
        'id="pr-add-sink-btn"' in head and page.count('id="pr-add-sink-btn"') == 1 and "<table" not in head,
        "index.html: Add Destination sits in the Publish To card's header, before its table, and nowhere else",
    )
    note = page[page.index('<p class="small muted pr-card-note">') : page.index('<p class="muted pr-empty">')]
    check(
        "(Home Assistant, an MQTT broker or an HTTP address); with no destination the state is still recorded and shown on "
        "this page, and nothing is sent.{% if"
        in note
        and note.split("{% if")[0].count(". ") == 0,
        "index.html: one sentence under Publish To says what a destination is and what happens with none",
    )
    first_run = page[
        page.index('<div class="card first-run">') : page.index('{% else %}\n<div class="card pr-card-flush">')
    ]
    check(
        page.index("{% if not rows %}\n{# v1.2.9") < page.index('<div class="card first-run">')
        and "<h3>Getting started</h3>" in first_run
        and first_run.count("<ol>") == 1
        and "No devices tracked yet" not in page,
        "index.html: with nothing tracked the page shows the card of first steps in place of the empty table",
    )
    check(
        first_run.count("<li>") == 4
        and first_run.count("{% if is_superadmin %}") == 1
        and first_run.count("{% elif is_admin %}") == 1
        and "/settings/alerts" not in page
        and "register_alert" not in source,
        "index.html: two steps for each role (one of three first steps, then what Jen does), and no alert step: Presence registers no alert type",
    )
    superadmin_step = first_run[first_run.index("{% if is_superadmin %}") : first_run.index("{% elif is_admin %}")]
    check(
        superadmin_step.index("Add a destination first") < superadmin_step.index("Then track a device")
        and 'data-pr-open="pr-add-sink-modal"' in superadmin_step
        and 'data-pr-open="pr-add-modal"' in superadmin_step,
        "index.html: the first step names the destination before the device, each with its button",
    )
    check(
        "querySelectorAll('[data-pr-open]')" in page
        and page.count('data-pr-open="pr-add-modal"') == 3
        and page.count('data-pr-open="pr-add-sink-modal"') == 2
        and "getElementById('pr-add-btn')" not in page
        and "getElementById('pr-add-sink-btn')" not in page,
        "index.html: every button that opens a dialog is bound through data-pr-open, so a button that is not drawn breaks no script",
    )
    check(
        'data-m="full"' not in page and '<p class="muted pr-empty">No destination yet.</p>' in page,
        "index.html: no empty table row is left on the page (its text sat high on a phone); the empty Publish To card is a centered line",
    )
    check(
        "Send Test</button>" in page and "Send test" not in page,
        "index.html: 'Send Test' is title case like the page's every button",
    )
    check(
        "@media screen and (max-width: 768px)" in page and not re.search(r"@media\s*\((?:max|min)-width", page),
        "index.html: the page's width rule names screen",
    )
    flashes = [re.sub(r"\{[^}]*\}?", "", text) for text in re.findall(r'flash\(\s*f?"([^"]*)"', source)]
    check(
        not [text for text in flashes if re.search(r"\bsinks?\b", text, re.I)]
        and 'flash("Destination enabled." if new_enabled else "Destination paused.", "success")' in source
        and source.count('flash("Destination not found.", "error")') == 2,
        f"plugin.py: no flash sentence says sink - a person reads destination ({len(flashes)} flash sentences read)",
    )
    p.is_superadmin = lambda: False
    refused = []
    p.flash = lambda message, category="message": refused.append((message, category))
    check(
        p._require_superadmin() is False
        and refused == [("Destinations are global integration settings: only a superadmin can change them.", "error")],
        f"_require_superadmin: an admin who is not a superadmin is told destinations are a superadmin's (got {refused})",
    )

    if failures:
        print(f"\n{len(failures)} check(s) failed")
        return 1
    print("\nall plugin checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
