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
    plugin_api.subscribe = lambda kind, fn: None
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


def check(cond, msg):
    if cond:
        print(f"ok    {msg}")
    else:
        failures.append(msg)
        print(f"FAIL  {msg}")


def main():
    p = load_plugin()

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
        == {"host": "mosquitto.local", "port": 1883, "use_tls": False, "username": None},
        "parse_mqtt_url: plain mqtt:// with an explicit port",
    )
    check(
        p.parse_mqtt_url("mqtts://mqtt.example.com")
        == {"host": "mqtt.example.com", "port": 8883, "use_tls": True, "username": None},
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

    # ── register(): runs end to end against a stub jen.plugin_api ───────────
    row_action_calls = _stub_jen_plugin_api()
    try:
        p.register(_FakeApp())
        registered = True
    except Exception as e:
        registered = False
        print(f"      register() raised: {e}")
    check(registered, "register(): runs end to end without raising against a real-rule stub")
    surfaces = sorted(c[1] for c in row_action_calls)
    check(
        surfaces == ["device", "lease"],
        f"register(): a Track presence row action is registered on lease + device only, not reservation (got {surfaces})",
    )

    if failures:
        print(f"\n{len(failures)} check(s) failed")
        return 1
    print("\nall plugin checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
