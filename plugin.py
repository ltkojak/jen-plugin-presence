"""
Presence plugin for Jen.
Publishes tracked devices' online/offline state to Home Assistant (a
webhook), MQTT, or any HTTP endpoint, so the house can react to a
phone joining or leaving. Opt-in per MAC — nothing is published for a
device that hasn't been explicitly tracked. Version lives in
manifest.json — not duplicated here.

Verify-first (read 2026-09-24, pinned here per CLAUDE.md's round-5
recipe — every byte value below is quoted from the spec itself):

MQTT 3.1.1 — OASIS standard,
http://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html
  * §2.2.3 Remaining Length: a variable-length, big-endian-ish,
    7-bits-per-byte encoding with the top bit as a continuation flag:
    `encodedByte = X % 128; X //= 128; if X > 0: encodedByte |= 0x80`,
    looped while X > 0.
  * §2.4 / §1.5.3: every UTF-8 string field (protocol name, client
    id, topic, username) is a 2-byte big-endian length prefix
    followed by the UTF-8 bytes — no null terminator.
  * §3.1 CONNECT: fixed header byte `0x10` (type 1, reserved flags
    0000). Variable header: Protocol Name `"MQTT"` (length-prefixed,
    6 bytes total), Protocol Level `0x04` (v3.1.1), Connect Flags (1
    byte: bit7 Username, bit6 Password, bit5 Will Retain, bits4-3
    Will QoS, bit2 Will Flag, bit1 Clean Session, bit0 reserved-0),
    Keep Alive (2-byte big-endian seconds). Payload, in this fixed
    order when the matching flag is set: Client Identifier, Will
    Topic, Will Message, User Name, Password (this plugin sends no
    Will). CONNACK reply: 4 bytes, `0x20 0x02 <ack flags> <return
    code>` — return code `0x00` is the only success value.
  * §3.3 PUBLISH at QoS 0: fixed header byte `0x30 | (retain ? 1 : 0)`
    — DUP "MUST be set to 0 for all QoS 0 messages", QoS bits `00`.
    Variable header is the length-prefixed Topic Name only — "a
    PUBLISH Packet MUST NOT contain a Packet Identifier if its QoS
    value is set to 0". Payload is the raw application bytes,
    un-prefixed (its length is Remaining Length minus the variable
    header's length).
  * §3.14 DISCONNECT: fixed header byte `0xE0` (type 14), "has no
    variable header" and "has no payload" — Remaining Length `0x00`.
    The whole packet is exactly `b"\\xe0\\x00"`.

Home Assistant webhook —
https://www.home-assistant.io/docs/automation/trigger/#webhook-trigger
  * `POST <ha>/api/webhook/<webhook_id>` with header
    `Content-Type: application/json` and a JSON body — no separate
    auth token; knowing the webhook id is what authorizes the call.

Home Assistant MQTT discovery (device_tracker) —
https://www.home-assistant.io/integrations/device_tracker.mqtt/
  * Discovery topic: `homeassistant/device_tracker/<object_id>/config`
    (retained). Payload (JSON): `state_topic`, `name`, `payload_home`,
    `payload_not_home`, `unique_id`, `source_type`. `payload_home`/
    `payload_not_home` must match whatever the state topic actually
    publishes — this plugin's own state topic publishes the literal
    strings `"online"`/`"offline"` (see the design note below), so
    the discovery payload sets `payload_home`/`payload_not_home` to
    those exact strings, not HA's own `"home"`/`"not_home"` defaults.

Design notes
────────────
**Two debounce regimes, on purpose.** A lease event (`lease.new`/
`lease.expired`) is itself a transition — Kea has already decided the
device is there or gone, so it's applied immediately, no debounce. The
periodic neighbour-table pass is a fuzzier signal (a phone can miss
one ARP probe cycle for all sorts of reasons), so `next_presence_state()`
below only flips an online device offline after
`_OFFLINE_MISS_THRESHOLD` CONSECUTIVE passes that didn't see it — a
single missed pass never flips it early. Any sighting, from either
signal, flips a device online at once.

**Only what Jen can see from where it sits (v1.0.1).** The neighbour pass reads
`ip -4 neigh`, which only ever holds hosts on a segment the Jen host has an
interface on. A tracked device anywhere else was never in it, so it "missed" three
passes and went offline fifteen minutes after joining, and stayed there (a renewal
emits nothing). A pass now reads the host's own interface subnets first
(`ip -4 -o addr show`); a miss counts only for a MAC that is on one of them. For
every other device the state follows lease events alone, and the page says
"lease-based" beside it.

**Who may do what (v1.0.1).** Sinks are global integrations with a credential, and
every transition publishes every tracked client's MAC, label, IP, hostname and state
to every enabled sink, so configuring one (add, pause/enable, test, remove) is a
superadmin action; other admins see the list read-only. A tracked device belongs to
the subnet its MAC is in NOW (device, active lease, reservation), derived here — never
a value in the request. Tracking a MAC that is already tracked authorises the existing
row first and only ever changes its label, never its subnet. A MAC with no subnet is for
unrestricted callers only.

**One connect-publish-disconnect cycle per transition.** This plugin
never holds an MQTT connection open — each transition opens a fresh
TCP (optionally TLS) connection, sends CONNECT, waits for CONNACK,
PUBLISHes, sends DISCONNECT, and closes. Presence transitions are rare
(a device joining or leaving), so the extra round trip is immaterial,
and a short-lived connection needs no keep-alive PINGREQ loop, no
reconnect logic, and can't leak a stale open socket.
"""

import ipaddress
import json
import logging
import os as _os
import re
import shutil
import socket
import ssl
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

logger = logging.getLogger(__name__)

PLUGIN_ID = "presence"

bp = Blueprint(
    "presence",
    __name__,
    template_folder="templates",
    root_path=_os.path.dirname(_os.path.abspath(__file__)),
    url_prefix="/management/presence",
)

_MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")
_SEEN_STATES = ("REACHABLE", "DELAY", "PROBE")
_OFFLINE_MISS_THRESHOLD = 3
# 5, not the design's literal "every 2 min" — jen.services.background's
# PERIODIC_MIN_MINUTES has enforced a 5-minute floor since Jen v5.30.0,
# well before this plugin was written; register_periodic() raises below
# it, the exact class of bug that made Host Watchdog 1.0.0 never load
# (Q89). 3 consecutive misses at 5 minutes is 15 minutes before an
# entirely unreachable device is called offline, against 6 minutes at a
# literal 2-minute tick — a real, deliberate trade against Jen's own
# floor, not an oversight.
_NEIGH_TICK_MINUTES = 5
_HTTP_TIMEOUT_S = 10
_MQTT_TIMEOUT_S = 10
_MQTT_KEEP_ALIVE_S = 30


class _PresenceError(Exception):
    pass


# ── Pure: MQTT packet encoding (see module docstring for the verified spec) ────


def encode_remaining_length(n):
    """Pure: MQTT §2.2.3 variable-length Remaining Length encoding."""
    if n < 0:
        raise ValueError("remaining length must be >= 0")
    out = bytearray()
    x = n
    while True:
        encoded = x % 128
        x //= 128
        if x > 0:
            encoded |= 0x80
        out.append(encoded)
        if x <= 0:
            break
    return bytes(out)


def encode_utf8_string(s):
    """Pure: a 2-byte big-endian length prefix followed by the UTF-8
    bytes — the encoding every MQTT string field uses."""
    b = s.encode("utf-8")
    return len(b).to_bytes(2, "big") + b


def build_connect_packet(client_id, username=None, password=None, keep_alive=_MQTT_KEEP_ALIVE_S, clean_session=True):
    """Pure: a full MQTT 3.1.1 CONNECT packet, no Will fields."""
    variable_header = encode_utf8_string("MQTT") + bytes([0x04])
    flags = 0
    if clean_session:
        flags |= 0x02
    if username:
        flags |= 0x80
    if password:
        flags |= 0x40
    if password and not username:
        raise ValueError("an MQTT password needs a user name (MQTT-3.1.2-22)")
    variable_header += bytes([flags])
    variable_header += keep_alive.to_bytes(2, "big")

    payload = encode_utf8_string(client_id)
    if username:
        payload += encode_utf8_string(username)
    if password:
        payload += encode_utf8_string(password)

    remaining = variable_header + payload
    return bytes([0x10]) + encode_remaining_length(len(remaining)) + remaining


def build_publish_packet(topic, payload_bytes, retain=False):
    """Pure: a QoS-0 MQTT 3.1.1 PUBLISH packet — no Packet Identifier."""
    variable_header = encode_utf8_string(topic)
    remaining = variable_header + payload_bytes
    first_byte = 0x30 | (0x01 if retain else 0x00)
    return bytes([first_byte]) + encode_remaining_length(len(remaining)) + remaining


def build_disconnect_packet():
    """Pure: the fixed, two-byte MQTT 3.1.1 DISCONNECT packet."""
    return b"\xe0\x00"


def parse_mqtt_url(url):
    """Pure: 'mqtt://[user[:pass]@]host[:port]' or 'mqtts://...' -> {"host",
    "port", "use_tls", "username", "password"} | None if malformed. Port defaults
    to 1883 (mqtt) / 8883 (mqtts) when omitted. `.port` raises ValueError for
    `host:abc` and `host:99999`, so it is read INSIDE the try — outside it the
    Add Sink form answered a bad port with a 500 instead of its message."""
    try:
        parsed = urllib.parse.urlparse(url or "")
        if parsed.scheme not in ("mqtt", "mqtts"):
            return None
        if not parsed.hostname:
            return None
        use_tls = parsed.scheme == "mqtts"
        explicit_port = parsed.port
        if explicit_port == 0:
            return None
        port = explicit_port or (8883 if use_tls else 1883)
        return {
            "host": parsed.hostname,
            "port": port,
            "use_tls": use_tls,
            "username": parsed.username,
            "password": parsed.password,
        }
    except ValueError:
        return None


def strip_url_password(url):
    """Pure: 'mqtt://user:pass@host:1883' -> 'mqtt://user@host:1883'. The password
    belongs in the encrypted credential, not in the `url` column, which is shown
    and stored in clear. A URL without a password comes back unchanged."""
    parsed = urllib.parse.urlparse(url)
    if parsed.password is None:
        return url
    host = parsed.hostname or ""
    if ":" in host:
        host = f"[{host}]"
    netloc = host + (f":{parsed.port}" if parsed.port else "")
    if parsed.username:
        netloc = f"{parsed.username}@{netloc}"
    return urllib.parse.urlunparse(parsed._replace(netloc=netloc))


def valid_http_url(url):
    """Pure: an http:// or https:// URL with a host. The webhook and HTTP sinks are
    handed to urllib, which would just as happily open file:// or ftp:// URLs."""
    try:
        parsed = urllib.parse.urlparse(url or "")
        return parsed.scheme in ("http", "https") and bool(parsed.hostname)
    except ValueError:
        return False


def mqtt_client_id(mac):
    """Pure: the MQTT client identifier for a device. MQTT 3.1.1 §3.1.3.1 says a server
    MUST accept 1-23 characters and MAY refuse more; 'jen-presence-' plus 12 hex digits
    was 25 and some brokers do refuse it."""
    return f"jen-pr-{mac.replace(':', '')}"


# ── Pure: neighbour-table parsing, the offline debounce ─────────────────────────


def parse_neighbor_table(text):
    """Pure: `ip -4 neigh show` output -> {mac: seen}. A line like
    '10.0.0.5 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE' — the same
    shape Network Discovery's own neighbour read parses. `seen=True`
    only for REACHABLE/DELAY/PROBE (per the design: actively confirmed
    or being actively reconfirmed right now); STALE and everything
    else is NOT 'seen' for presence purposes, even though Discovery's
    own looser 'alive enough to report' definition would include it."""
    out = {}
    for line in (text or "").splitlines():
        parts = line.split()
        if not parts or "lladdr" not in parts:
            continue
        i = parts.index("lladdr")
        if i + 1 >= len(parts):
            continue
        mac = parts[i + 1].lower()
        if not _MAC_RE.match(mac):
            continue
        state = parts[-1].upper()
        seen = state in _SEEN_STATES
        out[mac] = out.get(mac, False) or seen
    return out


def parse_interface_networks(text):
    """Pure: `ip -4 -o addr show` output -> [IPv4Network] of the subnets the Jen host
    has an interface on (loopback excluded). One line looks like
    '2: eth0    inet 10.0.0.5/24 brd 10.0.0.255 scope global eth0'."""
    nets = []
    for line in (text or "").splitlines():
        parts = line.split()
        if "inet" not in parts:
            continue
        i = parts.index("inet")
        if i + 1 >= len(parts):
            continue
        try:
            net = ipaddress.ip_interface(parts[i + 1]).network
        except ValueError:
            continue
        if net.is_loopback:
            continue
        nets.append(net)
    return nets


def mac_is_local(ip, subnet_cidr, local_nets):
    """Pure: is a tracked device on a segment the Jen host has an interface on, i.e. one
    whose ARP entries `ip -4 neigh` can actually contain? Judged on the device's current
    address when it has one, else on its subnet; a device that is neither is not local."""
    if ip:
        try:
            addr = ipaddress.IPv4Address(ip)
            return any(addr in net for net in local_nets)
        except ValueError:
            pass
    if subnet_cidr:
        try:
            net = ipaddress.IPv4Network(subnet_cidr, strict=False)
            return any(net.overlaps(local) for local in local_nets)
        except ValueError:
            return False
    return False


def next_presence_state(state, misses, seen, miss_threshold=_OFFLINE_MISS_THRESHOLD):
    """Pure: (new_state, new_misses, transitioned). Any sighting flips
    to 'online' at once, misses reset to 0. A miss only flips an
    'online' device to 'offline' after `miss_threshold` CONSECUTIVE
    misses — a lone missed pass never flips it early, and an
    already-'offline' device just keeps accumulating misses without
    re-transitioning."""
    if seen:
        return "online", 0, (state != "online")
    misses = misses + 1
    if state == "online" and misses >= miss_threshold:
        return "offline", misses, True
    return state, misses, False


# ── Pure: sink topic/payload builders ────────────────────────────────────────────


def mqtt_state_topic(prefix, mac):
    return f"{prefix}/{mac.replace(':', '-')}"


def mqtt_attributes_topic(prefix, mac):
    return f"{mqtt_state_topic(prefix, mac)}/attributes"


def mqtt_discovery_topic(mac):
    return f"homeassistant/device_tracker/jen_{mac.replace(':', '')}/config"


def mqtt_discovery_payload(mac, label, prefix):
    return {
        "state_topic": mqtt_state_topic(prefix, mac),
        "json_attributes_topic": mqtt_attributes_topic(prefix, mac),
        "name": label or mac,
        "payload_home": "online",
        "payload_not_home": "offline",
        "unique_id": f"jen_presence_{mac.replace(':', '')}",
        "source_type": "router",
    }


def build_sink_payload(mac, label, online, since_iso, ip, hostname):
    """Pure: the JSON body every HA-webhook/generic-HTTP sink gets,
    and the content of MQTT's own .../attributes topic."""
    return {
        "mac": mac,
        "label": label,
        "online": online,
        "since": since_iso,
        "ip": ip,
        "hostname": hostname,
    }


# ── DB helpers (same shape as every other bundled plugin) ──────────────────────


def _get_db():
    from jen.plugin_api import get_jen_db

    return get_jen_db()


def _get_kea_db():
    from jen.plugin_api import get_kea_db

    return get_kea_db()


def _can(subnet_id):
    """May the session user act on something in `subnet_id`? None ("no attributable
    subnet") is for unrestricted users only — plugin_api decides (v5.65.2)."""
    from jen.plugin_api import can_access_subnet

    return can_access_subnet(subnet_id)


def _subnet_map():
    from jen.plugin_api import subnet_map

    return subnet_map()


def _is_admin():
    try:
        from jen.plugin_api import is_admin_or_above

        return is_admin_or_above()
    except Exception:
        role = getattr(current_user, "role", None)
        if role is not None:
            return role in ("superadmin", "admin")
        return bool(getattr(current_user, "is_admin", False))


def _require_write():
    if _is_admin():
        return True
    flash("Viewers can look at Presence but not change it.", "error")
    return False


def _is_superadmin():
    try:
        from jen.plugin_api import is_superadmin

        return is_superadmin()
    except Exception:
        return getattr(current_user, "role", None) == "superadmin"


def _require_superadmin():
    """Sinks are global integrations with a credential that receive every tracked
    client's state, so configuring one is a superadmin action (like Alerts channels)."""
    if _is_superadmin():
        return True
    flash("Sinks are global integration settings: only a superadmin can change them.", "error")
    return False


def _audit(action, target, detail):
    try:
        from jen.plugin_api import audit

        audit(action, target, detail)
    except Exception as e:
        logger.error(f"Presence: audit failed: {e}")


def _normalize_mac(raw):
    if not raw:
        return ""
    cleaned = re.sub(r"[^0-9a-fA-F]", "", raw).lower()
    if len(cleaned) != 12:
        return ""
    mac = ":".join(cleaned[i : i + 2] for i in range(0, 12, 2))
    return mac if _MAC_RE.match(mac) else ""


def _current_subnet_for_mac(mac):
    """The MAC's current subnet — a device's last-known placement, then an active lease, then
    a reservation (a global reservation carries no useful subnet, so it falls through)."""
    db = None
    try:
        db = _get_db()
        with db.cursor() as cur:
            cur.execute("SELECT last_subnet_id FROM devices WHERE mac=%s", (mac,))
            row = cur.fetchone()
            if row and row.get("last_subnet_id") is not None:
                return row["last_subnet_id"]
    except Exception as e:
        logger.warning(f"Presence: device subnet lookup failed: {e}")
    finally:
        if db:
            db.close()
    hex_mac = mac.replace(":", "").upper()
    kdb = None
    try:
        kdb = _get_kea_db()
        with kdb.cursor() as cur:
            cur.execute("SELECT subnet_id FROM lease4 WHERE HEX(hwaddr)=%s AND state=0", (hex_mac,))
            row = cur.fetchone()
            if row:
                return row["subnet_id"]
            cur.execute(
                "SELECT dhcp4_subnet_id AS subnet_id FROM hosts WHERE dhcp_identifier_type=0 AND HEX(dhcp_identifier)=%s",
                (hex_mac,),
            )
            row = cur.fetchone()
            if row and row["subnet_id"]:
                return row["subnet_id"]
    except Exception as e:
        logger.warning(f"Presence: lease/reservation subnet lookup failed: {e}")
    finally:
        if kdb:
            kdb.close()
    return None


def _current_ip_hostname(mac):
    """Best-effort current IP/hostname for a tracked MAC, from an
    active lease. Never raises — presence still publishes without
    this context if it fails."""
    hex_mac = mac.replace(":", "").upper()
    kdb = None
    try:
        kdb = _get_kea_db()
        with kdb.cursor() as cur:
            cur.execute(
                "SELECT inet_ntoa(address) AS ip, hostname FROM lease4 WHERE HEX(hwaddr)=%s AND state=0", (hex_mac,)
            )
            row = cur.fetchone()
            if row:
                return row.get("ip"), row.get("hostname")
    except Exception as e:
        logger.warning(f"Presence: lease lookup for {mac} failed: {e}")
    finally:
        if kdb:
            kdb.close()
    return None, None


# ── Candidates for the Track picker ──────────────────────────────────────────


def _candidate_hosts():
    out = []
    db = None
    try:
        db = _get_db()
        with db.cursor() as cur:
            cur.execute("SELECT mac, device_name, last_subnet_id FROM devices WHERE mac IS NOT NULL")
            for row in cur.fetchall():
                mac = _normalize_mac(row["mac"])
                if not mac:
                    continue
                sid = row.get("last_subnet_id")
                if not _can(sid):
                    continue
                out.append({"mac": mac, "label": row.get("device_name") or "", "subnet_id": sid})
    except Exception as e:
        logger.warning(f"Presence: device candidates failed: {e}")
    finally:
        if db:
            db.close()

    kdb = None
    try:
        kdb = _get_kea_db()
        with kdb.cursor() as cur:
            cur.execute(
                "SELECT inet_ntoa(address) AS ip, hostname, HEX(hwaddr) AS mac_hex, subnet_id "
                "FROM lease4 WHERE state=0 AND hwaddr IS NOT NULL"
            )
            for row in cur.fetchall():
                hex_mac = row.get("mac_hex") or ""
                if len(hex_mac) != 12:
                    continue
                mac = ":".join(hex_mac[i : i + 2] for i in range(0, 12, 2)).lower()
                sid = row.get("subnet_id")
                if not _can(sid):
                    continue
                if any(c["mac"] == mac for c in out):
                    continue
                out.append({"mac": mac, "label": row.get("hostname") or "", "subnet_id": sid})
    except Exception as e:
        logger.warning(f"Presence: lease candidates failed: {e}")
    finally:
        if kdb:
            kdb.close()
    return out


# ── MQTT client (impure: one connect-publish-disconnect cycle) ──────────────────


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise _PresenceError("MQTT connection closed before CONNACK")
        buf += chunk
    return buf


def _mqtt_publish(mqtt_info, username, password, client_id, messages):
    """messages: [(topic, payload_bytes, retain)]. Raises _PresenceError
    on any failure; never leaves a socket open."""
    sock = socket.create_connection((mqtt_info["host"], mqtt_info["port"]), timeout=_MQTT_TIMEOUT_S)
    try:
        if mqtt_info["use_tls"]:
            ctx = ssl.create_default_context()
            sock = ctx.wrap_socket(sock, server_hostname=mqtt_info["host"])
        sock.sendall(build_connect_packet(client_id, username, password))
        connack = _recv_exact(sock, 4)
        if connack[0] != 0x20 or connack[3] != 0x00:
            raise _PresenceError(f"MQTT CONNECT refused (return code {connack[3]})")
        for topic, payload_bytes, retain in messages:
            sock.sendall(build_publish_packet(topic, payload_bytes, retain))
        sock.sendall(build_disconnect_packet())
    except OSError as e:
        raise _PresenceError(str(e)[:200]) from e
    finally:
        sock.close()


# ── HTTP sinks (impure: urllib only) ─────────────────────────────────────────────


def _http_post_json(url, body, bearer=None):
    if not valid_http_url(url):
        raise _PresenceError("sink URL must be http:// or https://")
    data = json.dumps(body).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if bearer:
        headers["Authorization"] = f"Bearer {bearer}"
    req = urllib.request.Request(url, data=data, method="POST", headers=headers)
    ctx = ssl.create_default_context() if url.startswith("https://") else None
    try:
        with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT_S, context=ctx) as resp:
            status = resp.status
    except urllib.error.HTTPError as e:
        status = e.code
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise _PresenceError(str(e)[:200]) from e
    if status >= 400:
        raise _PresenceError(f"HTTP {status}")


def _send_to_sink(sink, mac, label, online, since_iso, ip, hostname, test=False):
    """One state message to one sink. `test=True` is the Send-test button: an HTTP sink's body
    carries `"test": true`, and an MQTT sink gets ONE non-retained message on `<prefix>/test`
    — no discovery, nothing on the device's real topics, so a test of a fake MAC never leaves a
    retained entity behind in Home Assistant."""
    payload = build_sink_payload(mac, label, online, since_iso, ip, hostname)
    if test:
        payload["test"] = True
    if sink["kind"] in ("ha_webhook", "http"):
        bearer = None
        if sink.get("credential"):
            from jen.plugin_api import decrypt_secret

            bearer = decrypt_secret(sink["credential"])
        _http_post_json(sink["url"], payload, bearer)
        return

    # kind == "mqtt"
    mqtt_info = parse_mqtt_url(sink["url"])
    if not mqtt_info:
        raise _PresenceError(f"invalid MQTT url {sink['url']!r}")
    password = None
    if sink.get("credential"):
        from jen.plugin_api import decrypt_secret

        password = decrypt_secret(sink["credential"])
    prefix = sink.get("topic_prefix") or "jen/presence"
    if test:
        client_id = mqtt_client_id(mac)
        _mqtt_publish(
            mqtt_info,
            mqtt_info.get("username"),
            password,
            client_id,
            [(f"{prefix}/test", json.dumps(payload).encode("utf-8"), False)],
        )
        return
    retain = bool(sink.get("retain"))
    state_payload = b"online" if online else b"offline"
    attrs_payload = json.dumps(payload).encode("utf-8")
    messages = [
        (mqtt_state_topic(prefix, mac), state_payload, retain),
        (mqtt_attributes_topic(prefix, mac), attrs_payload, retain),
    ]
    if sink.get("discovery"):
        disc_payload = json.dumps(mqtt_discovery_payload(mac, label, prefix)).encode("utf-8")
        messages.insert(0, (mqtt_discovery_topic(mac), disc_payload, True))
    client_id = mqtt_client_id(mac)
    _mqtt_publish(mqtt_info, mqtt_info.get("username"), password, client_id, messages)


def _enabled_sinks():
    db = None
    try:
        db = _get_db()
        with db.cursor() as cur:
            cur.execute(
                "SELECT id, name, kind, url, credential, topic_prefix, retain, discovery FROM pr_sinks WHERE enabled=1"
            )
            return cur.fetchall()
    except Exception as e:
        logger.error(f"Presence: could not list sinks: {e}")
        return []
    finally:
        if db:
            db.close()


def _record_sink_error(sink_id, error):
    db = None
    try:
        db = _get_db()
        with db.cursor() as cur:
            cur.execute("UPDATE pr_sinks SET last_error=%s WHERE id=%s", (error[:300], sink_id))
        db.commit()
    except Exception as e:
        logger.error(f"Presence: could not record sink error: {e}")
    finally:
        if db:
            db.close()


# ── Transitions ───────────────────────────────────────────────────────────────


def _tracked_label(mac):
    db = None
    try:
        db = _get_db()
        with db.cursor() as cur:
            cur.execute("SELECT label FROM pr_tracked WHERE mac=%s", (mac,))
            row = cur.fetchone()
            return row["label"] if row else ""
    except Exception:
        return ""
    finally:
        if db:
            db.close()


def _apply_transition(mac, online):
    """The one place a transition is recorded and published, whichever
    signal (a lease event or the periodic neighbour pass) triggered
    it."""
    db = None
    try:
        db = _get_db()
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO pr_state (mac, online, since, last_seen, misses) "
                "VALUES (%s, %s, UTC_TIMESTAMP(), UTC_TIMESTAMP(), 0) "
                "ON DUPLICATE KEY UPDATE online=VALUES(online), since=UTC_TIMESTAMP(), "
                "last_seen=UTC_TIMESTAMP(), misses=0",
                (mac, 1 if online else 0),
            )
        db.commit()
    except Exception as e:
        logger.error(f"Presence: could not record transition for {mac}: {e}")
        return
    finally:
        if db:
            db.close()

    label = _tracked_label(mac)
    ip, hostname = _current_ip_hostname(mac)
    since_iso = datetime.now(timezone.utc).isoformat()
    for sink in _enabled_sinks():
        try:
            _send_to_sink(sink, mac, label, online, since_iso, ip, hostname)
        except Exception as e:
            logger.warning(f"Presence: sink {sink.get('name')!r} failed for {mac}: {e}")
            _record_sink_error(sink["id"], str(e)[:300])
    _audit("PRESENCE_TRANSITION", mac, "online" if online else "offline")
    try:
        from jen.plugin_api import emit

        emit("plugin.presence.transition", mac=mac, detail="online" if online else "offline")
    except Exception as e:
        logger.warning(f"Presence: could not emit transition event: {e}")


def _tracked_macs():
    db = None
    try:
        db = _get_db()
        with db.cursor() as cur:
            cur.execute("SELECT mac FROM pr_tracked")
            return {r["mac"] for r in cur.fetchall()}
    except Exception as e:
        logger.error(f"Presence: could not list tracked macs: {e}")
        return set()
    finally:
        if db:
            db.close()


def _recorded_online(mac):
    """True / False for a device's recorded state, None when it has none yet."""
    db = None
    try:
        db = _get_db()
        with db.cursor() as cur:
            cur.execute("SELECT online FROM pr_state WHERE mac=%s", (mac,))
            row = cur.fetchone()
            return None if row is None else bool(row["online"])
    except Exception as e:
        logger.warning(f"Presence: could not read recorded state for {mac}: {e}")
        return None
    finally:
        if db:
            db.close()


def _on_lease_event(event):
    mac = (event.get("mac") or "").lower()
    if not mac or mac not in _tracked_macs():
        return
    online = event.get("kind") == "lease.new"
    # A lease.new for a device already recorded online (a renewal is reported the same way) is not a
    # transition: publishing it again would re-send, re-audit and re-emit an unchanged state.
    if _recorded_online(mac) is online:
        return
    _apply_transition(mac, online)


# ── Periodic neighbour-table pass ────────────────────────────────────────────


def _ip_binary():
    for candidate in ("ip", "/usr/sbin/ip", "/sbin/ip", "/bin/ip"):
        found = (
            shutil.which(candidate)
            if "/" not in candidate
            else (candidate if _os.access(candidate, _os.X_OK) else None)
        )
        if found:
            return found
    return None


def _local_networks(ip_bin):
    """The subnets the Jen host has an interface on, or None when they cannot be read."""
    try:
        result = subprocess.run([ip_bin, "-4", "-o", "addr", "show"], capture_output=True, text=True, timeout=10)
    except Exception as e:
        logger.warning(f"Presence: could not read the host's interface subnets: {e}")
        return None
    if result.returncode != 0:
        return None
    return parse_interface_networks(result.stdout)


def _tracked_subnets():
    """{mac: subnet_id} for every tracked device."""
    db = None
    try:
        db = _get_db()
        with db.cursor() as cur:
            cur.execute("SELECT mac, subnet_id FROM pr_tracked")
            return {r["mac"]: r["subnet_id"] for r in cur.fetchall()}
    except Exception as e:
        logger.error(f"Presence: could not list tracked subnets: {e}")
        return {}
    finally:
        if db:
            db.close()


def _local_macs(tracked, local_nets):
    """The subset of `tracked` whose ARP entries this host can see (see mac_is_local)."""
    subnets = _tracked_subnets()
    cidrs = {sid: info.get("cidr") for sid, info in _subnet_map().items()}
    out = set()
    for mac in tracked:
        ip, _hostname = _current_ip_hostname(mac)
        if mac_is_local(ip, cidrs.get(subnets.get(mac)), local_nets):
            out.add(mac)
    return out


def _neighbor_tick():
    tracked = _tracked_macs()
    if not tracked:
        return
    ip_bin = _ip_binary()
    if not ip_bin:
        logger.warning("Presence: no 'ip' binary found — skipping this neighbour pass")
        return
    local_nets = _local_networks(ip_bin)
    if not local_nets:
        # Without the host's own subnets a miss cannot be told from "not on my segment": count none.
        logger.warning("Presence: could not determine the host's interface subnets — skipping this neighbour pass")
        return
    # Only a device on a segment this host has an interface on can ever appear in its neighbour table.
    # For every other device the state follows lease events alone.
    tracked = _local_macs(tracked, local_nets)
    if not tracked:
        return
    try:
        result = subprocess.run([ip_bin, "-4", "neigh", "show"], capture_output=True, text=True, timeout=10)
    except Exception as e:
        logger.warning(f"Presence: could not read the neighbour table: {e}")
        return
    seen_by_mac = parse_neighbor_table(result.stdout if result.returncode == 0 else "")

    db = None
    try:
        db = _get_db()
        with db.cursor() as cur:
            # `tracked` is never empty here — the early return above
            # already handles that case.
            placeholders = ",".join(["%s"] * len(tracked))
            cur.execute(
                f"SELECT mac, online, misses FROM pr_state WHERE mac IN ({placeholders})",  # nosec B608 - only `%s` placeholders are interpolated; every value is bound
                tuple(tracked),
            )
            states = {r["mac"]: r for r in cur.fetchall()}
    except Exception as e:
        logger.error(f"Presence: could not read state for the neighbour pass: {e}")
        return
    finally:
        if db:
            db.close()

    transitions = []
    updates = []
    for mac in tracked:
        row = states.get(mac)
        state = "online" if (row and row["online"]) else "offline"
        misses = row["misses"] if row else 0
        seen = seen_by_mac.get(mac, False)
        new_state, new_misses, transitioned = next_presence_state(state, misses, seen)
        if transitioned:
            transitions.append((mac, new_state == "online"))
        elif new_misses != misses:
            updates.append((mac, new_misses))

    db = None
    try:
        db = _get_db()
        with db.cursor() as cur:
            for mac, new_misses in updates:
                cur.execute("UPDATE pr_state SET misses=%s WHERE mac=%s", (new_misses, mac))
            for mac in tracked:
                if seen_by_mac.get(mac) and not any(t[0] == mac for t in transitions):
                    cur.execute("UPDATE pr_state SET last_seen=UTC_TIMESTAMP() WHERE mac=%s", (mac,))
        db.commit()
    except Exception as e:
        logger.error(f"Presence: could not save neighbour-pass misses: {e}")
    finally:
        if db:
            db.close()

    for mac, online in transitions:
        _apply_transition(mac, online)


# ── Routes: page ────────────────────────────────────────────────────────────


def _tracked_rows():
    db = None
    try:
        db = _get_db()
        with db.cursor() as cur:
            cur.execute(
                "SELECT t.mac, t.label, t.subnet_id, s.online, s.since, s.last_seen "
                "FROM pr_tracked t LEFT JOIN pr_state s ON s.mac = t.mac ORDER BY t.label, t.mac"
            )
            return cur.fetchall()
    except Exception as e:
        logger.error(f"Presence: index error: {e}")
        return []
    finally:
        if db:
            db.close()


def _mark_lease_based(rows):
    """Add `lease_based` to each row: True when the device is not on a segment the Jen host has an
    interface on, so its state follows lease events only. None (unknown) when the host's own subnets
    cannot be read — the page then says nothing rather than guess."""
    ip_bin = _ip_binary()
    local_nets = _local_networks(ip_bin) if ip_bin else None
    if not local_nets:
        for r in rows:
            r["lease_based"] = None
        return rows
    local = _local_macs({r["mac"] for r in rows}, local_nets)
    for r in rows:
        r["lease_based"] = r["mac"] not in local
    return rows


def _sink_rows():
    db = None
    try:
        db = _get_db()
        with db.cursor() as cur:
            cur.execute(
                "SELECT id, name, kind, url, topic_prefix, retain, discovery, enabled, last_error FROM pr_sinks ORDER BY name"
            )
            return cur.fetchall()
    except Exception as e:
        logger.error(f"Presence: sink list error: {e}")
        return []
    finally:
        if db:
            db.close()


@bp.route("/")
@login_required
def index():
    rows = _mark_lease_based([r for r in _tracked_rows() if _can(r["subnet_id"])])
    return render_template(
        "presence/index.html",
        rows=rows,
        sinks=_sink_rows() if _is_admin() else [],
        candidates=_candidate_hosts() if _is_admin() else [],
        is_admin=_is_admin(),
        is_superadmin=_is_superadmin(),
    )


def _existing_tracked(mac):
    """The pr_tracked row for `mac`, or None."""
    db = None
    try:
        db = _get_db()
        with db.cursor() as cur:
            cur.execute("SELECT mac, subnet_id FROM pr_tracked WHERE mac=%s", (mac,))
            return cur.fetchone()
    finally:
        if db:
            db.close()


def _track(mac, label, source):
    """Track `mac` (or relabel it if it is already tracked). Returns a refusal message, or "".
    The subnet is the MAC's own, worked out here. An existing row is authorised on ITS subnet first
    and only its label is ever changed: the upsert used to overwrite `subnet_id`, so a scoped admin
    who knew a hidden device's MAC could re-track it into their own subnet and read its state."""
    existing = _existing_tracked(mac)
    if existing is not None:
        if not _can(existing["subnet_id"]):
            return "That device is not on a subnet you can access."
        subnet_id = existing["subnet_id"]
    else:
        subnet_id = _current_subnet_for_mac(mac)
        if not _can(subnet_id):
            return "That MAC is not on a subnet you can access."
    db = None
    try:
        db = _get_db()
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO pr_tracked (mac, label, subnet_id, added_by) VALUES (%s, %s, %s, %s) "
                "ON DUPLICATE KEY UPDATE label=VALUES(label)",
                (mac, label, subnet_id, current_user.username),
            )
        db.commit()
        _audit("PRESENCE_TRACK", mac, f"label={label}{source}")
    finally:
        if db:
            db.close()
    return ""


@bp.route("/track", methods=["POST"])
@login_required
def track():
    if not _require_write():
        return redirect(url_for("presence.index"))
    mac = _normalize_mac(request.form.get("mac", ""))
    if not mac:
        flash("Invalid MAC address.", "error")
        return redirect(url_for("presence.index"))
    label = request.form.get("label", "").strip()[:100]
    try:
        refusal = _track(mac, label, "")
    except Exception as e:
        flash(f"Could not track {mac}: {e}", "error")
        return redirect(url_for("presence.index"))
    if refusal:
        flash(refusal, "error")
    else:
        flash(f"Now tracking {label or mac}.", "success")
    return redirect(url_for("presence.index"))


@bp.route("/untrack/<mac>", methods=["POST"])
@login_required
def untrack(mac):
    if not _require_write():
        return redirect(url_for("presence.index"))
    mac = _normalize_mac(mac)
    row = _existing_tracked(mac) if mac else None
    if row is None or not _can(row["subnet_id"]):
        flash("Device not found.", "error")
        return redirect(url_for("presence.index"))
    db = None
    try:
        db = _get_db()
        with db.cursor() as cur:
            cur.execute("DELETE FROM pr_state WHERE mac=%s", (mac,))
            cur.execute("DELETE FROM pr_tracked WHERE mac=%s", (mac,))
        db.commit()
        flash("No longer tracked.", "success")
        _audit("PRESENCE_UNTRACK", mac, "untracked")
    except Exception as e:
        flash(f"Could not untrack {mac}: {e}", "error")
    finally:
        if db:
            db.close()
    return redirect(url_for("presence.index"))


# ── Row action target: "Track presence" (lease, device rows) ────────────────


@bp.route("/track-row", methods=["POST"])
@login_required
def track_from_row():
    if not _require_write():
        return redirect(url_for("presence.index"))
    mac = _normalize_mac(request.args.get("mac", ""))
    if not mac:
        flash("Invalid MAC address.", "error")
        return redirect(url_for("presence.index"))
    hostname = request.args.get("hostname", "").strip()[:100]
    # a `subnet_id` in the query string is ignored: the subnet is worked out from the MAC
    try:
        refusal = _track(mac, hostname, " source=row")
    except Exception as e:
        flash(f"Could not track {mac}: {e}", "error")
        return redirect(url_for("presence.index"))
    if refusal:
        flash(refusal, "error")
    else:
        flash(f"Now tracking {hostname or mac}.", "success")
    return redirect(url_for("presence.index"))


# ── Sinks admin ───────────────────────────────────────────────────────────────


@bp.route("/sinks/add", methods=["POST"])
@login_required
def add_sink():
    if not _require_superadmin():
        return redirect(url_for("presence.index"))
    name = request.form.get("name", "").strip()[:100]
    kind = request.form.get("kind", "")
    if kind not in ("ha_webhook", "mqtt", "http"):
        flash("Pick a supported sink type.", "error")
        return redirect(url_for("presence.index"))
    url = request.form.get("url", "").strip()[:255]
    if not url:
        flash("URL is required.", "error")
        return redirect(url_for("presence.index"))
    credential_raw = request.form.get("credential", "")
    if kind == "mqtt":
        info = parse_mqtt_url(url)
        if not info:
            flash("MQTT URL must look like mqtt://host:1883 or mqtts://host:8883 (a port from 1 to 65535).", "error")
            return redirect(url_for("presence.index"))
        if info.get("password"):
            # a password typed into the URL belongs in the encrypted credential, not in the stored URL
            credential_raw = credential_raw or info["password"]
            url = strip_url_password(url)
        if credential_raw and not info.get("username"):
            flash("An MQTT password needs a user name: use mqtt://user@host:1883.", "error")
            return redirect(url_for("presence.index"))
    elif not valid_http_url(url):
        flash("URL must start with http:// or https://.", "error")
        return redirect(url_for("presence.index"))
    topic_prefix = request.form.get("topic_prefix", "jen/presence").strip()[:100] or "jen/presence"
    retain = 1 if request.form.get("retain") else 0
    discovery = 1 if request.form.get("discovery") else 0
    credential = ""
    if credential_raw:
        from jen.plugin_api import encrypt_secret

        credential = encrypt_secret(credential_raw)

    db = None
    try:
        db = _get_db()
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO pr_sinks (name, kind, url, credential, topic_prefix, retain, discovery) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s)",
                (name, kind, url, credential, topic_prefix, retain, discovery),
            )
        db.commit()
        flash(f"{name} added.", "success")
        _audit("PRESENCE_ADD_SINK", name, f"kind={kind}")
    except Exception as e:
        flash(f"Could not add sink: {e}", "error")
    finally:
        if db:
            db.close()
    return redirect(url_for("presence.index"))


@bp.route("/sinks/<int:sink_id>/toggle", methods=["POST"])
@login_required
def toggle_sink(sink_id):
    if not _require_superadmin():
        return redirect(url_for("presence.index"))
    db = None
    try:
        db = _get_db()
        with db.cursor() as cur:
            cur.execute("SELECT enabled FROM pr_sinks WHERE id=%s", (sink_id,))
            row = cur.fetchone()
            if row is None:
                flash("Sink not found.", "error")
                return redirect(url_for("presence.index"))
            new_enabled = 0 if row["enabled"] else 1
            cur.execute("UPDATE pr_sinks SET enabled=%s WHERE id=%s", (new_enabled, sink_id))
        db.commit()
        flash("Sink enabled." if new_enabled else "Sink paused.", "success")
    except Exception as e:
        flash(f"Could not update sink: {e}", "error")
    finally:
        if db:
            db.close()
    return redirect(url_for("presence.index"))


@bp.route("/sinks/<int:sink_id>/delete", methods=["POST"])
@login_required
def delete_sink(sink_id):
    if not _require_superadmin():
        return redirect(url_for("presence.index"))
    db = None
    try:
        db = _get_db()
        with db.cursor() as cur:
            cur.execute("DELETE FROM pr_sinks WHERE id=%s", (sink_id,))
        db.commit()
        flash("Sink removed.", "success")
        _audit("PRESENCE_DELETE_SINK", str(sink_id), "sink removed")
    except Exception as e:
        flash(f"Could not remove sink: {e}", "error")
    finally:
        if db:
            db.close()
    return redirect(url_for("presence.index"))


@bp.route("/sinks/<int:sink_id>/test", methods=["POST"])
@login_required
def test_sink(sink_id):
    if not _require_superadmin():
        return redirect(url_for("presence.index"))
    db = None
    try:
        db = _get_db()
        with db.cursor() as cur:
            cur.execute(
                "SELECT id, name, kind, url, credential, topic_prefix, retain, discovery FROM pr_sinks WHERE id=%s",
                (sink_id,),
            )
            sink = cur.fetchone()
    finally:
        if db:
            db.close()
    if not sink:
        flash("Sink not found.", "error")
        return redirect(url_for("presence.index"))
    try:
        _send_to_sink(
            sink,
            "aa:bb:cc:dd:ee:ff",
            "Test device",
            True,
            datetime.now(timezone.utc).isoformat(),
            None,
            None,
            test=True,
        )
        flash(f"Test message sent to {sink['name']}.", "success")
    except Exception as e:
        flash(f"Test failed: {e}", "error")
        _record_sink_error(sink_id, str(e)[:300])
    return redirect(url_for("presence.index"))


def register(app):
    app.register_blueprint(bp)

    from jen.plugin_api import register_periodic, register_row_action, subscribe

    for surface in ("lease", "device"):
        register_row_action(
            PLUGIN_ID,
            surface,
            label="Track presence",
            icon="wifi",
            href="/management/presence/track-row?mac={mac}&hostname={hostname}",
            method="POST",
        )

    subscribe("lease.new", _on_lease_event)
    subscribe("lease.expired", _on_lease_event)
    register_periodic(PLUGIN_ID, "neighbor-tick", _neighbor_tick, _NEIGH_TICK_MINUTES)

    logger.info("Presence plugin registered")
