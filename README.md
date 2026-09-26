# Presence — Jen Plugin

Publishes tracked devices' online/offline state to [Home Assistant](https://www.home-assistant.io/) (a webhook), MQTT, or any HTTP endpoint, so the house can react to a phone joining or leaving the network.

> **Opt-in, and IPv4 only.** Only devices you explicitly track publish anything — nothing is published for a MAC you haven't chosen. Presence identifies devices by their IPv4-side lease/neighbour activity; this isn't a bug or a gap to report, it's a deliberate scope decision, the same one every other bundled plugin makes.

## Requirements

- [Jen](https://github.com/ltkojak/jen-kea) v5.65.6 or later

## How a device is judged online or offline

Two signals feed one state per tracked device:

- **Lease events** (`lease.new` / `lease.ip_changed` / `lease.expired`) — Kea has already decided the device is there or gone, so these apply immediately, no delay. A `lease.expired` marks a device offline only when no other active lease remains for its MAC, and every handled lease event refreshes the device's stored subnet, so a client that moves subnet follows it.
- **A periodic pass** over `ip -4 neigh show` (the same table [Network Discovery](https://github.com/ltkojak/jen-plugin-network-discovery) reads), every 5 minutes — Jen's own floor for any plugin's periodic job. A device counts as *seen* on a pass only when its neighbour entry is `REACHABLE`, `DELAY`, or `PROBE` (actively confirmed, or being actively reconfirmed); anything else, including a `STALE` entry, does not. Any single sighting flips a device online at once; going *offline* needs **three consecutive** passes with no sighting, so one missed ARP probe cycle never flips a device early.

**A limitation to know about:** `ip -4 neigh` only ever holds hosts on a segment the Jen host has an interface on. Each pass therefore reads the host's own interface subnets (`ip -4 -o addr show`) and counts a miss only for a tracked device on one of them. A device anywhere else (behind a router, on a VLAN Jen has no interface in) is **lease-based**: it is online from its lease and offline when the lease expires, never from a probe, and the page says "lease-based" beside its state. If the host's own subnets cannot be read, the pass counts nothing.

## Sinks

Add one or more sinks (Presence → Sinks) and every transition is sent to all of them:

- **Home Assistant webhook** — `POST <ha>/api/webhook/<id>` with a JSON body; HA needs no separate auth token for a webhook
- **MQTT** — this plugin ships its own minimal MQTT 3.1.1 publish-only client (no external dependency), connecting fresh for each transition: publishes the state (`online`/`offline`) to `<prefix>/<mac-with-dashes>`, JSON attributes (ip, hostname, since) to `<prefix>/<mac-with-dashes>/attributes`, and — opt-in per sink — a retained Home Assistant MQTT discovery message so the device shows up as a `device_tracker` entity automatically
- **Generic HTTP** — a JSON `POST` with the same body shape as the Home Assistant webhook, for anything else that can receive one

Every sink send has a 10-second timeout; a failure records `last_error` on the sink and is retried on the next transition — nothing is queued or retried immediately.

## Features

- **Track** row action on Lease and Device rows, plus a picker (over reservations and leases) on the Presence page itself
- Respects Jen's subnet access control on both the tracked-device list and the picker
- **Send test** on any sink, to confirm credentials and connectivity without waiting for a real transition (one non-retained message on `<prefix>/test`, or an HTTP body marked `"test": true`; nothing durable)
- Credentials (an MQTT password, or an HTTP bearer token) are stored encrypted and never shown again once saved

Adding, removing, and tracking a device need admin — viewers are read-only. **Sinks are superadmin-only**: every transition publishes every tracked device's MAC, label, IP, hostname and state to every enabled sink, so adding, pausing, testing or removing one is a global integration change, like an Alerts channel (other admins see the list read-only). A tracked device belongs to the subnet its MAC is in (worked out server-side, never from a value in the request), and re-tracking an existing device can only change its label.

## Installation

Open Jen → **Settings → Plugins** and click **Install** next to Presence. Jen downloads the release pinned in its plugin registry, verifies its checksum, and enables it; restart Jen when prompted.

To install by hand instead (a checkout without registry access), unzip `plugin.zip` from the release tag you want into `/var/lib/jen/plugins/presence/`, then enable it from Settings → Plugins and restart Jen.

## Development

`python3 tools/verify.py --build` rebuilds `plugin.zip` deterministically from the tree and runs the same checks CI runs on every push and tag: the zip matches the tree byte-for-byte, no template carries an inline event handler, an inline `style=` attribute, an un-nonce'd `<script>`, or a POST form missing `csrf_token`, `manifest.json`'s version matches the top `CHANGELOG.md` entry, and `plugin.py` compiles and passes ruff. The committed `plugin.zip` is the artifact Jen installs, so rebuild it in the same commit as any change.

`python3 tools/test_plugin.py` exercises every pure function — the MQTT packet encoder (checked byte-range by byte-range against the OASIS MQTT 3.1.1 spec, for CONNECT with and without a username/password, PUBLISH, and DISCONNECT), MQTT URL parsing, the neighbour-table parser, the offline-debounce state machine, and every sink payload/topic builder — plus calls `register(app)` end to end against a stub `jen.plugin_api`, no Jen, database, or network access needed.

## Version History

See [CHANGELOG.md](CHANGELOG.md).

## License

GPL v3 — Copyright 2026 Matthew Thibodeau
