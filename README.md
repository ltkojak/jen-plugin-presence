# Presence — Jen Plugin

Publishes tracked devices' online/offline state to [Home Assistant](https://www.home-assistant.io/) (a webhook), MQTT, or any HTTP endpoint, so the house can react to a phone joining or leaving the network.

> **Opt-in, and IPv4 only.** Only devices you explicitly track publish anything — nothing is published for a MAC you haven't chosen. Presence identifies devices by their IPv4-side lease/neighbour activity; this isn't a bug or a gap to report, it's a deliberate scope decision, the same one every other bundled plugin makes.

## Requirements

- [Jen](https://github.com/ltkojak/jen-kea) v5.68.0 or later

## How a device is judged online or offline

Two signals feed one state per tracked device:

- **Lease events** (`lease.new` / `lease.ip_changed` / `lease.expired`) — Kea has already decided the device is there or gone, so these apply immediately, no delay. A `lease.expired` marks a device offline only when no other active lease remains for its MAC, and a lease event updates the device's state only: it never changes the subnet the tracking is filed under.
- **A periodic pass** over `ip -4 neigh show` (the same table [Network Discovery](https://github.com/ltkojak/jen-plugin-network-discovery) reads), every 5 minutes — Jen's own floor for any plugin's periodic job. A device counts as *seen* on a pass only when its neighbour entry is `REACHABLE`, `DELAY`, or `PROBE` (actively confirmed, or being actively reconfirmed); anything else, including a `STALE` entry, does not. A tracked device the table does not show as seen, and that holds a lease, is then **asked**: Jen sends one empty UDP datagram to its address (port 9, discard), which makes the host's kernel ask the device by ARP, waits nine seconds, and counts the device as seen when its entry has become `REACHABLE`. Without this a phone at home that the Jen host never talks to was never in one of those states and was called offline. At most 64 devices are asked on one pass. When more than 64 tracked devices are unseen, every unseen device is asked in turn, the one asked longest ago first (since 1.2.8; a device never asked goes before all of them), and a device that was not asked on a pass is neither seen nor missed on it: its state waits for its turn, so with 200 unseen devices one that has left is called offline after about an hour instead of fifteen minutes (since 1.2.7). When Kea's lease database cannot be read, nobody can be asked, and no device is counted as missed until it can be read again (since 1.2.8). The same holds when the datagrams could not be sent, or the neighbor table could not be read after they were: nobody was asked, so no device is counted as missed on that pass (since 1.2.9). Any single sighting flips a device online at once; going *offline* needs **three consecutive** passes with no sighting, so one missed ARP probe cycle never flips a device early.

**A limitation to know about:** `ip -4 neigh` only ever holds hosts on a segment the Jen host has an interface on. Each pass therefore reads the host's own interface subnets (`ip -4 -o addr show`) and counts a miss only for a tracked device on one of them. A device anywhere else (behind a router, on a VLAN Jen has no interface in) is **lease-based**: it is online from its lease and offline when the lease expires, never from a probe, and the page says "lease-based" beside its state. If the host's own subnets cannot be read, the pass counts nothing.

## Destinations

Add one or more destinations (Presence → Publish To → Add Destination) and every transition is sent to all of them that are not paused. The page called a destination a *sink* before 1.2.9, and the routes, the `pr_sinks` table and the audit actions still do. With no destination the state is still recorded and shown on the Presence page, and nothing is sent. A destination is sent only the changes that happen after it was added, so add it before the devices it should hear about.

- **Home Assistant webhook** — `POST <ha>/api/webhook/<id>` with a JSON body; HA needs no separate auth token for a webhook
- **MQTT** — this plugin ships its own minimal MQTT 3.1.1 publish-only client (no external dependency), connecting fresh for each transition: publishes the state (`online`/`offline`) to `<prefix>/<mac-with-dashes>`, JSON attributes (ip, hostname, since) to `<prefix>/<mac-with-dashes>/attributes`, and — opt-in per destination — a retained Home Assistant MQTT discovery message so the device shows up as a `device_tracker` entity automatically
- **Generic HTTP** — a JSON `POST` with the same body shape as the Home Assistant webhook, for anything else that can receive one

Every send has a 10-second timeout; a failure records `last_error` on the destination and is retried on the next transition — nothing is queued or retried immediately.

## Features

- **Track presence** row action on Lease and Device rows, plus **Track Device** on the Presence page itself, with a picker over reservations and leases
- With nothing tracked yet the page shows a **Getting started** card in place of an empty table: the destination first, then the device, then what Jen does by itself
- Respects Jen's subnet access control on both the tracked-device list and the picker. `pr_tracked.subnet_id` is the **owner subnet** of a tracking (v1.2.0): written when the device is tracked, changed only by an admin's explicit **Move** (who must be able to see both subnets; audited), never by a lease event. Visibility, relabel, untrack and the card judge on it; where the device is now is derived when the page is read and shown (*now in …*) only to an account that may see that subnet. A device that had followed a client under an older release keeps the subnet it has: move it by hand if it should belong elsewhere
- **On the Investigation page** (Jen 5.68.0): a card under "What else Jen knows" for a tracked device — online or offline, since when, last seen, and (to an admin) which destinations it is published to. A tracked device is judged by the subnet it was tracked in, so it is not shown to an account that cannot see that subnet just because the device has since moved into one it can; where the device is now is shown only when the account may see that subnet too
- **Investigate** on every tracked row, Jen's own action for a row that names a client
- **Send Test** on any destination, to confirm credentials and connectivity without waiting for a real transition (one non-retained message on `<prefix>/test`, or an HTTP body marked `"test": true`; nothing durable)
- Credentials (an MQTT password, or an HTTP bearer token) are stored encrypted and never shown again once saved

Adding, removing, and tracking a device need admin — viewers are read-only. **Destinations are superadmin-only**: every transition publishes every tracked device's MAC, label, IP, hostname and state to every enabled destination, so adding, pausing, testing or removing one is a global integration change, like an Alerts channel (other admins see the list read-only). A tracked device belongs to the subnet its MAC is in (worked out server-side, never from a value in the request), and re-tracking an existing device can only change its label.

## Recorded for the audit trail, not displayed

`pr_tracked.added_by` (the username that first tracked the device) and `pr_tracked.added_at` are written when a device is tracked and read by nothing in this plugin, so no page, card or event shows who started tracking a device or when. They stay in the table as the record of how each device came to be tracked and are not dropped. (The *Move* of a tracked device is audited in Jen's own audit log with both subnets.)

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
