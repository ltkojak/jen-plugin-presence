# Presence Plugin — Changelog

## [1.0.1] - 2026-09-25

Requires Jen 5.65.2 or later (the `can_access_subnet` helper in the plugin API).

### Fixed: any admin could send every tracked device's state to a server they control

A sink receives every tracked client's MAC, label, IP, hostname and online state, for every device on every subnet, and the sink routes only checked "admin". An admin scoped to one subnet could add an HTTP or MQTT sink they control and from then on receive presence events for subnets they cannot see, and gained a general outbound HTTP and MQTT capability from the Jen host. A sink is a global integration with a credential, like an Alerts channel: adding, pausing or enabling, testing and removing one is now **superadmin-only**. Other admins see the list read-only.

### Fixed: routes authorised one thing and acted on another

The pattern this release names in every plugin: a route authorises on one thing (a subnet id the caller typed, or nothing for a by-id POST) and acts on another, or reads "no subnet" as "allow".

- **Tracking upserted over a hidden row.** The upsert overwrote `subnet_id`, so a scoped admin who knew the MAC of a device tracked in a subnet they cannot see could re-track it into their own and then see its state. The subnet is now the MAC's own (device, active lease, reservation), worked out here; an already-tracked MAC is authorised on its existing row first, and only its label can change, never its subnet.
- **"Track presence" from a row** authorised the `subnet_id` in the query string. It is ignored; the subnet comes from the MAC. The row action link no longer carries it, and the Track form no longer asks for an IP.
- **Untrack** by MAC checked nothing about the row; it now reads as not found unless the row's subnet is the caller's. A device with no subnet is for unrestricted callers only.

### Fixed: devices off the Jen host's own segment flapped offline

The neighbour pass reads `ip -4 neigh`, which only holds hosts on a segment the Jen host has an interface on. A tracked phone on any other subnet was never in it, so it "missed" three passes and went offline fifteen minutes after joining, and stayed there, because a renewal emits nothing. A pass now reads the host's own interface subnets (`ip -4 -o addr show`) and counts a miss only for a device on one of them. For every other device the state follows lease events alone, and the page says "lease-based" beside it. If the host's own subnets cannot be read, the pass counts nothing rather than guess. The README now states the limitation: a device that is not on a segment the Jen host is attached to is online from its lease and offline when the lease expires, not from a probe.

### Fixed: smaller things

- A bad MQTT port (`mqtt://host:abc`, `:99999`, `:0`) made the Add Sink form answer with a 500; the port is now read inside the validation, and the form shows its message.
- A `lease.new` for a device already recorded online (a renewal is reported the same way) re-published, re-audited and re-emitted an unchanged state. The lease path now acts only on a change, like the neighbour path.
- **Send test** published a retained Home Assistant discovery message for a made-up MAC, leaving a phantom entity behind. It now sends one non-retained message to `<prefix>/test` (an HTTP sink's body carries `"test": true`) and touches nothing else.
- An MQTT password with no user name broke MQTT-3.1.2-22 (the password flag must not be set without the user name flag); both the form and the packet builder refuse it.
- A `user:password@` password typed into an MQTT URL was stored in the URL column in clear. It is moved to the encrypted credential and the stored URL keeps only the user name.
- A webhook sink's bearer token was stored and then ignored; it is now sent, as it always was for a generic HTTP sink.
- Webhook and HTTP sinks accepted any URL scheme, including `file://`; they must be `http://` or `https://`.
- The MQTT client id was 25 characters (`jen-presence-` and 12 hex digits); MQTT 3.1.1 only guarantees 23. It is now `jen-pr-` and the 12 digits.
- The Home Assistant discovery message gains `json_attributes_topic`, so the attributes Presence already publishes show up on the entity.

### Changed

- The page's static styling moved out of inline `style=` attributes into its own `<style>` block; `tools/verify.py` now fails a template that carries one.
- The one dynamic `IN (...)` builder carries a one-line `# nosec B608` saying why it is safe.
- `tools/test_plugin.py` now runs the real routes, the neighbour pass, the lease path and the sink sender against fakes.

## [1.0.0] - 2026-09-24

### First release

Publishes tracked devices' online/offline state to Home Assistant, MQTT,
or any HTTP endpoint, so the house can react to a phone joining or
leaving the network. Only devices you explicitly track publish
anything, and each has two signals feeding its state: a Kea lease
event flips it immediately, and a periodic pass over the neighbour
table catches everything else — a single missed ARP probe cycle never
flips a device offline early, only three consecutive misses does.

MQTT is handled by this plugin's own minimal publish-only client, with
no external dependency: a fresh connection per transition, TLS
optional, an optional retained Home Assistant discovery message per
sink so a tracked device shows up as a `device_tracker` entity
automatically. Home Assistant webhooks and generic HTTP endpoints get
the same JSON body. Every sink can be sent a test message on demand,
and a failure records its own error without blocking any other sink
or queuing a retry.

A "Track presence" action is available straight from Jen's Lease and
Device rows. Everything respects Jen's subnet access control.

Built on Jen 5.57.0's plugin API v3 from the first commit: sprite
icons, a phone-ready rowlist, and no inline styles.
