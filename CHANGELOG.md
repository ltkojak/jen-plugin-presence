# Presence Plugin — Changelog

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
