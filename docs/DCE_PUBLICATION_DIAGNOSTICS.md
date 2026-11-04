# Bounded publication diagnostics

`--publish-diagnostics` is **off by default**. It enables fixed server counters and at most8 diagnostic stderr lines for the whole process. It adds no route, timer, live probe, retry, credential or activation action. Public HTTP bodies/status/headers and UDP bytes remain unchanged. Existing ordinary startup output is unchanged; the8-line bound applies specifically to `dce_publish_diag` lines.

Each line contains only a fixed stage label, saturating count and event ordinal:

```
dce_publish_diag stage=advertisement_players_capacity count=1 event=1/8
```

No publisher/master identifiers, keys, signatures, nonces, tickets, request bodies, packet bytes, addresses, endpoints or arbitrary error strings are formatted or retained by these diagnostics. Counters continue after the eighth line; no HTTP endpoint exposes them and no remote request resets the logging cap. Library tests can read the fixed counter snapshot.

## Failure-stage mapping

| Stage | Meaning | Guest phase |
|---|---|---|
|`advertisement_json`|Authenticated body failed JSON/object/type parsing; no content logged|5 HTTP|
|`advertisement_field_names`, `advertisement_field_presence`|Unknown/duplicate/noncanonical fields, missing/null fields|5 HTTP|
|`advertisement_protocol`, `family`, `network_version`, `mode`, `score`, `players_capacity`, `sequence`, `name`, `instance`, `game_port`, `time` (each prefixed `advertisement_`)|Fixed typed validation rule failed; first classification only, no rejected value|5 HTTP|
|`advertisement_id`|Derived instance id differs from signed request path|5 HTTP|
|`candidate_address`|Constrained candidate rejected by existing address policy|5 HTTP|
|`publish_owner`, `publish_sequence`, `publish_quota`, `publish_random`|Existing publication refusal: ownership403, sequence409, quota429 or entropy500|5 HTTP|
|`ticket_accepted`|Server created pending proof and generated202 response; does not prove client received it|5 HTTP →6 ticket|
|`probe_scheduled`|Existing bounded scheduler returned a challenge for sending|7 proof|
|`probe_send_ok`, `probe_send_failed`|Kernel send accepted full datagram, or send error/short write; no error text logged|7 proof|
|`ack_format`, `ack_address`|Wrong length/magic/kind, or forbidden source address|7 proof|
|`ack_ticket`|Unknown, consumed or already-swept ticket (including expired tickets after cleanup)|7 proof|
|`ack_expired`, `ack_unsent`, `ack_source`, `ack_nonce`|Recognized pending proof failed expiry/send/source/nonce check|7 proof|
|`ack_rate`, `ack_signature`|ACK verification throttled or host proof rejected|7 proof|
|`ack_accepted`|Exact observed source and host signature accepted; existing90-second catalog row created|7 proof|

Advertisement/candidate counters occur **after** existing approved-key, timestamp, signature and nonce acceptance; they expose no authentication material. The primary validator remains unchanged. Diagnostic classification does not replace or relax validation. Multiple invalid fields may yield only the first fixed rule label.

A guest's local `ack_sent` counter is only local send acceptance; it is not this server's `ack_accepted`. Likewise `probe_send_ok` does not prove delivery. No ACK events after challenge sending narrows investigation to delivery/receive paths but does not identify which network device dropped traffic. A created row can subsequently expire; acceptance does not establish browser catalog delivery, game joining or gameplay.

## Resource and evidence boundaries

Measured amd64 object size304 bytes:34 uint64 counters plus mutex/output bookkeeping. Server gains an8-byte diagnostics pointer; off-default pointer remains nil, allocates no diagnostic object and the recording call performs no allocation. After the logging cap, recording allocates zero bytes. Each diagnostic line fits128 bytes, so diagnostic text is at most1024 bytes per process. Fixed label strings/code are additional static binary data; these component bounds are not whole-process RAM quotas.

The first8 stderr writes are synchronous and may occur under the existing server mutex. Bounded output bytes do not guarantee bounded latency if the operator's stderr sink blocks. Off/default and post-cap paths perform no log writes; no background logging queue is introduced.

DC RAM/VRAM/AICA delta0 bytes; this is server-only source. No version/image change. Tests cover rejection stages, send/ACK stages, saturation,8-line cap, secret-free vocabulary, zero disabled/post-cap allocations and exact enabled/disabled HTTP/UDP comparisons. Deployment/restart and actual host probing require root's separate review; these files do not activate diagnostics or identify the live failure by themselves.
