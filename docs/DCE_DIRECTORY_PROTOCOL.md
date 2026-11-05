# DCE directory extension v1

Separate DCE discovery namespace and executable. Native OpenCE `/v1/servers` and native invites are unchanged and are not implemented by this executable. This protocol advertises **DCE_NET3** only; listing is not proof of successful game join or gameplay parity.

## HTTP authentication

HTTPS required, except direct loopback testing. Only explicitly configured proxies may supply forwarded client/scheme headers. Hosts have separate persistent Ed25519 keys, approved through a local operator allowlist. No shared private key ships with a client. Master identity is pinned separately for each pool.

Reuse upstream `internal/sign/request.go` byte for byte:

```
Authorization: OpenCE-Ed25519 keyid=<16 lowercase hex>, ts=<UTC seconds>, nonce=<32 lowercase hex>, sig=<base64 64-byte signature>
```

Sign the following UTF-8 bytes, joined by LF with **no trailing LF**:

```
OpenCE-Master-v1
<receiving master's 16-character lowercase key id>
<uppercase HTTP method>
<exact request path, no query>
<decimal ts>
<32-character nonce>
<lowercase hex SHA-256 of exact request body bytes>
```

Clock tolerance300 seconds; nonce replay memory600 seconds, retained in a separate SQLite DB. Keys must be on the local approved list. Maximum HTTP body2048 bytes. Requests with query strings, noncanonical paths, unknown JSON fields or trailing JSON are rejected for writes. DELETE body is empty. Server id is upstream `sign.ServerID(keyid, instance)` = first8 bytes SHA256(ASCII keyid || ASCII instance), rendered16 lowercase hex. Each instance is16 lowercase random hex per host session. A different key cannot update/remove the id.

Every successful JSON response has `Signature: ed25519=<base64 signature of exact body bytes>`, `Signature-Key: <master key id>`, `Signature-Time: <UTC seconds>` and exposes these headers through CORS. List body `master.time` equals `Signature-Time`. Verify pinned master key, key id, timestamp and exact body signature before reading entries.

## Register and refresh

`PUT /v1/dce/servers/<id>` authenticates the exact body:

```json
{"protocol":1,"family":"dce-net","network_version":4,"build":305419896,"map":0,"map_crc":123456789,"mode":0,"score":15,"players":1,"capacity":2,"flags":0,"name":"Test game","sequence":1,"time":1793800000,"instance":"0123456789abcdef","game_port":5150}
```

Bounds: build/map_crc/sequence unsigned32; sequence>=1 and strictly newer than last accepted PUT for this live instance; map0..255 (client checks installed maps), mode0|1, score10|15|25|50, players1..capacity, capacity2..8, flags0..3 (bit 0 dial-up limits apply, bit 1 vehicles on); name1..32 printable ASCII bytes, no surrounding whitespace; time within300 seconds of master; game_port1024..65535. Family/protocol/network_version exact as above. No endpoint IP/address is accepted. Trusted HTTP client IP is only a **candidate**, never proof of a game endpoint. A local operator may configure a specific candidate IPv4 override for a particular approved key (for example, a browser gateway or a reviewed LAN host). Without an override, differing HTTP/UDP egress fails closed.

Successful PUT returns202 and a signed challenge descriptor:

```json
{"protocol":1,"family":"dce-net","id":"<16hex>","master":{"key_id":"<16hex>","time":1793800000},"ticket":"<32hex>","expires":1793800030,"interval":30,"ttl":90}
```

Ticket expires30 seconds after PUT. Directory sends a signed UDP challenge from its own outbound socket to the candidateIP and signed game_port. Host answers from its **actual game UDP socket** (the browser uses its actual UDP gateway socket). Never open a separate ephemeral probe socket. The directory needs no fixed inbound UDP port: its outbound probe establishes its own NAT return mapping. The host still needs a reachable game endpoint/forwarding or approved LAN route; this protocol does not provide gameplay relay or NAT traversal. Heartbeat every30 seconds repeats PUT with new sequence/time/nonce, then proves endpoint again. A retry is a new PUT/sequence and replaces the older ticket. The previous proven row remains only until its original90-second proof expiry; new metadata becomes visible only after new proof. A challenge may arrive before the HTTP response; the client keeps at most one bounded pending challenge and answers only after matching the signed HTTP ticket.

## UDP source and ownership proof

Each packet is exactly121 bytes, never a DCE game packet:

| Offset | Bytes | Field |
|---|---:|---|
|0|8|ASCII `DCEDIR1` followed by NUL|
|8|1|kind2 challenge,3 acknowledgement; kind1 is not used|
|9|16|raw ticket bytes from signed PUT response|
|25|32|random directory challenge nonce|
|57|64|Ed25519 signature|

Signature input is ASCII `DCE-Directory-UDP-v1\n` (one actual LF), then raw master key id8 bytes, then packet bytes0..56 inclusive. Acknowledgement is signed by the approved host key. Challenge is signed by the pinned master key; host verifies it and the ticket before answering, to the challenge packet's actual source tuple.

Only a correctly signed, approved HTTP PUT schedules a challenge, to the constrained candidate tuple. Directory sends at most3 identical121-byte challenges per ticket, at0/2/4 seconds, with per-address/per-key/global bounded rate limits. PUT bodies are larger than a challenge. No arbitrary publisher-selected IP, unsolicited scan, or UDP amplification service exists. Incoming UDP never triggers another UDP response. Private/reserved/multicast candidates are refused by production configuration; explicit loopback test mode permits loopback only.

The acknowledgement must come from the exact candidate tuple, with correct ticket, nonce and valid host signature, before expiry. Only this **observed UDP source** is published. It consumes the ticket and proves the actual game endpoint for90 seconds. Changed source, replayed acknowledgement, bad signature, wrong master, stale ticket or nonce are silently ignored. New public endpoint requires new PUT/proof. For an explicitly reviewed LAN test, an operator may allow a specific RFC1918 subnet with `--allow-private-lan-cidr`; this is never the production default. A Cloudflare HTTPS tunnel is not a game UDP route.

## List and remove

`GET /v1/dce/servers` returns a signed JSON envelope, sorted by id, maximum64 rows. `?limit=16` selects at most16 rows for bounded clients; limit1..64 only, no other query parameter. Signed `truncated` is true when more eligible rows exist. Default limit64. Dreamcast clients bound response16KiB and request limit16.

```json
{"protocol":1,"family":"dce-net","network_version":4,"master":{"key_id":"<16hex>","time":1793800001},"ttl":90,"truncated":false,"servers":[{"id":"<16hex>","key_id":"<16hex>","protocol":1,"family":"dce-net","network_version":4,"build":305419896,"map":0,"map_crc":123456789,"mode":0,"score":15,"players":1,"capacity":2,"flags":0,"name":"Test game","sequence":1,"time":1793800000,"instance":"0123456789abcdef","game_port":5150,"endpoint":{"ip":"203.0.113.1","port":5150},"updated":1793800001,"expires":1793800091,"reachable":true}]}
```

Example address is documentation-only; production never accepts documentation ranges. Rows are present only while proof is fresh and key still approved. `updated` and `expires` are master times of proof/expiry, not host claims. Client checks exact build, network version, map and content CRC before offering existing DCE join; joining still performs the real DCE handshake. No native invite or relabelled native listing exists. Reads are rate limited60/min per address. No default cross-pool fallback.

`DELETE /v1/dce/servers/<id>` uses approved owner's signature and empty body, removes pending/proven row and returns signed `{ "ok": true }`. Unknown id can be removed idempotently; existing other-owner id is forbidden. Send once on leave with bounded retries; expiry handles lost DELETE.

## Initial operational bounds

At most4 tracked instances per approved key,64 globally; bounded pending tickets and rate-limit keys. Ephemeral listings/proofs clear on process restart, so no stale endpoint is restored. Signing key, approval file and persistent nonce DB are outside Git. Separate DCE process and separate key/DB from native master. No HTTP admin/apply/key-enrollment endpoint. Deployment and game/WAN acceptance require separate review.
