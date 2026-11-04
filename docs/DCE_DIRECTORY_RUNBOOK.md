# DCE directory extension: local qualification

This separate Go command serves DCE_NET3 discovery only. It does not change native OpenCE routes, native invites, the native master's state or running service. See [wire contract](DCE_DIRECTORY_PROTOCOL.md). The implementation reuses upstream Ed25519 canonical requests/signed bodies, SQLite replay protection, proxy-origin parsing, address policy and bounded token buckets. It is an AGPL-3.0-or-later derivative; preserve LICENSE and provide corresponding source when deployed.

## Build and check

```sh
CGO_ENABLED=0 go build -o dce-directory ./cmd/dce-directory
go test ./internal/dcedirectory ./cmd/dce-directory
go vet ./internal/dcedirectory ./cmd/dce-directory
```

Fixed synthetic interoperability vectors: `testdata/dce_directory_vectors.json`. Test keys are public fixtures, never deployment or VMU credentials. After an agreed protocol change only, regenerate with `go test ./internal/dcedirectory -run TestDCEVectorsFile -update-dce-vectors`; keep game-client copy byte-identical. Tests cover actual loopback HTTP and UDP socket exchange, signed populated list, ownership/replay/tamper/refusals, bounded retries, TTL, strict typed metadata, query limits and state isolation. Tests never send traffic outside loopback; public candidate tests exercise pure packet validation without sockets.

## New isolated state

Create a separate protected directory outside every Git checkout. On Windows, restrict its ACL to the current service account, SYSTEM and Administrators; Unix mode0600 does not implement Windows ACL protection. Use the upstream `opence-master keygen --out <state>/dce-master.key` command once to generate a new identity; preserve that key thereafter. Do not use the native master's key or database.

Local approval file `<state>/approved.json` holds public keys only:

```json
[{"public_key":"ed25519:<approved host's 64 hex public key>"}]
```

For a specifically reviewed gateway or LAN route, that operator-owned record may additionally contain `"candidate_ip":"<literal IPv4>"`. This is not publisher-controlled and does not prove reachability; signed UDP proof is still required. Production refuses private/reserved addresses. Keys are loaded at startup; changes require a reviewed restart. No remote approval or admin endpoint is provided.

```sh
dce-directory --key <state>/dce-master.key --db <state>/dce-nonces.db \
  --approvals <state>/approved.json --listen 127.0.0.1:18095 --udp-listen 0.0.0.0:0
```

The command requires existing key and approval files. The new database gets an adjacent `.dce-identity` marker binding it to this master. Existing unmarked databases and changed keys are refused before opening the database. Listings/proofs are intentionally ephemeral and clear on restart; request nonces persist. Never erase identity files to bypass a mismatch.

Use `--allow-loopback` only for isolated socket tests. For a reviewed LAN test, `--allow-private-lan-cidr <specific RFC1918 subnet>` permits only that subnet. Trusted reverse proxies must be explicitly listed with `--trusted-proxies <exact proxy IP>` and must set the actual client address and HTTPS scheme. Never trust arbitrary forwarded headers or expose admin routes through a proxy. This command provides only `/healthz` and `/v1/dce/servers` with signed item PUT/DELETE; native `/v1/servers` remains absent here.

The registry sends outbound UDP challenges and receives their replies on one socket; it needs no fixed inbound registry UDP forwarding. Hosts still need reachable game UDP ports or an approved LAN/gateway route. An HTTPS tunnel, browser login or signed listing does not provide that game path. If the HTTP egress IP differs from the game endpoint, proof fails closed unless a local operator has set the approved candidate override.

## Deployment gates

No public deployment, production restart, key upload or game compatibility is established by these files. Before deployment, review the extension, publish corresponding source to an authorized fork, configure separate HTTPS origin and pinned public key, approve only intended host public keys, and test both host and guest routes. Do not push this fork to the upstream origin. Keep native and DCE pools explicit, preserve game/browser authentication, direct connect and exact build/map checks. Paired physical Dreamcast/Flycast/browser gameplay remains separate acceptance evidence.

Game RAM/VRAM/audio delta from this server-only command:0 bytes. Server bounds:64 tracked sessions,4 per approved key,2048-byte publish body,121-byte UDP packets,3 probes per ticket,30-second tickets,90-second listing proof and bounded limiter maps. Runtime working set remains a deployment measurement rather than a console cost claim.

### Measured local baseline (2026-11-04)

Windows command binary SHA256
`0bdea58964159b91094fc6d6c039ddae21afe29a38ca2f77fdd927f62bb89dd8`:
empty-catalog idle working set 12,742,656 bytes; idle private committed memory
49,897,472 bytes. After 100 sequential loopback GET requests, peak working set
13,971,456 bytes and private committed memory 50,671,616 bytes. Process CPU time
was 0.0625 seconds. Sixty requests returned 200 and forty returned 429, exercising
the per-client read limiter. The isolated process was stopped afterward.

This is a baseline, not a maximum-memory budget: it excludes TLS/proxy memory,
maximum record population, concurrent clients and distributed request load.
Connection/process limits and capacity testing remain deployment gates.
