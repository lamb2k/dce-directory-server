# Optional private device enrollment

This operator control plane approves a browser-generated **public** device key after authenticated gateway access and Ed25519 proof of possession. It never accepts a private key, seed, RNG state, candidate address, browser-selected URL or account credential. Browser VMU generation/encryption and gateway login are separate components. Public directory routes and publisher signatures remain unchanged. Game RAM/VRAM/audio delta:0 bytes.

Disabled by default. Enable only on a separate literal loopback listener:

```
--enrollment-listen 127.0.0.1:18097
--enrollment-token-file <protected-state>/enrollment.token
```

The token file contains32..64 cryptographically random bytes encoded as64..128 lowercase hex characters, optionally followed by a newline. Provision it outside Git with private filesystem permissions/Windows ACL. Pass only its path on the command line, never its contents. Gateway sends `Authorization: Bearer <literal hex token>`. Listener rejects wildcard binds, DNS names and non-loopback addresses; handler also rejects non-loopback peers and ignores forwarded-origin claims. Do not proxy this listener or these paths through the public directory origin. No CORS access is enabled.

The operator may configure `--enrollment-candidate-ip <literal IPv4>` for newly approved gateway devices. It must pass the existing production/LAN address policy. Browser request bodies cannot change it. Existing approval overrides are preserved. Enrollment does not establish UDP/game reachability: every advertised session still needs the separate signed challenge/ACK proof.

## Authenticated relay contract

The gateway authenticates its browser user before forwarding either request and supplies `X-DCE-Enrollment-Session: <64 lowercase hex HMAC session binding>`. This is opaque public proof context, not the browser cookie or a new credential. Never persist challenge metadata as a login or VMU credential.

`POST /v1/dce/enrollment/challenge`:

```json
{"publicKey":"ed25519:<64 lowercase hex>"}
```

Signed200 response:

```json
{"protocol":1,"masterKeyId":"<16hex>","keyId":"<16hex>","publicKey":"ed25519:<64hex>","challenge":"<32hex>","expires":1793800060,"serverTime":1793800000,"sessionBinding":"<64hex>"}
```

Device reconstructs these exact six UTF-8 lines, LF separators, **no trailing LF**, then signs with its persistent device key:

```
DCE-Device-Enrollment-v1
<masterKeyId>
<publicKey>
<challenge>
<decimal expires>
<sessionBinding>
```

Validate the known domain, expected device public key, configured master identity and field formats before signing; never sign an arbitrary message supplied by a remote endpoint. The browser must save its encrypted VMU record before enrollment. No private key leaves it.

`POST /v1/dce/enrollment/register`:

```json
{"publicKey":"ed25519:<64hex>","challenge":"<32hex>","signature":"<standard base64 of64 signature bytes>"}
```

Signed200 response:

```json
{"ok":true,"masterKeyId":"<16hex>","keyId":"<16hex>","publicKey":"ed25519:<64hex>","approved":true,"created":true,"serverTime":1793800001}
```

A relay that serves public sign-up sends `X-DCE-Enrollment-Class: public`. Those keys are stored with `"public": true` and share `MaxPublicRecords` (16) listed records and `MaxPublicApprovals` (256) approvals; at the cap, registration answers 429 `public_capacity`. Without the header a key is an operator key, which keeps the remaining 48 records and 768 approvals. Approval files from before this change read as operator keys. An older server binary refuses a file holding `public` rows, so roll back with the file as it was.

Both responses use existing `Signature`, `Signature-Key`, `Signature-Time` headers over exact serialized bytes. `serverTime` equals `Signature-Time`, including retries. Gateway verifies the configured master public key/id and clock before trusting fields or forwarding authoritative UTC. It must not forward arbitrary time/URL values. Successful enrollment supplies no private credential.

Challenge lifetime60 seconds, bound to one session and public key. A fresh challenge replaces that session's previous challenge. Exact successful registration retry (same session/key/challenge/signature) within its original TTL returns the same approval result with fresh signed serverTime, without another file update. A new cookie/session needs a new challenge/proof; the same saved device key returns `created:false`, preserving identity without reinstallation. Invalid/expired proof cannot enroll a key just because another session previously enrolled it.

## Persistence and bounds

Existing approved public-key JSON format is retained, max1024 total records including operator approvals. Enrollment uses a process mutex and exclusive adjacent lock file. It rereads current approvals, rejects key-id collisions, appends only the new public metadata, writes a private same-directory temp file, fsyncs it, atomically replaces the approval file, and reads back exact bytes before in-memory activation. Unix also fsyncs the directory; Windows uses MoveFileEx replace/write-through. Key and candidate map updates are synchronized with concurrent game requests. A failed write/readback leaves the key inactive. A crash-stale lock fails closed for operator recovery; never delete a lock belonging to an active writer. The protected parent directory must provide correct Windows ACL inheritance.

Request512 bytes; exact canonical JSON fields only, no aliases/duplicates/extras. Max64 pending/completed session records, one per session; expired records removed. Backend limits5 challenges/min and10 registrations/min per session,120/240 globally. Three bad signatures consume the challenge. No token, raw cookie, private device material or proof request is logged.

Interoperability vectors: `testdata/dce_enrollment_vectors.json` contains explicitly synthetic public test seed/material. Never deploy fixture seeds or the unit-test operator token. Source credit and AGPL licence remain unchanged. Source-only implementation does not authorize enabling the listener, provisioning secrets, restarting services or accepting paired game play.
