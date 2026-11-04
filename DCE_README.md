# DCE directory service inside Halo DCE

This is the standalone discovery service used by the DCE multiplayer client.
Build and operate it separately from the game. No Go code is linked into the
Dreamcast executable.

Start with [setup and qualification](docs/DCE_DIRECTORY_RUNBOOK.md) and the
[signed wire protocol](docs/DCE_DIRECTORY_PROTOCOL.md). Native OpenCE commands
remain as upstream source, not as the DCE deployment entry point.

```sh
CGO_ENABLED=0 go build -o dce-directory ./cmd/dce-directory
go test ./internal/dcedirectory ./cmd/dce-directory
```

## Source and license

Upstream: https://github.com/OpenCommunityEdition/opence-master-server

Upstream base: `a38bbbf7add066bce3ec429cc97717db75e0194c`.
DCE extension checkpoint: `5c66972d833c4e9024476a253e19b65e2f73dc45`.
The Git content of all 129 imported files matches that checkpoint; checkout line
endings may differ. Repository-level GitHub workflows are omitted.
Original README, AGENTS, module path, copyright
notices and LICENSE are preserved.

This service retains its own AGPL-3.0-or-later [license](LICENSE). When deploying
a modified service, provide corresponding source to its users. The containing
game repository does not replace this service's license. Keep private keys,
approvals, databases, binaries and private game assets outside this directory.

## Qualification

Signed registration, same-game-socket UDP proof, listing, refresh and deletion
passed isolated loopback tests. These do not establish deployed reachability,
game-client admission, paired gameplay or native OpenCE crossplay. The runbook
records baseline memory measurements and outstanding deployment gates.
