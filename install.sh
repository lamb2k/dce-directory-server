#!/bin/sh
# Installs an OpenCE master server with Docker, behind Caddy (which gets its
# HTTPS certificate):
#
#   curl -fsSL https://github.com/OpenCommunityEdition/opence-master-server/releases/latest/download/install.sh | sh
#
# It asks whether the bundled Caddy gets the HTTPS certificate or a reverse
# proxy of your own (nginx, Caddy, ...) on this machine forwards to the
# master, and for the master's domain. It installs Docker if it is missing
# (with your consent), writes compose.yaml, the settings and the proxy's
# files to /opt/opence-master, starts the master, and prints the setup link
# that names it. Run it again to repair, move or switch an install: the data
# (the master-data volume) and the settings are kept.
#
# Options (or the environment variables beside them):
#   --domain <name>    OPENCE_DOMAIN        the master's domain
#   --proxy <which>    OPENCE_PROXY         bundled (Caddy in Docker, on ports
#                                           80 and 443) or external (your own
#                                           proxy, forwarding to 127.0.0.1)
#   --port <n>         OPENCE_PORT          the master's port on 127.0.0.1,
#                                           for an external proxy (8090)
#   --dir <path>       OPENCE_DIR           where it goes (/opt/opence-master)
#   --yes              OPENCE_YES=1         no questions: the bundled proxy
#                                           unless --proxy says otherwise
#   --install-docker   OPENCE_INSTALL_DOCKER=1  run Docker's own script if Docker
#                                           is missing, unasked. --yes alone
#                                           never runs a downloaded script as root
set -eu

REPO="OpenCommunityEdition/opence-master-server"
# The release key, public half (internal/update/key.go): signs SHA256SUMS. A fork's releases set OPENCE_RELEASE_KEY.
RELEASE_KEY="${OPENCE_RELEASE_KEY:-a61b8ee032e662ff0ba1fc60f60b689343c8893bfa4db6e82f5b791030c6c486}"
INSTALL_DOCKER="${OPENCE_INSTALL_DOCKER:-}"
BASE="${OPENCE_RELEASE_URL:-https://github.com/$REPO/releases/latest/download}"
DIR="${OPENCE_DIR:-/opt/opence-master}"
DOMAIN="${OPENCE_DOMAIN:-}"
PROXY="${OPENCE_PROXY:-}"
PORT="${OPENCE_PORT:-}"
YES="${OPENCE_YES:-}"

say() { printf '%s\n' "$*"; }
step() { printf '\n==> %s\n' "$*"; }
fail() {
	printf '\nopence-master install: %s\n' "$*" >&2
	exit 1
}

while [ $# -gt 0 ]; do
	case "$1" in
	--domain) [ $# -ge 2 ] || fail "--domain needs a name"; DOMAIN="$2"; shift 2 ;;
	--domain=*) DOMAIN="${1#--domain=}"; shift ;;
	--proxy) [ $# -ge 2 ] || fail "--proxy needs bundled or external"; PROXY="$2"; shift 2 ;;
	--proxy=*) PROXY="${1#--proxy=}"; shift ;;
	--port) [ $# -ge 2 ] || fail "--port needs a number"; PORT="$2"; shift 2 ;;
	--port=*) PORT="${1#--port=}"; shift ;;
	--dir) [ $# -ge 2 ] || fail "--dir needs a path"; DIR="$2"; shift 2 ;;
	--dir=*) DIR="${1#--dir=}"; shift ;;
	-y | --yes) YES=1; shift ;;
	--install-docker) INSTALL_DOCKER=1; shift ;;
	-h | --help) sed -n '2,29p' "$0" 2>/dev/null | sed 's/^# \{0,1\}//'; exit 0 ;;
	*) fail "unknown option $1 (--help lists them)" ;;
	esac
done

# ask reads an answer from the terminal (the script itself may be standard
# input, through a pipe); with no terminal, the answer is empty.
ask() {
	printf '%s ' "$1"
	answer=""
	if [ -z "$YES" ] && [ -r /dev/tty ]; then
		read -r answer </dev/tty || answer=""
	fi
}

# ---------- the release's signature

# hex_bytes HEX: the bytes. POSIX printf; no xxd on a small server.
hex_bytes() {
	hex_rest="$1"
	while [ -n "$hex_rest" ]; do
		hex_pair="${hex_rest%"${hex_rest#??}"}"
		hex_rest="${hex_rest#??}"
		# shellcheck disable=SC2059
		printf "\\$(printf '%03o' "0x$hex_pair")"
	done
}

# verify_sums DIR KEY: DIR/SHA256SUMS.sig is KEY's Ed25519 signature of DIR/SHA256SUMS. Returns non-zero otherwise.
verify_sums() {
	sig_hex="$(tr -d ' \r\n' <"$1/SHA256SUMS.sig")"
	printf '%s' "$sig_hex" | grep -Eq '^[0-9a-fA-F]{128}$' || return 1
	printf '%s' "$2" | grep -Eq '^[0-9a-fA-F]{64}$' || return 1
	hex_bytes "$sig_hex" >"$1/sums.sig.bin"
	# (the fixed DER header of an Ed25519 public key, then the key)
	{
		printf '%s\n' '-----BEGIN PUBLIC KEY-----'
		{ hex_bytes 302a300506032b6570032100; hex_bytes "$2"; } | openssl base64 -A
		printf '\n%s\n' '-----END PUBLIC KEY-----'
	} >"$1/release-key.pem"
	openssl pkeyutl -verify -pubin -inkey "$1/release-key.pem" -rawin -in "$1/SHA256SUMS" -sigfile "$1/sums.sig.bin" >/dev/null 2>&1
}
# ---------- end of the signature functions

# ---------- what it needs

[ "$(uname -s)" = Linux ] || fail "this installer is for Linux (README.md tells of the other ways)"
parent="$DIR"
while [ ! -d "$parent" ]; do parent="$(dirname "$parent")"; done
if [ "$(id -u)" -eq 0 ]; then
	SUDO=""
elif [ -w "$parent" ] && command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
	# (Docker and the directory are this user's: no root needed)
	SUDO=""
elif command -v sudo >/dev/null 2>&1; then
	SUDO="sudo"
	say "Some steps need root: sudo may ask for your password."
else
	fail "run it as root (or install sudo)"
fi

if command -v curl >/dev/null 2>&1; then
	fetch() { curl -fsSL --retry 3 "$1" -o "$2"; }
elif command -v wget >/dev/null 2>&1; then
	fetch() { wget -q -O "$2" "$1"; }
else
	fail "curl or wget is needed"
fi

step "Docker"
if ! command -v docker >/dev/null 2>&1; then
	if [ -n "$INSTALL_DOCKER" ]; then
		answer=y
	elif [ -n "$YES" ]; then
		fail "Docker is not installed, and --yes does not run a downloaded script as root: install Docker first (https://docs.docker.com/engine/install/), or add --install-docker"
	else
		ask "Docker is not installed. Install it with Docker's own script (https://get.docker.com)? [Y/n]"
	fi
	case "$answer" in
	"" | y | Y | yes) ;;
	*) fail "Docker is needed: https://docs.docker.com/engine/install/" ;;
	esac
	if [ -n "$INSTALL_DOCKER" ] || [ -r /dev/tty ]; then :; else fail "no terminal to ask on: run it with --install-docker"; fi
	tmp_docker="$(mktemp)"
	fetch https://get.docker.com "$tmp_docker"
	$SUDO sh "$tmp_docker"
	rm -f "$tmp_docker"
fi
$SUDO docker info >/dev/null 2>&1 || fail "Docker is installed but not running: start it (systemctl start docker)"
$SUDO docker compose version >/dev/null 2>&1 ||
	fail "Docker Compose is needed (the docker-compose-plugin package): https://docs.docker.com/compose/install/"
say "$($SUDO docker --version), $($SUDO docker compose version --short 2>/dev/null || echo compose)"

# ---------- the proxy and the domain

# (an earlier install's choices are the defaults)
previous() {
	if [ -f "$DIR/.env" ]; then sed -n "s/^$1=//p" "$DIR/.env" | head -n 1; fi
}
if [ -z "$PROXY" ] && [ -n "$(previous OPENCE_PROXY)" ]; then
	PROXY="$(previous OPENCE_PROXY)"
	say "Keeping the $PROXY reverse proxy (--proxy changes it)."
fi
if [ -z "$PORT" ]; then
	PORT="$(previous MASTER_PORT)"
fi
if [ -z "$DOMAIN" ] && [ -n "$(previous MASTER_DOMAIN)" ]; then
	DOMAIN="$(previous MASTER_DOMAIN)"
	say "Keeping the domain $DOMAIN (--domain changes it)."
fi

step "HTTPS"
if [ -z "$PROXY" ]; then
	if [ -n "$YES" ] || [ ! -r /dev/tty ]; then
		PROXY=bundled
	else
		say "The master needs HTTPS in front of it. Either:"
		say "  1) Caddy, in Docker beside the master, gets the certificate itself (ports 80 and 443)"
		say "  2) a reverse proxy of your own on this machine (nginx, Caddy, ...) forwards to the master"
		ask "Which? [1]"
		case "$answer" in
		"" | 1 | bundled) PROXY=bundled ;;
		2 | external) PROXY=external ;;
		*) fail "\"$answer\" is neither 1 nor 2" ;;
		esac
	fi
fi
case "$PROXY" in
bundled) say "Caddy in Docker gets the certificate." ;;
external)
	if [ -z "$PORT" ] && [ -z "$YES" ] && [ -r /dev/tty ]; then
		ask "The master's port on 127.0.0.1, which your proxy forwards to: [8090]"
		PORT="$answer"
	fi
	PORT="${PORT:-8090}"
	case "$PORT" in
	*[!0-9]*) fail "the port \"$PORT\" is not a number" ;;
	esac
	{ [ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ]; } || fail "the port $PORT is not 1 to 65535"
	say "Your proxy forwards to http://127.0.0.1:$PORT."
	;;
*) fail "--proxy is bundled or external, not \"$PROXY\"" ;;
esac
while [ -z "$DOMAIN" ]; do
	[ -r /dev/tty ] || fail "no terminal to ask on: give the domain with --domain master1.example.org"
	if [ "$PROXY" = external ]; then
		ask "The master's domain, which your proxy serves (such as master1.example.org):"
	else
		ask "The master's domain (its DNS record points at this machine), such as master1.example.org:"
	fi
	DOMAIN="$answer"
done
DOMAIN="$(printf '%s' "$DOMAIN" | tr 'A-Z' 'a-z' | sed 's#^https\{0,1\}://##; s#/.*##')"
case "$DOMAIN" in
*[!a-z0-9.-]* | .* | *. | *..* | "") fail "\"$DOMAIN\" is not a domain name" ;;
*.*) ;;
*) fail "\"$DOMAIN\" is not a full domain name (master1.example.org)" ;;
esac

if [ "$PROXY" = bundled ] && command -v getent >/dev/null 2>&1; then
	if ! getent ahosts "$DOMAIN" >/dev/null 2>&1; then
		say "Warning: $DOMAIN has no DNS record yet. Caddy gets the certificate once it points here."
	fi
fi
# (a port taken by something other than this install)
running=""
if [ -f "$DIR/compose.yaml" ]; then
	running="$(cd "$DIR" && $SUDO docker compose ps --format '{{.Service}} {{.Ports}}' 2>/dev/null || true)"
fi
if command -v ss >/dev/null 2>&1; then
	if [ "$PROXY" = bundled ] && ss -ltn 2>/dev/null | grep -Eq '[:.](80|443)[[:space:]]' &&
		! printf '%s\n' "$running" | grep -q '^caddy'; then
		say "Warning: something already listens on port 80 or 443, which Caddy needs. If it is your own"
		say "web server, run the installer again and choose 2 (--proxy external)."
	fi
	if [ "$PROXY" = external ] && ss -ltn 2>/dev/null | grep -Eq "[:.]$PORT[[:space:]]" &&
		! printf '%s\n' "$running" | grep -q ":$PORT->"; then
		fail "port $PORT on this machine is taken: choose another with --port"
	fi
fi

# ---------- the files

step "Files in $DIR"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
for f in compose.yaml compose.proxy.yaml Caddyfile SHA256SUMS SHA256SUMS.sig; do
	fetch "$BASE/$f" "$tmp/$f" || fail "$BASE/$f could not be downloaded"
done
command -v sha256sum >/dev/null 2>&1 || fail "sha256sum is needed to check the release's files (the coreutils package)"
command -v openssl >/dev/null 2>&1 || fail "openssl 3 is needed to check the release's signature (the openssl package)"
verify_sums "$tmp" "$RELEASE_KEY" || fail "SHA256SUMS is not signed by the release key: nothing installed"
[ "$(grep -cE '  (compose\.yaml|compose\.proxy\.yaml|Caddyfile)$' "$tmp/SHA256SUMS")" = 3 ] ||
	fail "SHA256SUMS does not name the release's three files: nothing installed"
(cd "$tmp" && grep -E '  (compose\.yaml|compose\.proxy\.yaml|Caddyfile)$' SHA256SUMS | sha256sum -c --status) ||
	fail "the downloaded files are not the release's (SHA256SUMS)"
$SUDO mkdir -p "$DIR/deploy"
$SUDO install -m 644 "$tmp/compose.yaml" "$DIR/compose.yaml"
$SUDO install -m 644 "$tmp/compose.proxy.yaml" "$DIR/compose.proxy.yaml"
$SUDO install -m 644 "$tmp/Caddyfile" "$DIR/deploy/Caddyfile"
{
	say "# install.sh's choices (docker compose reads this file)"
	say "MASTER_DOMAIN=$DOMAIN"
	say "OPENCE_PROXY=$PROXY"
	if [ "$PROXY" = external ]; then
		say "MASTER_PORT=$PORT"
		# (the master's port on loopback, and no Caddy)
		say "COMPOSE_FILE=compose.yaml:compose.proxy.yaml"
	fi
} >"$tmp/.env"
$SUDO install -m 644 "$tmp/.env" "$DIR/.env"
if $SUDO test -f "$DIR/master.env"; then
	# (kept, with the domain's URL)
	$SUDO sed -i "s#^MASTER_PUBLIC_URL=.*#MASTER_PUBLIC_URL=https://$DOMAIN#" "$DIR/master.env"
	say "Kept the settings in $DIR/master.env."
else
	cat >"$tmp/master.env" <<EOF
# The master's settings (every option: README.md, "Options"). The name, the
# contact and the admin token are made by the setup link; the Discord bot is
# set up on the admin pages.
MASTER_PUBLIC_URL=https://$DOMAIN
# updates: notify (the admins update with a button), auto, or off
#MASTER_UPDATES=notify
EOF
	$SUDO install -m 600 "$tmp/master.env" "$DIR/master.env"
fi
if [ "$PROXY" = external ]; then
	cat >"$tmp/reverse-proxy.txt" <<PROXYEOF
Your reverse proxy serves https://$DOMAIN and forwards to http://127.0.0.1:$PORT,
with the X-Forwarded-Proto, X-Forwarded-For and X-Forwarded-Host headers (the master
refuses its admin pages and the servers' publishes without them).

Caddy (a Caddyfile; it gets the certificate itself and sends the headers):

$DOMAIN {
	reverse_proxy 127.0.0.1:$PORT
}

nginx (a server block; the certificate is yours to get, with certbot say):

server {
	listen 443 ssl;
	listen [::]:443 ssl;
	server_name $DOMAIN;
	ssl_certificate     /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
	ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;
	client_max_body_size 1m;

	location / {
		proxy_pass http://127.0.0.1:$PORT;
		proxy_set_header Host \$host;
		proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
		proxy_set_header X-Forwarded-Proto \$scheme;
		proxy_set_header X-Forwarded-Host \$host;
	}
}
PROXYEOF
	$SUDO install -m 644 "$tmp/reverse-proxy.txt" "$DIR/reverse-proxy.txt"
fi
say "Wrote compose.yaml, compose.proxy.yaml, deploy/Caddyfile, .env and master.env."

# ---------- start

step "Starting the master and Caddy"
cd "$DIR"
if ! $SUDO docker compose pull --quiet; then
	$SUDO docker image inspect "$(sed -n 's/^ *image: \(ghcr[^ ]*\)$/\1/p' "$DIR/compose.yaml")" >/dev/null 2>&1 ||
		fail "the image could not be downloaded (ghcr.io/opencommunityedition/opence-master-server)"
	say "Warning: the images were not updated; using the ones already here."
fi
# (recreated: a repair runs the settings just written, and the log below is
# this start's)
if [ "$PROXY" = external ]; then
	# (the bundled Caddy of an earlier install goes)
	$SUDO docker compose --profile bundled-caddy rm -sf caddy >/dev/null 2>&1 || true
fi
$SUDO docker compose up -d --remove-orphans --force-recreate

step "Waiting for the master"
link=""
ready=""
i=0
while [ $i -lt 60 ]; do
	since="$($SUDO docker inspect -f '{{.State.StartedAt}}' "$($SUDO docker compose ps -q master)" 2>/dev/null || true)"
	logs="$($SUDO docker compose logs --no-color ${since:+--since "$since"} master 2>/dev/null || true)"
	if printf '%s' "$logs" | grep -q "listening on"; then
		ready=1
		link="$(printf '%s\n' "$logs" | grep -o 'https\{0,1\}://[^ "]*/admin/setup?code=[0-9a-f]*' | tail -n 1)"
		[ -n "$link" ] && break
		# (set up already: no link; a moment for the line to come)
		[ $i -ge 3 ] && break
	fi
	i=$((i + 1))
	sleep 2
done
[ -n "$ready" ] || fail "the master did not start: ${SUDO:+$SUDO }docker compose --project-directory $DIR logs master"

key="$(printf '%s\n' "$logs" | grep -o 'public_key=ed25519:[0-9a-f]*' | tail -n 1 | sed 's/^public_key=//')"

say ""
if [ "$PROXY" = external ]; then
	say "The OpenCE master listens on http://127.0.0.1:$PORT, for your reverse proxy."
	say ""
	say "Set your proxy up to serve https://$DOMAIN and forward to it; with Caddy:"
	say ""
	say "    $DOMAIN {"
	say "        reverse_proxy 127.0.0.1:$PORT"
	say "    }"
	say ""
	say "(nginx's, and the headers the master needs: $DIR/reverse-proxy.txt). Then open the link."
else
	say "The OpenCE master runs at https://$DOMAIN"
fi
if [ -n "$link" ]; then
	say ""
	say "Open this link to name the master and make its admin token (it is good once):"
	say ""
	say "    $link"
	say ""
	if [ "$PROXY" = bundled ]; then
		say "Caddy may take a minute to get the certificate; reload if the page does not open yet."
	fi
else
	say "It is set up already: the admin pages are at https://$DOMAIN/admin/"
fi
[ -n "$key" ] && say "" && say "Its public key, for the game's masters.txt: $key"
run="${SUDO:+$SUDO }"
say ""
say "In $DIR:"
say "  ${run}docker compose logs -f master     the log"
say "  ${run}docker compose pull && ${run}docker compose up -d   update (the admin pages and the"
say "                                            Discord bot's notice do it with a button too)"
say "  ${run}docker compose down               stop (the data stays in the master-data volume)"
say "Back up the master-data volume: it holds the database and the master key, the master's identity."
