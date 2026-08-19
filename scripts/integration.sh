#!/usr/bin/env bash
#
# End-to-end test for the Cloud KMS config provider.
#
# Builds and installs the managed plugin, then drives it two ways: directly over
# its unix socket, where the driver's own answers are visible, and through
# `docker secret create --driver` in a swarm, which is how it is really used.
#
# Cases that need no credentials always run. Set the following to also unwrap a
# real ciphertext:
#
#   GOOGLE_CLOUD_PROJECT   project holding the key ring
#   GCLOUD_LOCATION        key ring location, e.g. global
#   GCLOUD_KEYRING         key ring name
#   GCLOUD_KEY             crypto key name
#   GCLOUD_CREDENTIALS     service account / workload identity JSON, inline
#     or GOOGLE_APPLICATION_CREDENTIALS  path to that JSON on the host
#     or nothing at all, on a GCE/GKE host whose service account may decrypt
#
# The credentialed run encrypts a probe value with `gcloud kms encrypt` and
# checks the plugin gives it back, so the gcloud CLI is needed as well.
#
# Requires: docker with swarm and plugin support, permission to install plugins,
# and curl.
#
#   ./scripts/integration.sh
#
set -euo pipefail

cd "$(dirname "$0")/.."

DOCKER=${DOCKER:-docker}
PLUGIN_NAME=${PLUGIN_NAME:-glabservices/gcloud-config}
PLUGIN_TAG=${PLUGIN_TAG:-test}
PLUGIN="${PLUGIN_NAME}:${PLUGIN_TAG}"
SECRET=${SECRET:-gcloud-itest-config}
SERVICE=${SERVICE:-gcloud-itest}
PROBE=${PROBE:-"listen: 0.0.0.0:8080"}

mount_dir=$(mktemp -d)
swarm_created=0
failures=0
socket=""

log()  { echo; echo "=== $*"; }
fail() { echo "!!! FAIL: $*" >&2; failures=$((failures + 1)); }

cleanup() {
	local rc=$?
	log "cleanup"
	$DOCKER service rm "$SERVICE" >/dev/null 2>&1 || true
	$DOCKER secret rm "$SECRET" >/dev/null 2>&1 || true
	$DOCKER plugin disable -f "$PLUGIN" >/dev/null 2>&1 || true
	$DOCKER plugin rm -f "$PLUGIN" >/dev/null 2>&1 || true
	[ "$swarm_created" -eq 1 ] && $DOCKER swarm leave --force >/dev/null 2>&1 || true
	rm -rf "$mount_dir"
	exit $rc
}
trap cleanup EXIT

# --- driving the plugin directly -------------------------------------------

# ask posts a SecretProvider.GetSecret request and prints the raw JSON reply.
ask() {
	curl -s --max-time 60 --unix-socket "$socket" \
		-H 'Content-Type: application/json' \
		-d "$1" http://localhost/SecretProvider.GetSecret
}

# value_of extracts and decodes the Value of a reply. Go renders []byte as
# base64, so the reply is not readable as it stands.
value_of() {
	local encoded
	encoded=$(printf '%s' "$1" | sed -n 's/.*"Value":"\([^"]*\)".*/\1/p')
	[ -n "$encoded" ] && printf '%s' "$encoded" | base64 -d
}

# refuses asserts that a request is rejected with a message the operator can act
# on, rather than silently returning nothing.
refuses() {
	local name=$1 body=$2 want=$3 reply
	reply=$(ask "$body")

	if ! echo "$reply" | grep -q '"Err"'; then
		fail "$name: expected a rejection, got: $reply"
	elif ! echo "$reply" | grep -qF "$want"; then
		fail "$name: rejection does not mention $want: $reply"
	else
		echo "--- ok: $name"
	fi
}

# --- driving the plugin through swarm --------------------------------------

reset_service() {
	$DOCKER service rm "$SERVICE" >/dev/null 2>&1 || true
	$DOCKER secret rm "$SECRET" >/dev/null 2>&1 || true
}

task_state() {
	$DOCKER service ps "$SERVICE" --no-trunc --format '{{.CurrentState}} {{.Error}}' 2>/dev/null | head -1
}

# wait_for_task blocks until the service's task settles and prints its state. A
# task stuck before "Running" means the driver never answered.
wait_for_task() {
	local state=""
	for _ in $(seq 60); do
		state=$(task_state)
		case "$state" in
			Complete*|Failed*|Rejected*|Shutdown*) echo "$state"; return 0 ;;
		esac
		sleep 1
	done
	echo "${state:-no task}"
	return 1
}

# deliver creates a driver-backed config with the given `docker secret create`
# arguments, mounts it into a one-shot service, and prints what the container
# read from /run/secrets.
deliver() {
	reset_service

	$DOCKER secret create --driver "$PLUGIN" "$@" "$SECRET" >/dev/null
	$DOCKER service create --detach \
		--name "$SERVICE" \
		--restart-condition none \
		--secret "source=$SECRET,target=probe" \
		busybox sh -c 'cat /run/secrets/probe' >/dev/null

	wait_for_task >/dev/null || true
	$DOCKER service logs --raw "$SERVICE" 2>/dev/null || true
}

# --- setup ------------------------------------------------------------------

command -v curl >/dev/null || { echo "curl is required" >&2; exit 1; }

log "pull fixtures"
$DOCKER pull -q busybox

if ! $DOCKER node ls >/dev/null 2>&1; then
	log "init swarm (secret drivers are a swarm feature)"
	$DOCKER swarm init >/dev/null
	swarm_created=1
fi

log "build plugin $PLUGIN"
PLUGIN_NAME="$PLUGIN_NAME" PLUGIN_TAG="$PLUGIN_TAG" DOCKER="$DOCKER" make

if [ -n "${GCLOUD_CREDENTIALS:-}" ]; then
	printf '%s' "$GCLOUD_CREDENTIALS" > "$mount_dir/credentials.json"
elif [ -n "${GOOGLE_APPLICATION_CREDENTIALS:-}" ]; then
	cp "$GOOGLE_APPLICATION_CREDENTIALS" "$mount_dir/credentials.json"
fi

log "configure and enable the plugin"
$DOCKER plugin set "$PLUGIN" DEBUG=1
$DOCKER plugin set "$PLUGIN" gcloud.source="$mount_dir"
for var in GOOGLE_CLOUD_PROJECT GCLOUD_LOCATION GCLOUD_KEYRING; do
	[ -n "${!var:-}" ] && $DOCKER plugin set "$PLUGIN" "$var=${!var}"
done
$DOCKER plugin enable "$PLUGIN"
$DOCKER plugin ls

socket="/run/docker/plugins/$($DOCKER plugin inspect "$PLUGIN" -f '{{.Id}}')/config-gcloud.sock"
if [ ! -S "$socket" ]; then
	echo "the plugin did not open $socket" >&2
	exit 1
fi

key="projects/${GOOGLE_CLOUD_PROJECT:-acme-prod}/locations/${GCLOUD_LOCATION:-global}"
key="$key/keyRings/${GCLOUD_KEYRING:-configs}/cryptoKeys/${GCLOUD_KEY:-app}"

# --- cases that need no credentials ----------------------------------------

log "case: a request with no key is refused"
refuses "no key" \
	"{\"SecretName\":\"app-config\",\"SecretLabels\":{\"gcloud.ciphertext\":\"$(printf wrapped | base64 -w0)\"}}" \
	"gcloud.key"

log "case: a malformed key label is refused"
refuses "bad key" \
	'{"SecretName":"app-config","SecretLabels":{"gcloud.key":"projects/acme/cryptoKeys/app","gcloud.ciphertext":"d3JhcHBlZA=="}}' \
	"not a Cloud KMS key"

log "case: a request with no ciphertext is refused"
refuses "no ciphertext" \
	"{\"SecretName\":\"app-config\",\"SecretLabels\":{\"gcloud.key\":\"$key\"}}" \
	"no ciphertext"

log "case: naming both a ciphertext and a file is refused"
refuses "both sources" \
	"{\"SecretName\":\"app-config\",\"SecretLabels\":{\"gcloud.key\":\"$key\",\"gcloud.ciphertext\":\"d3JhcHBlZA==\",\"gcloud.file\":\"app.enc\"}}" \
	"mutually exclusive"

# The file label is attacker-controlled input in the sense that whoever creates
# a config picks it; it must not reach the credentials sitting next to it.
log "case: a file label cannot escape the mount"
printf 'not ciphertext' > "$mount_dir/credentials.json.probe"
refuses "path escape" \
	"{\"SecretName\":\"app-config\",\"SecretLabels\":{\"gcloud.key\":\"$key\",\"gcloud.file\":\"../../../etc/shadow\"}}" \
	"failed to read the ciphertext"

log "case: a missing ciphertext file is refused"
refuses "missing file" \
	"{\"SecretName\":\"app-config\",\"SecretLabels\":{\"gcloud.key\":\"$key\",\"gcloud.file\":\"absent.enc\"}}" \
	"failed to read the ciphertext"

log "case: a rejected config fails the task instead of hanging"
reset_service
$DOCKER secret create --driver "$PLUGIN" -l gcloud.key=not-a-key "$SECRET" >/dev/null
$DOCKER service create --detach \
	--name "$SERVICE" \
	--restart-condition none \
	--secret "source=$SECRET,target=probe" \
	busybox true >/dev/null
state=$(wait_for_task || true)
case "$state" in
	Complete*) fail "rejected config: the task started with no config to mount" ;;
	Failed*|Rejected*) echo "--- ok: a rejected config fails the task" ;;
	*) fail "rejected config: task never settled ($state)" ;;
esac

# --- cases that need a real key --------------------------------------------

if [ -z "${GOOGLE_CLOUD_PROJECT:-}" ] || [ -z "${GCLOUD_KEY:-}" ]; then
	log "skipping the credentialed cases"
	echo "set GOOGLE_CLOUD_PROJECT, GCLOUD_LOCATION, GCLOUD_KEYRING and GCLOUD_KEY"
	echo "to exercise a real key"
else
	command -v gcloud >/dev/null || { echo "the gcloud CLI is required for these cases" >&2; exit 1; }

	log "wrap a probe value with $key"
	printf '%s' "$PROBE" | gcloud kms encrypt \
		--project "$GOOGLE_CLOUD_PROJECT" \
		--location "${GCLOUD_LOCATION:-global}" \
		--keyring "$GCLOUD_KEYRING" \
		--key "$GCLOUD_KEY" \
		--plaintext-file - \
		--ciphertext-file "$mount_dir/app.enc"
	ciphertext=$(base64 -w0 < "$mount_dir/app.enc")

	log "case: an inline ciphertext is unwrapped"
	reply=$(ask "{\"SecretName\":\"app-config\",\"SecretLabels\":{\"gcloud.key\":\"$key\",\"gcloud.ciphertext\":\"$ciphertext\"}}")
	if [ "$(value_of "$reply")" != "$PROBE" ]; then
		fail "inline: got '$(value_of "$reply")', want '$PROBE': $reply"
	else
		echo "--- ok: an inline ciphertext is unwrapped"
	fi

	log "case: a mounted ciphertext file is unwrapped"
	reply=$(ask "{\"SecretName\":\"app-config\",\"SecretLabels\":{\"gcloud.key\":\"$key\",\"gcloud.file\":\"app.enc\"}}")
	if [ "$(value_of "$reply")" != "$PROBE" ]; then
		fail "file: got '$(value_of "$reply")', want '$PROBE': $reply"
	else
		echo "--- ok: a mounted ciphertext file is unwrapped"
	fi

	log "case: the key name can be assembled from the plugin defaults"
	reply=$(ask "{\"SecretName\":\"app-config\",\"SecretLabels\":{\"gcloud.crypto_key\":\"$GCLOUD_KEY\",\"gcloud.file\":\"app.enc\"}}")
	if [ "$(value_of "$reply")" != "$PROBE" ]; then
		fail "defaults: got '$(value_of "$reply")', want '$PROBE': $reply"
	else
		echo "--- ok: the key name can be assembled from the plugin defaults"
	fi

	log "case: a ciphertext wrapped with other AAD is refused"
	refuses "wrong aad" \
		"{\"SecretName\":\"app-config\",\"SecretLabels\":{\"gcloud.key\":\"$key\",\"gcloud.file\":\"app.enc\",\"gcloud.aad\":\"staging\"}}" \
		"failed to decrypt"

	log "case: the plaintext reaches a container"
	delivered=$(deliver -l "gcloud.key=$key" -l "gcloud.ciphertext=$ciphertext")
	if [ "$delivered" != "$PROBE" ]; then
		fail "swarm delivery: container read '$delivered'; $(task_state)"
	else
		echo "--- ok: the plaintext reaches a container"
	fi
fi

log "result"
if [ "$failures" -ne 0 ]; then
	echo "$failures case(s) failed" >&2
	exit 1
fi
echo "all cases passed"
