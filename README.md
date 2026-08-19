# Docker config provider for Google Cloud KMS

This plugin lets Docker Swarm ship configuration as ciphertext and have it
unwrapped with a [Cloud KMS](https://cloud.google.com/kms) key at the moment a
task is scheduled.

[![CI](https://github.com/guru-docker/docker-config-gcloud/actions/workflows/ci.yml/badge.svg)](https://github.com/guru-docker/docker-config-gcloud/actions/workflows/ci.yml)

The encrypted blob is the thing you keep: in git, in the swarm's labels, or in a
file on the managers. Nothing readable is stored anywhere, and the key never
leaves Google — the plugin sends the ciphertext to KMS and gets the plaintext
back over the wire.

## Why a secret provider

Docker has no config-driver interface: `ConfigSpec` accepts a templating driver
only, while `SecretSpec` accepts a real external driver. So this plugin
implements `docker.secretprovider/1.0` and configs are created with
`docker secret create --driver`. The value arrives under `/run/secrets` exactly
as a swarm secret does — what makes it a *config* is that the source of truth is
an encrypted blob you own, not a value held by a secret store.

Secret drivers are a swarm feature, so the plugin must be installed on every
manager. `docker run` on a standalone engine does not use it.

If what you want is a hosted secret store rather than your own ciphertext, use
[docker-secret-gcloud](https://github.com/guru-docker/docker-secret-gcloud),
which reads Google Cloud Secret Manager.

## Usage

1 - Encrypt the config

```
$ gcloud kms encrypt \
    --location global --keyring configs --key app \
    --plaintext-file app.yaml \
    --ciphertext-file app.enc
```

2 - Install the plugin on each swarm manager

```
$ docker plugin install glabservices/gcloud-config \
    GOOGLE_CLOUD_PROJECT=<project> \
    GCLOUD_LOCATION=global \
    GCLOUD_KEYRING=configs

# or to enable debug
$ docker plugin install glabservices/gcloud-config DEBUG=1

# or to point at a host directory holding credentials and ciphertext files
$ docker plugin install glabservices/gcloud-config \
    gcloud.source=<any_folder>
```

3 - Create a config

> The plugin's service account needs `roles/cloudkms.cryptoKeyDecrypter` on the
> key. Decrypt is the only permission it uses.

```
$ docker secret create \
    --driver glabservices/gcloud-config \
    -l gcloud.crypto_key=app \
    -l gcloud.ciphertext="$(base64 -w0 app.enc)" \
    app-config
qkw4l4kjqjqkl4jkl4jqkl4jq
```

4 - Use the config

```
$ docker service create --name app --secret app-config myimage
```

The plaintext lands at `/run/secrets/app-config` in the task.

## Options

Labels on the swarm object say which key unwraps it and where the wrapped bytes
are. A key is named either whole, with `gcloud.key`, or in parts that fall back
to what the plugin was installed with.

| Label                 | Required | Description                                                          |
| --------------------- | -------- | -------------------------------------------------------------------- |
| `gcloud.key`          | no       | Full CryptoKey resource name; overrides the four labels below.       |
| `gcloud.project`      | no       | Project holding the key. Defaults to `GOOGLE_CLOUD_PROJECT`.         |
| `gcloud.location`     | no       | Key ring location. Defaults to `GCLOUD_LOCATION`.                    |
| `gcloud.keyring`      | no       | Key ring name. Defaults to `GCLOUD_KEYRING`.                         |
| `gcloud.crypto_key`   | no       | Key name. No default — it is the one part that varies per config.    |
| `gcloud.ciphertext`   | *        | The wrapped bytes, base64 encoded.                                   |
| `gcloud.file`         | *        | A file under `/run/gcloud` holding the wrapped bytes instead.        |
| `gcloud.encoding`     | no       | `raw` (default) or `base64`, for how that file is written.           |
| `gcloud.aad`          | no       | Additional authenticated data the ciphertext was wrapped with.       |
| `gcloud.do_not_reuse` | no       | `true` makes the swarm unwrap again for every task.                  |

\* exactly one of `gcloud.ciphertext` and `gcloud.file` is required.

The key is addressed as a CryptoKey, not a version: symmetric decryption lets
KMS pick the version the ciphertext was wrapped with, so rotating the key does
not invalidate configs encrypted with an earlier version.

```
# ciphertext inline, key assembled from the plugin's defaults
$ docker secret create -d glabservices/gcloud-config \
    -l gcloud.crypto_key=app \
    -l gcloud.ciphertext="$(base64 -w0 app.enc)" \
    app-config

# ciphertext in a file on the managers, key named in full
$ docker secret create -d glabservices/gcloud-config \
    -l gcloud.key=projects/acme-prod/locations/global/keyRings/configs/cryptoKeys/app \
    -l gcloud.file=app.enc \
    app-config
```

`gcloud.file` is resolved inside the mounted directory and cannot reach outside
it, so a config cannot be used to read the credentials sitting next to it.

If the ciphertext was wrapped with additional authenticated data, the same value
has to be given back, or KMS refuses to unwrap it:

```
$ gcloud kms encrypt ... --additional-authenticated-data-file <(printf production)
$ docker secret create -d glabservices/gcloud-config \
    -l gcloud.crypto_key=app \
    -l gcloud.aad=production \
    -l gcloud.file=app.enc \
    app-config
```

Docker caches a driver's answer and reuses it for further tasks of the same
object. `-l gcloud.do_not_reuse=true` turns that off, so every task unwraps the
ciphertext for itself.

## Settings

Plugin variables are set at install time, or with `docker plugin set` while the
plugin is disabled.

| Variable                         | Default | Description                                             |
| -------------------------------- | ------- | ------------------------------------------------------- |
| `GOOGLE_CLOUD_PROJECT`           |         | Project used when a config carries no `gcloud.project`. |
| `GCLOUD_LOCATION`                |         | Location used when it carries no `gcloud.location`.     |
| `GCLOUD_KEYRING`                 |         | Key ring used when it carries no `gcloud.keyring`.      |
| `GOOGLE_APPLICATION_CREDENTIALS` |         | Path *inside the plugin* to a credentials file.         |
| `GCLOUD_TIMEOUT`                 | `30s`   | Deadline for a single Cloud KMS call.                   |
| `GCLOUD_REQUIRE_CREDENTIALS_FILE`| `0`     | `1` refuses to start without a credentials file.        |
| `DEBUG`                          | `0`     | `1` turns on debug logging.                             |

## Authentication

The plugin uses Application Default Credentials, and resolves them in this
order:

1. `GOOGLE_APPLICATION_CREDENTIALS`, if set, as a path inside the plugin's
   filesystem — the `gcloud` mount below is how a host file gets there.
2. `/run/gcloud/credentials.json`, if it exists. This is the zero-configuration
   path: drop a key in the mounted directory and nothing else needs setting.
3. The GCE/GKE metadata server, on a Google Cloud host. Nothing to mount at all;
   grant the node's service account `cryptoKeyDecrypter` and you are done.

The credentials file may be either a service account key or a workload identity
federation (`external_account`) config, which is the keyless option for managers
running outside Google Cloud.

If the credentials live on a remote filesystem, set
`GCLOUD_REQUIRE_CREDENTIALS_FILE=1`. Docker binds the host directory at the
moment the plugin is enabled, so a filesystem mounted *after* that point never
becomes visible to the plugin — it keeps reading the empty directory underneath
while the file is plainly there on the host. With the requirement set, the
plugin refuses to start rather than falling through to the metadata server, and
`docker plugin enable` fails with the reason in the daemon log. Order dockerd
after the mount to avoid the situation in the first place.

The plugin bind-mounts a host directory at `/run/gcloud`, read only. It holds
both the credentials file and any ciphertext files, and defaults to Docker's own
plugin directory, which has neither — so out of the box step 2 finds nothing and
the plugin falls through to the metadata server. Point it at your own directory:

```
$ docker plugin install glabservices/gcloud-config \
    gcloud.source=/etc/gcloud

# on an already installed plugin
$ docker plugin disable glabservices/gcloud-config
$ docker plugin set glabservices/gcloud-config gcloud.source=/etc/gcloud
$ docker plugin enable glabservices/gcloud-config
```

## Integrity

The ciphertext is sent with a CRC32C checksum so KMS can reject bytes damaged on
the way out, and the plaintext that comes back is checked against the checksum
KMS computed for it. A config that did not survive the round trip fails the
request rather than reaching a container.

## Development

```
# unit tests and static checks
$ ./scripts/unit.sh

# build the managed plugin locally
$ make

# end-to-end tests (needs docker, swarm, plugin install rights and curl)
$ sudo ./scripts/integration.sh
```

The integration suite runs its uncredentialed cases anywhere; set
`GOOGLE_CLOUD_PROJECT`, `GCLOUD_LOCATION`, `GCLOUD_KEYRING` and `GCLOUD_KEY` to
also wrap a probe value with a real key and read it back.

`make` targets the local Docker engine by default. Override it with
`make DOCKER="docker --context=<name>"` to build against another engine, and
`PLUGIN_NAME` / `PLUGIN_TAG` to change what is built.

## LICENSE

MIT
