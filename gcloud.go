package main

import (
	"context"
	"os"
	"strconv"
	"strings"

	kms "cloud.google.com/go/kms/apiv1"
	"github.com/rs/zerolog/log"
	"google.golang.org/api/option"
)

// credentialsFile is where the plugin looks for a credentials file when
// GOOGLE_APPLICATION_CREDENTIALS is not set. config.json binds a host directory
// at /run/gcloud precisely so a key can be dropped there without also having to
// set an environment variable at install time.
// It is a var so tests can point it somewhere writable.
var credentialsFile = "/run/gcloud/credentials.json"

// clientOptions renders the credentials the Cloud KMS client should use.
//
// Nothing set means Application Default Credentials, which covers the GCE/GKE
// metadata server, a GOOGLE_APPLICATION_CREDENTIALS path, and gcloud user
// credentials. A file mounted at credentialsFile is picked up explicitly and
// may hold either a service account key or a workload identity federation
// ("external_account") config -- ADC reads both.
func clientOptions() []option.ClientOption {
	if os.Getenv("GOOGLE_APPLICATION_CREDENTIALS") != "" {
		return nil
	}

	if _, err := os.Stat(credentialsFile); err != nil {
		return nil
	}

	log.Info().Any("method", "clientOptions").Msgf("using credentials from %s", credentialsFile)
	return []option.ClientOption{option.WithCredentialsFile(credentialsFile)}
}

// newKeyManagementClient is the production implementation of the driver's
// newClient hook.
func newKeyManagementClient(ctx context.Context) (keyDecrypter, error) {
	c, err := kms.NewKeyManagementClient(ctx, clientOptions()...)
	if err != nil {
		return nil, logError("failed to create the Cloud KMS client: %v", err)
	}
	return c, nil
}

// checkCredentials reports where the plugin will get its credentials, and
// refuses to start when that is plainly not what the operator asked for.
//
// The failure it exists to catch: the credentials live on a filesystem that was
// not mounted when the plugin was enabled. Docker binds the host directory at
// that moment, so the plugin keeps reading the empty directory underneath while
// the file is plainly there on the host. Without this, the only symptom is
// "could not find default credentials" on every request.
func checkCredentials() error {
	if path := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"); path != "" {
		if _, err := os.Stat(path); err != nil {
			return logError("GOOGLE_APPLICATION_CREDENTIALS is %s, which the plugin cannot read: %v", path, err)
		}
		log.Info().Any("method", "checkCredentials").Msgf("using credentials from %s", path)
		return nil
	}

	if _, err := os.Stat(credentialsFile); err == nil {
		log.Info().Any("method", "checkCredentials").Msgf("using credentials from %s", credentialsFile)
		return nil
	}

	required, err := boolEnv("GCLOUD_REQUIRE_CREDENTIALS_FILE")
	if err != nil {
		return err
	}
	if required {
		return logError("no credentials file at %s, and GCLOUD_REQUIRE_CREDENTIALS_FILE is set. "+
			"The gcloud mount points at a host directory with no credentials.json in it; if that is a "+
			"remote filesystem, it was probably not mounted when the plugin was enabled -- mount it, "+
			"then re-enable the plugin", credentialsFile)
	}

	log.Warn().Any("method", "checkCredentials").Msgf(
		"no credentials file at %s; falling back to Application Default Credentials. "+
			"If you meant to mount one, the host directory may not have been mounted when the plugin "+
			"was enabled -- re-enable the plugin once it is", credentialsFile)

	return nil
}

func boolEnv(name string) (bool, error) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return false, nil
	}

	value, err := strconv.ParseBool(raw)
	if err != nil {
		return false, logError("%s=%q is not a boolean", name, raw)
	}

	return value, nil
}
