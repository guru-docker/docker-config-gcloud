package main

import (
	"os"
	"strconv"
	"time"

	"github.com/docker/go-plugins-helpers/secrets"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

const socketAddress = "/run/docker/plugins/config-gcloud.sock"

// defaultTimeout bounds a single Cloud KMS call. Docker gives the whole driver
// request a deadline of its own, so this only has to be shorter.
const defaultTimeout = 30 * time.Second

func main() {
	zerolog.SetGlobalLevel(logLevel())

	timeout, err := timeoutFromEnv()
	if err != nil {
		log.Fatal().Msg(err.Error())
	}

	if err = checkCredentials(); err != nil {
		log.Fatal().Msg(err.Error())
	}

	d := newDockerDriver(keyDefaults{
		Project:  os.Getenv("GOOGLE_CLOUD_PROJECT"),
		Location: os.Getenv("GCLOUD_LOCATION"),
		KeyRing:  os.Getenv("GCLOUD_KEYRING"),
	}, timeout)
	defer d.Close()

	h := secrets.NewHandler(d)

	log.Info().Any("method", "main").Msgf("listening on %s", socketAddress)
	log.Error().Msgf("%v", h.ServeUnix(socketAddress, 0))
}

// logLevel reads the DEBUG variable the plugin declares in config.json.
func logLevel() zerolog.Level {
	if debug, err := strconv.ParseBool(os.Getenv("DEBUG")); err == nil && debug {
		return zerolog.DebugLevel
	}
	return zerolog.InfoLevel
}

func timeoutFromEnv() (time.Duration, error) {
	raw := os.Getenv("GCLOUD_TIMEOUT")
	if raw == "" {
		return defaultTimeout, nil
	}

	timeout, err := time.ParseDuration(raw)
	if err != nil {
		return 0, logError("GCLOUD_TIMEOUT %q is not a duration: %v", raw, err)
	}
	if timeout <= 0 {
		return 0, logError("GCLOUD_TIMEOUT %q must be positive", raw)
	}

	return timeout, nil
}
