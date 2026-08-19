package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"hash/crc32"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/docker/go-plugins-helpers/secrets"
	"github.com/googleapis/gax-go/v2"
	"github.com/rs/zerolog/log"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// Labels set on the swarm object say which key unwraps it, and where the
// wrapped bytes are.
const (
	labelKey        = "gcloud.key"
	labelProject    = "gcloud.project"
	labelLocation   = "gcloud.location"
	labelKeyRing    = "gcloud.keyring"
	labelCryptoKey  = "gcloud.crypto_key"
	labelCiphertext = "gcloud.ciphertext"
	labelFile       = "gcloud.file"
	labelEncoding   = "gcloud.encoding"
	labelAAD        = "gcloud.aad"
	labelDoNotReuse = "gcloud.do_not_reuse"
)

// ciphertextDir is where gcloud.file is resolved. It is the same bind mount the
// credentials come from, so one host directory holds everything the plugin
// reads. A var so tests can point it at a temporary directory.
var ciphertextDir = "/run/gcloud"

// Symmetric decryption addresses the CryptoKey, not one of its versions: KMS
// picks the version the ciphertext was wrapped with.
var keyPattern = regexp.MustCompile(`^projects/[^/]+/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/]+$`)

// keyDecrypter is the part of *kms.KeyManagementClient the driver uses; tests
// substitute a fake so no call reaches Google.
type keyDecrypter interface {
	Decrypt(context.Context, *kmspb.DecryptRequest, ...gax.CallOption) (*kmspb.DecryptResponse, error)
	Close() error
}

// keyDefaults fill in the parts of a key name that are the same for every
// config on a host, so a label only has to name the key itself.
type keyDefaults struct {
	Project  string
	Location string
	KeyRing  string
}

// DockerDriver serves docker.secretprovider requests by unwrapping a ciphertext
// with Cloud KMS.
type DockerDriver struct {
	sync.Mutex

	defaults keyDefaults
	timeout  time.Duration

	client keyDecrypter
	// newClient builds the API client on first use; tests replace it. It is a
	// field rather than a call in the constructor so that a plugin installed
	// without working credentials still starts and reports the failure per
	// request instead of crash-looping.
	newClient func(context.Context) (keyDecrypter, error)
}

func newDockerDriver(defaults keyDefaults, timeout time.Duration) *DockerDriver {
	log.Info().Any("method", "new driver").Msgf("defaults=%+v timeout=%s", defaults, timeout)

	return &DockerDriver{
		defaults:  defaults,
		timeout:   timeout,
		newClient: newKeyManagementClient,
	}
}

// configRef is a resolved request: which key to use, where the wrapped bytes
// are, and whether the plaintext may be shared between tasks.
type configRef struct {
	Key string

	// Exactly one of Ciphertext and File is set.
	Ciphertext []byte
	File       string
	// Base64 says the file holds base64 rather than the raw bytes that
	// `gcloud kms encrypt --ciphertext-file` writes.
	Base64 bool

	AAD        []byte
	DoNotReuse bool
}

// Get implements secrets.Driver.
func (d *DockerDriver) Get(req secrets.Request) secrets.Response {
	log.Info().Any("method", "get").
		Str("config", req.SecretName).
		Str("service", req.ServiceName).
		Str("task", req.TaskID).
		Msgf("%v", req.SecretLabels)

	ref, err := resolve(req, d.defaults)
	if err != nil {
		return secrets.Response{Err: err.Error()}
	}

	ciphertext, err := d.ciphertext(ref)
	if err != nil {
		return secrets.Response{Err: err.Error()}
	}

	ctx, cancel := context.WithTimeout(context.Background(), d.timeout)
	defer cancel()

	plaintext, err := d.decrypt(ctx, ref, ciphertext)
	if err != nil {
		return secrets.Response{Err: err.Error()}
	}

	log.Info().Any("method", "get").
		Str("config", req.SecretName).
		Msgf("delivered %d bytes unwrapped with %s", len(plaintext), ref.Key)

	return secrets.Response{Value: plaintext, DoNotReuse: ref.DoNotReuse}
}

// Close releases the API client. Safe to call on a driver that never built one.
func (d *DockerDriver) Close() error {
	d.Lock()
	defer d.Unlock()

	if d.client == nil {
		return nil
	}

	err := d.client.Close()
	d.client = nil
	return err
}

// ciphertext returns the wrapped bytes named by the reference, reading them
// from the mounted directory when the reference points at a file.
func (d *DockerDriver) ciphertext(ref configRef) ([]byte, error) {
	if ref.File == "" {
		return ref.Ciphertext, nil
	}

	path, err := ciphertextPath(ref.File)
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, logError("failed to read the ciphertext: %v", err)
	}
	if !ref.Base64 {
		return data, nil
	}

	decoded, err := decodeBase64(strings.TrimSpace(string(data)))
	if err != nil {
		return nil, logError("%s: %v", ref.File, err)
	}

	return decoded, nil
}

// decrypt unwraps the ciphertext and checks the plaintext arrived intact. The
// ciphertext checksum travels with the request so KMS can reject bytes that
// were damaged on the way out.
func (d *DockerDriver) decrypt(ctx context.Context, ref configRef, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) == 0 {
		return nil, logError("the ciphertext is empty")
	}

	client, err := d.clientFor(ctx)
	if err != nil {
		return nil, err
	}

	req := &kmspb.DecryptRequest{
		Name:             ref.Key,
		Ciphertext:       ciphertext,
		CiphertextCrc32C: wrapperspb.Int64(crc32c(ciphertext)),
	}
	if len(ref.AAD) > 0 {
		req.AdditionalAuthenticatedData = ref.AAD
		req.AdditionalAuthenticatedDataCrc32C = wrapperspb.Int64(crc32c(ref.AAD))
	}

	resp, err := client.Decrypt(ctx, req)
	if err != nil {
		return nil, logError("failed to decrypt with %s: %v", ref.Key, err)
	}

	plaintext := resp.GetPlaintext()
	if err = verifyCRC32C(plaintext, resp.GetPlaintextCrc32C()); err != nil {
		return nil, logError("%s: %v", ref.Key, err)
	}

	return plaintext, nil
}

// clientFor returns the cached API client, building it on first use. A failed
// build is not cached, so a plugin that started before its credentials were in
// place recovers on the next request.
func (d *DockerDriver) clientFor(ctx context.Context) (keyDecrypter, error) {
	d.Lock()
	defer d.Unlock()

	if d.client != nil {
		return d.client, nil
	}

	client, err := d.newClient(ctx)
	if err != nil {
		return nil, err
	}
	d.client = client

	return client, nil
}

// resolve turns a driver request into the key to use and the ciphertext to
// unwrap with it.
func resolve(req secrets.Request, defaults keyDefaults) (configRef, error) {
	labels := req.SecretLabels

	key, err := resolveKey(labels, defaults)
	if err != nil {
		return configRef{}, err
	}

	ref := configRef{Key: key, AAD: []byte(labels[labelAAD])}
	if ref.DoNotReuse, err = boolLabel(labels, labelDoNotReuse); err != nil {
		return configRef{}, err
	}

	inline := strings.TrimSpace(labels[labelCiphertext])
	file := strings.TrimSpace(labels[labelFile])

	switch {
	case inline != "" && file != "":
		return configRef{}, logError("%s and %s are mutually exclusive", labelCiphertext, labelFile)
	case inline != "":
		if ref.Ciphertext, err = decodeBase64(inline); err != nil {
			return configRef{}, logError("%s: %v", labelCiphertext, err)
		}
	case file != "":
		ref.File = file
		if ref.Base64, err = encodingLabel(labels); err != nil {
			return configRef{}, err
		}
	default:
		return configRef{}, logError("no ciphertext: set the %q label (base64) or the %q label", labelCiphertext, labelFile)
	}

	return ref, nil
}

// resolveKey assembles the CryptoKey resource name, either taken whole from a
// label or built from the parts the plugin was installed with.
func resolveKey(labels map[string]string, defaults keyDefaults) (string, error) {
	if key := strings.TrimSpace(labels[labelKey]); key != "" {
		if !keyPattern.MatchString(key) {
			return "", logError("%q is not a Cloud KMS key (projects/<project>/locations/<location>/keyRings/<ring>/cryptoKeys/<key>)", key)
		}
		return key, nil
	}

	project := firstNonEmpty(labels[labelProject], defaults.Project)
	location := firstNonEmpty(labels[labelLocation], defaults.Location)
	keyRing := firstNonEmpty(labels[labelKeyRing], defaults.KeyRing)
	cryptoKey := strings.TrimSpace(labels[labelCryptoKey])

	var missing []string
	for _, part := range []struct{ name, value string }{
		{labelProject, project},
		{labelLocation, location},
		{labelKeyRing, keyRing},
		{labelCryptoKey, cryptoKey},
	} {
		if part.value == "" {
			missing = append(missing, part.name)
		}
	}
	if len(missing) > 0 {
		return "", logError("no key: set the %q label, or supply %s", labelKey, strings.Join(missing, ", "))
	}

	return fmt.Sprintf("projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s", project, location, keyRing, cryptoKey), nil
}

// ciphertextPath resolves a gcloud.file label against the mounted directory. A
// label is data from whoever created the config, so it must not be able to
// reach outside that directory.
func ciphertextPath(name string) (string, error) {
	root, err := filepath.Abs(ciphertextDir)
	if err != nil {
		return "", logError("%v", err)
	}

	path := filepath.Join(root, filepath.Clean("/"+name))
	if path != root && !strings.HasPrefix(path, root+string(filepath.Separator)) {
		return "", logError("%s=%q escapes %s", labelFile, name, ciphertextDir)
	}

	return path, nil
}

// decodeBase64 accepts both the standard and the URL-safe alphabet, with or
// without padding, because ciphertext gets pasted from all sorts of places.
func decodeBase64(s string) ([]byte, error) {
	s = strings.Join(strings.Fields(s), "")

	for _, encoding := range []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	} {
		if decoded, err := encoding.DecodeString(s); err == nil {
			return decoded, nil
		}
	}

	return nil, fmt.Errorf("not valid base64")
}

// verifyCRC32C checks the plaintext against the checksum KMS computed for it.
func verifyCRC32C(data []byte, want *wrapperspb.Int64Value) error {
	if want == nil {
		return nil
	}

	if got := crc32c(data); want.GetValue() != got {
		return fmt.Errorf("plaintext failed its crc32c check (want %d, got %d)", want.GetValue(), got)
	}

	return nil
}

func crc32c(data []byte) int64 {
	return int64(crc32.Checksum(data, crc32.MakeTable(crc32.Castagnoli)))
}

func encodingLabel(labels map[string]string) (base64Encoded bool, err error) {
	switch encoding := strings.ToLower(strings.TrimSpace(labels[labelEncoding])); encoding {
	case "", "raw", "binary":
		return false, nil
	case "base64":
		return true, nil
	default:
		return false, logError("label %s=%q is not one of raw, base64", labelEncoding, encoding)
	}
}

func boolLabel(labels map[string]string, key string) (bool, error) {
	raw := strings.TrimSpace(labels[key])
	if raw == "" {
		return false, nil
	}

	value, err := strconv.ParseBool(raw)
	if err != nil {
		return false, logError("label %s=%q is not a boolean", key, raw)
	}

	return value, nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v = strings.TrimSpace(v); v != "" {
			return v
		}
	}
	return ""
}

func logError(format string, args ...interface{}) error {
	log.Error().Any("method", "logError").Msgf(format, args...)
	return fmt.Errorf(format, args...)
}
