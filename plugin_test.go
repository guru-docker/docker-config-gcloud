package main

import (
	"context"
	"encoding/base64"
	"errors"
	"hash/crc32"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/docker/go-plugins-helpers/secrets"
	"github.com/googleapis/gax-go/v2"
	"github.com/rs/zerolog"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const testKey = "projects/acme-prod/locations/europe-west1/keyRings/configs/cryptoKeys/app"

var testDefaults = keyDefaults{Project: "acme-prod", Location: "europe-west1", KeyRing: "configs"}

func TestMain(m *testing.M) {
	// The driver logs every request; keep test output readable.
	zerolog.SetGlobalLevel(zerolog.Disabled)
	os.Exit(m.Run())
}

// fakeDecrypter stands in for *kms.KeyManagementClient so no test reaches
// Google. It "decrypts" by reversing the wrapping the tests apply.
type fakeDecrypter struct {
	mu sync.Mutex

	requests []*kmspb.DecryptRequest
	closed   int

	plaintext []byte
	crc       *wrapperspb.Int64Value
	err       error
}

func (f *fakeDecrypter) Decrypt(_ context.Context, req *kmspb.DecryptRequest, _ ...gax.CallOption) (*kmspb.DecryptResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.requests = append(f.requests, req)
	if f.err != nil {
		return nil, f.err
	}

	crc := f.crc
	if crc == nil {
		crc = wrapperspb.Int64(crc32c(f.plaintext))
	}

	return &kmspb.DecryptResponse{Plaintext: f.plaintext, PlaintextCrc32C: crc}, nil
}

func (f *fakeDecrypter) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.closed++
	return nil
}

func (f *fakeDecrypter) lastRequest(t *testing.T) *kmspb.DecryptRequest {
	t.Helper()

	f.mu.Lock()
	defer f.mu.Unlock()

	if len(f.requests) == 0 {
		t.Fatal("the driver never called Decrypt")
	}
	return f.requests[len(f.requests)-1]
}

func newTestDriver(t *testing.T, fake *fakeDecrypter) *DockerDriver {
	t.Helper()

	d := newDockerDriver(testDefaults, time.Second)
	d.newClient = func(context.Context) (keyDecrypter, error) { return fake, nil }

	return d
}

// useCiphertextDir points file lookups at a temporary directory for one test.
func useCiphertextDir(t *testing.T) string {
	t.Helper()

	original := ciphertextDir
	t.Cleanup(func() { ciphertextDir = original })
	ciphertextDir = t.TempDir()

	return ciphertextDir
}

func b64(data string) string { return base64.StdEncoding.EncodeToString([]byte(data)) }

// --- key resolution --------------------------------------------------------

func TestResolveKey(t *testing.T) {
	tests := []struct {
		name     string
		labels   map[string]string
		defaults keyDefaults
		want     string
	}{
		{
			name:   "full key label",
			labels: map[string]string{labelKey: testKey},
			want:   testKey,
		},
		{
			name:     "assembled from the plugin defaults",
			labels:   map[string]string{labelCryptoKey: "app"},
			defaults: testDefaults,
			want:     testKey,
		},
		{
			name: "labels override the defaults",
			labels: map[string]string{
				labelProject:   "acme-dev",
				labelLocation:  "us-central1",
				labelKeyRing:   "scratch",
				labelCryptoKey: "app",
			},
			defaults: testDefaults,
			want:     "projects/acme-dev/locations/us-central1/keyRings/scratch/cryptoKeys/app",
		},
		{
			name:     "the key label wins over the parts",
			labels:   map[string]string{labelKey: testKey, labelCryptoKey: "ignored"},
			defaults: keyDefaults{Project: "elsewhere"},
			want:     testKey,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveKey(tt.labels, tt.defaults)
			if err != nil {
				t.Fatalf("resolveKey: %v", err)
			}
			if got != tt.want {
				t.Errorf("key = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestResolveKey_Errors(t *testing.T) {
	tests := []struct {
		name     string
		labels   map[string]string
		defaults keyDefaults
		wantErr  []string
	}{
		{
			name:    "nothing configured names every missing part",
			labels:  map[string]string{},
			wantErr: []string{labelProject, labelLocation, labelKeyRing, labelCryptoKey},
		},
		{
			name:     "only the key name is missing",
			labels:   map[string]string{},
			defaults: testDefaults,
			wantErr:  []string{labelCryptoKey},
		},
		{
			name:    "malformed key label",
			labels:  map[string]string{labelKey: "projects/acme-prod/cryptoKeys/app"},
			wantErr: []string{"not a Cloud KMS key"},
		},
		{
			name:    "a key version is not a decryption key",
			labels:  map[string]string{labelKey: testKey + "/cryptoKeyVersions/3"},
			wantErr: []string{"not a Cloud KMS key"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := resolveKey(tt.labels, tt.defaults)
			if err == nil {
				t.Fatal("expected an error")
			}
			for _, want := range tt.wantErr {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not mention %q", err, want)
				}
			}
		})
	}
}

// --- request resolution ----------------------------------------------------

func TestResolve_InlineCiphertext(t *testing.T) {
	tests := []struct {
		name  string
		label string
	}{
		{"standard alphabet", base64.StdEncoding.EncodeToString([]byte("wrapped"))},
		{"unpadded", base64.RawStdEncoding.EncodeToString([]byte("wrapped"))},
		{"url safe", base64.URLEncoding.EncodeToString([]byte("wrapped"))},
		{"wrapped in whitespace", "  " + base64.StdEncoding.EncodeToString([]byte("wrapped")) + "\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ref, err := resolve(secrets.Request{
				SecretLabels: map[string]string{labelKey: testKey, labelCiphertext: tt.label},
			}, keyDefaults{})
			if err != nil {
				t.Fatalf("resolve: %v", err)
			}
			if string(ref.Ciphertext) != "wrapped" {
				t.Errorf("Ciphertext = %q, want %q", ref.Ciphertext, "wrapped")
			}
			if ref.File != "" {
				t.Errorf("File = %q, want empty", ref.File)
			}
		})
	}
}

func TestResolve_File(t *testing.T) {
	ref, err := resolve(secrets.Request{
		SecretLabels: map[string]string{
			labelKey:      testKey,
			labelFile:     "app.enc",
			labelEncoding: "base64",
			labelAAD:      "production",
		},
	}, keyDefaults{})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}

	if ref.File != "app.enc" {
		t.Errorf("File = %q", ref.File)
	}
	if !ref.Base64 {
		t.Error("Base64 = false, want true")
	}
	if string(ref.AAD) != "production" {
		t.Errorf("AAD = %q", ref.AAD)
	}
}

func TestResolve_Errors(t *testing.T) {
	tests := []struct {
		name    string
		labels  map[string]string
		wantErr string
	}{
		{
			name:    "no ciphertext at all",
			labels:  map[string]string{labelKey: testKey},
			wantErr: "no ciphertext",
		},
		{
			name:    "both sources",
			labels:  map[string]string{labelKey: testKey, labelCiphertext: b64("wrapped"), labelFile: "app.enc"},
			wantErr: "mutually exclusive",
		},
		{
			name:    "unknown encoding",
			labels:  map[string]string{labelKey: testKey, labelFile: "app.enc", labelEncoding: "hex"},
			wantErr: "raw, base64",
		},
		{
			name:    "unparseable do_not_reuse",
			labels:  map[string]string{labelKey: testKey, labelCiphertext: b64("wrapped"), labelDoNotReuse: "sometimes"},
			wantErr: "not a boolean",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := resolve(secrets.Request{SecretLabels: tt.labels}, keyDefaults{})
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not mention %q", err, tt.wantErr)
			}
		})
	}
}

func TestResolve_DoNotReuse(t *testing.T) {
	for _, tt := range []struct {
		label string
		want  bool
	}{{"", false}, {"true", true}, {"1", true}, {"false", false}} {
		t.Run("label="+tt.label, func(t *testing.T) {
			ref, err := resolve(secrets.Request{
				SecretLabels: map[string]string{
					labelKey:        testKey,
					labelCiphertext: b64("wrapped"),
					labelDoNotReuse: tt.label,
				},
			}, keyDefaults{})
			if err != nil {
				t.Fatalf("resolve: %v", err)
			}
			if ref.DoNotReuse != tt.want {
				t.Errorf("DoNotReuse = %v, want %v", ref.DoNotReuse, tt.want)
			}
		})
	}
}

// --- reading ciphertext files ----------------------------------------------

func TestCiphertext_ReadsAFile(t *testing.T) {
	dir := useCiphertextDir(t)
	if err := os.WriteFile(filepath.Join(dir, "app.enc"), []byte("wrapped"), 0600); err != nil {
		t.Fatal(err)
	}

	d := newTestDriver(t, &fakeDecrypter{})

	got, err := d.ciphertext(configRef{File: "app.enc"})
	if err != nil {
		t.Fatalf("ciphertext: %v", err)
	}
	if string(got) != "wrapped" {
		t.Errorf("ciphertext = %q", got)
	}
}

func TestCiphertext_DecodesABase64File(t *testing.T) {
	dir := useCiphertextDir(t)
	if err := os.WriteFile(filepath.Join(dir, "app.enc"), []byte(b64("wrapped")+"\n"), 0600); err != nil {
		t.Fatal(err)
	}

	d := newTestDriver(t, &fakeDecrypter{})

	got, err := d.ciphertext(configRef{File: "app.enc", Base64: true})
	if err != nil {
		t.Fatalf("ciphertext: %v", err)
	}
	if string(got) != "wrapped" {
		t.Errorf("ciphertext = %q", got)
	}
}

func TestCiphertext_MissingFile(t *testing.T) {
	useCiphertextDir(t)
	d := newTestDriver(t, &fakeDecrypter{})

	if _, err := d.ciphertext(configRef{File: "absent.enc"}); err == nil {
		t.Fatal("expected an error for a file that is not there")
	}
}

// Labels come from whoever created the config; a file label must not be able to
// read the host's plugin directory or the credentials next to it.
func TestCiphertextPath_StaysInsideTheMount(t *testing.T) {
	dir := useCiphertextDir(t)

	t.Run("plain name", func(t *testing.T) {
		got, err := ciphertextPath("app.enc")
		if err != nil {
			t.Fatalf("ciphertextPath: %v", err)
		}
		if got != filepath.Join(dir, "app.enc") {
			t.Errorf("path = %q", got)
		}
	})

	t.Run("subdirectory", func(t *testing.T) {
		got, err := ciphertextPath("apps/web.enc")
		if err != nil {
			t.Fatalf("ciphertextPath: %v", err)
		}
		if got != filepath.Join(dir, "apps", "web.enc") {
			t.Errorf("path = %q", got)
		}
	})

	for _, name := range []string{
		"../credentials.json",
		"../../etc/shadow",
		"apps/../../credentials.json",
		"/etc/shadow",
	} {
		t.Run("escape "+name, func(t *testing.T) {
			got, err := ciphertextPath(name)
			if err != nil && strings.Contains(err.Error(), "escapes") {
				return
			}
			if err != nil {
				t.Fatalf("ciphertextPath: %v", err)
			}
			if !strings.HasPrefix(got, dir+string(filepath.Separator)) {
				t.Errorf("%q resolved outside the mount: %q", name, got)
			}
		})
	}
}

// --- Get -------------------------------------------------------------------

func TestGet_ReturnsThePlaintext(t *testing.T) {
	fake := &fakeDecrypter{plaintext: []byte("listen: 0.0.0.0:8080")}
	d := newTestDriver(t, fake)

	resp := d.Get(secrets.Request{
		SecretName:   "app-config",
		SecretLabels: map[string]string{labelCryptoKey: "app", labelCiphertext: b64("wrapped")},
	})

	if resp.Err != "" {
		t.Fatalf("Get: %s", resp.Err)
	}
	if string(resp.Value) != "listen: 0.0.0.0:8080" {
		t.Errorf("Value = %q", resp.Value)
	}

	req := fake.lastRequest(t)
	if req.GetName() != testKey {
		t.Errorf("key = %q, want %q", req.GetName(), testKey)
	}
	if string(req.GetCiphertext()) != "wrapped" {
		t.Errorf("ciphertext = %q", req.GetCiphertext())
	}
	if req.GetCiphertextCrc32C().GetValue() != crc32c([]byte("wrapped")) {
		t.Error("the request did not carry a ciphertext checksum")
	}
	if len(req.GetAdditionalAuthenticatedData()) != 0 {
		t.Error("AAD was sent although no label asked for it")
	}
}

func TestGet_SendsAAD(t *testing.T) {
	fake := &fakeDecrypter{plaintext: []byte("config")}
	d := newTestDriver(t, fake)

	resp := d.Get(secrets.Request{
		SecretName: "app-config",
		SecretLabels: map[string]string{
			labelKey:        testKey,
			labelCiphertext: b64("wrapped"),
			labelAAD:        "production",
		},
	})
	if resp.Err != "" {
		t.Fatalf("Get: %s", resp.Err)
	}

	req := fake.lastRequest(t)
	if string(req.GetAdditionalAuthenticatedData()) != "production" {
		t.Errorf("AAD = %q", req.GetAdditionalAuthenticatedData())
	}
	if req.GetAdditionalAuthenticatedDataCrc32C().GetValue() != crc32c([]byte("production")) {
		t.Error("the AAD was sent without its checksum")
	}
}

func TestGet_ReadsTheCiphertextFromAFile(t *testing.T) {
	dir := useCiphertextDir(t)
	if err := os.WriteFile(filepath.Join(dir, "app.enc"), []byte("wrapped"), 0600); err != nil {
		t.Fatal(err)
	}

	fake := &fakeDecrypter{plaintext: []byte("config")}
	d := newTestDriver(t, fake)

	resp := d.Get(secrets.Request{
		SecretName:   "app-config",
		SecretLabels: map[string]string{labelKey: testKey, labelFile: "app.enc"},
	})
	if resp.Err != "" {
		t.Fatalf("Get: %s", resp.Err)
	}
	if string(fake.lastRequest(t).GetCiphertext()) != "wrapped" {
		t.Errorf("ciphertext = %q", fake.lastRequest(t).GetCiphertext())
	}
}

func TestGet_PassesDoNotReuseThrough(t *testing.T) {
	d := newTestDriver(t, &fakeDecrypter{plaintext: []byte("config")})

	resp := d.Get(secrets.Request{
		SecretName: "app-config",
		SecretLabels: map[string]string{
			labelKey:        testKey,
			labelCiphertext: b64("wrapped"),
			labelDoNotReuse: "true",
		},
	})
	if resp.Err != "" {
		t.Fatalf("Get: %s", resp.Err)
	}
	if !resp.DoNotReuse {
		t.Error("DoNotReuse = false, want true")
	}
}

func TestGet_ResolutionFailureDoesNotCallTheAPI(t *testing.T) {
	fake := &fakeDecrypter{plaintext: []byte("config")}
	d := newDockerDriver(keyDefaults{}, time.Second)
	d.newClient = func(context.Context) (keyDecrypter, error) { return fake, nil }

	resp := d.Get(secrets.Request{SecretName: "app-config"})

	if resp.Err == "" {
		t.Fatal("expected an error when no key is configured")
	}
	if len(fake.requests) != 0 {
		t.Errorf("the API was called anyway: %v", fake.requests)
	}
}

func TestGet_ReportsAPIFailure(t *testing.T) {
	fake := &fakeDecrypter{err: errors.New("permission denied")}
	d := newTestDriver(t, fake)

	resp := d.Get(secrets.Request{
		SecretName:   "app-config",
		SecretLabels: map[string]string{labelKey: testKey, labelCiphertext: b64("wrapped")},
	})

	if resp.Err == "" {
		t.Fatal("expected the API failure to surface")
	}
	if !strings.Contains(resp.Err, "permission denied") {
		t.Errorf("Err = %q, want the underlying cause", resp.Err)
	}
	if len(resp.Value) != 0 {
		t.Errorf("a failed Get must not return a value, got %q", resp.Value)
	}
}

func TestGet_RejectsAnEmptyCiphertext(t *testing.T) {
	fake := &fakeDecrypter{plaintext: []byte("config")}
	d := newTestDriver(t, fake)

	resp := d.Get(secrets.Request{
		SecretName:   "app-config",
		SecretLabels: map[string]string{labelKey: testKey, labelCiphertext: "  "},
	})

	if resp.Err == "" {
		t.Fatal("expected an error for an empty ciphertext label")
	}
	if len(fake.requests) != 0 {
		t.Error("an empty ciphertext was sent to KMS")
	}
}

// A damaged plaintext must not be handed to a container as if it were the
// config; KMS ships a checksum precisely so this is detectable.
func TestGet_RejectsACorruptedPlaintext(t *testing.T) {
	fake := &fakeDecrypter{plaintext: []byte("config"), crc: wrapperspb.Int64(1)}
	d := newTestDriver(t, fake)

	resp := d.Get(secrets.Request{
		SecretName:   "app-config",
		SecretLabels: map[string]string{labelKey: testKey, labelCiphertext: b64("wrapped")},
	})

	if resp.Err == "" {
		t.Fatal("expected a checksum failure")
	}
	if !strings.Contains(resp.Err, "crc32c") {
		t.Errorf("Err = %q, want a checksum message", resp.Err)
	}
}

func TestGet_ReusesTheClient(t *testing.T) {
	fake := &fakeDecrypter{plaintext: []byte("config")}
	d := newDockerDriver(testDefaults, time.Second)

	var built int
	d.newClient = func(context.Context) (keyDecrypter, error) {
		built++
		return fake, nil
	}

	for i := 0; i < 3; i++ {
		resp := d.Get(secrets.Request{
			SecretName:   "app-config",
			SecretLabels: map[string]string{labelCryptoKey: "app", labelCiphertext: b64("wrapped")},
		})
		if resp.Err != "" {
			t.Fatalf("Get %d: %s", i, resp.Err)
		}
	}

	if built != 1 {
		t.Errorf("client built %d times, want 1", built)
	}
}

// A plugin installed before its credentials are in place must recover once they
// appear, rather than caching the failure for its lifetime.
func TestGet_RetriesAFailedClientBuild(t *testing.T) {
	fake := &fakeDecrypter{plaintext: []byte("config")}
	d := newDockerDriver(testDefaults, time.Second)

	var attempts int
	d.newClient = func(context.Context) (keyDecrypter, error) {
		attempts++
		if attempts == 1 {
			return nil, errors.New("no credentials")
		}
		return fake, nil
	}

	req := secrets.Request{
		SecretName:   "app-config",
		SecretLabels: map[string]string{labelCryptoKey: "app", labelCiphertext: b64("wrapped")},
	}

	if resp := d.Get(req); resp.Err == "" {
		t.Fatal("expected the first request to fail")
	}
	if resp := d.Get(req); resp.Err != "" {
		t.Fatalf("second request: %s", resp.Err)
	}
	if attempts != 2 {
		t.Errorf("newClient called %d times, want 2", attempts)
	}
}

func TestGet_HonoursTheTimeout(t *testing.T) {
	d := newDockerDriver(testDefaults, time.Millisecond)

	var deadline time.Time
	d.newClient = func(ctx context.Context) (keyDecrypter, error) {
		deadline, _ = ctx.Deadline()
		return &fakeDecrypter{plaintext: []byte("config")}, nil
	}

	resp := d.Get(secrets.Request{
		SecretName:   "app-config",
		SecretLabels: map[string]string{labelCryptoKey: "app", labelCiphertext: b64("wrapped")},
	})
	if resp.Err != "" {
		t.Fatalf("Get: %s", resp.Err)
	}
	if deadline.IsZero() {
		t.Fatal("the API call was made without a deadline")
	}
}

func TestClose(t *testing.T) {
	fake := &fakeDecrypter{plaintext: []byte("config")}
	d := newTestDriver(t, fake)

	if err := d.Close(); err != nil {
		t.Fatalf("Close before any request: %v", err)
	}
	if fake.closed != 0 {
		t.Error("closed a client that was never built")
	}

	resp := d.Get(secrets.Request{
		SecretName:   "app-config",
		SecretLabels: map[string]string{labelCryptoKey: "app", labelCiphertext: b64("wrapped")},
	})
	if resp.Err != "" {
		t.Fatal(resp.Err)
	}
	if err := d.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if fake.closed != 1 {
		t.Errorf("client closed %d times, want 1", fake.closed)
	}
}

// --- checksum --------------------------------------------------------------

func TestVerifyCRC32C(t *testing.T) {
	data := []byte("config")

	if err := verifyCRC32C(data, nil); err != nil {
		t.Errorf("an absent checksum must be accepted: %v", err)
	}
	if err := verifyCRC32C(data, wrapperspb.Int64(int64(crc32.Checksum(data, crc32.MakeTable(crc32.Castagnoli))))); err != nil {
		t.Errorf("a matching checksum must be accepted: %v", err)
	}
	if err := verifyCRC32C(data, wrapperspb.Int64(42)); err == nil {
		t.Error("a mismatched checksum must be rejected")
	}
}

// --- environment -----------------------------------------------------------

func TestTimeoutFromEnv(t *testing.T) {
	tests := []struct {
		value   string
		want    time.Duration
		wantErr bool
	}{
		{"", defaultTimeout, false},
		{"5s", 5 * time.Second, false},
		{"1m30s", 90 * time.Second, false},
		{"soon", 0, true},
		{"0", 0, true},
		{"-5s", 0, true},
	}

	for _, tt := range tests {
		t.Run("GCLOUD_TIMEOUT="+tt.value, func(t *testing.T) {
			t.Setenv("GCLOUD_TIMEOUT", tt.value)

			got, err := timeoutFromEnv()
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("timeoutFromEnv: %v", err)
			}
			if got != tt.want {
				t.Errorf("timeout = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestLogLevel(t *testing.T) {
	for _, tt := range []struct {
		value string
		want  zerolog.Level
	}{
		{"", zerolog.InfoLevel},
		{"0", zerolog.InfoLevel},
		{"1", zerolog.DebugLevel},
		{"true", zerolog.DebugLevel},
		{"nonsense", zerolog.InfoLevel},
	} {
		t.Run("DEBUG="+tt.value, func(t *testing.T) {
			t.Setenv("DEBUG", tt.value)

			if got := logLevel(); got != tt.want {
				t.Errorf("logLevel() = %s, want %s", got, tt.want)
			}
		})
	}
}

// --- credentials -----------------------------------------------------------

func TestClientOptions(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "credentials.json")

	original := credentialsFile
	t.Cleanup(func() { credentialsFile = original })

	t.Run("nothing configured falls back to ADC", func(t *testing.T) {
		t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")
		credentialsFile = filepath.Join(dir, "absent.json")
		if opts := clientOptions(); len(opts) != 0 {
			t.Errorf("got %d options, want none", len(opts))
		}
	})

	t.Run("a mounted credentials file is used", func(t *testing.T) {
		t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")
		if err := os.WriteFile(key, []byte(`{"type":"service_account"}`), 0600); err != nil {
			t.Fatal(err)
		}
		credentialsFile = key

		if opts := clientOptions(); len(opts) != 1 {
			t.Errorf("got %d options, want 1", len(opts))
		}
	})

	t.Run("GOOGLE_APPLICATION_CREDENTIALS wins", func(t *testing.T) {
		t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", key)
		credentialsFile = key

		if opts := clientOptions(); len(opts) != 0 {
			t.Errorf("got %d options, want none: ADC reads the variable itself", len(opts))
		}
	})
}

// --- the startup credentials check -----------------------------------------

func TestCheckCredentials(t *testing.T) {
	dir := t.TempDir()
	present := filepath.Join(dir, "credentials.json")
	if err := os.WriteFile(present, []byte(`{"type":"service_account"}`), 0600); err != nil {
		t.Fatal(err)
	}
	absent := filepath.Join(dir, "absent.json")

	original := credentialsFile
	t.Cleanup(func() { credentialsFile = original })

	tests := []struct {
		name     string
		envPath  string
		mounted  string
		required string
		wantErr  string
	}{
		{
			name:    "a mounted credentials file is accepted",
			mounted: present,
		},
		{
			name:    "GOOGLE_APPLICATION_CREDENTIALS is accepted",
			envPath: present,
			mounted: absent,
		},
		{
			name:    "GOOGLE_APPLICATION_CREDENTIALS pointing at nothing is fatal",
			envPath: absent,
			mounted: present,
			wantErr: "cannot read",
		},
		{
			name:    "an empty mount falls back to ADC by default",
			mounted: absent,
		},
		{
			name:     "an empty mount is fatal when the file is required",
			mounted:  absent,
			required: "1",
			wantErr:  "not mounted when the plugin was enabled",
		},
		{
			name:     "a required file that is present is accepted",
			mounted:  present,
			required: "true",
		},
		{
			name:     "an unparseable requirement is fatal",
			mounted:  absent,
			required: "maybe",
			wantErr:  "not a boolean",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", tt.envPath)
			t.Setenv("GCLOUD_REQUIRE_CREDENTIALS_FILE", tt.required)
			credentialsFile = tt.mounted

			err := checkCredentials()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("checkCredentials: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("expected the plugin to refuse to start")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not mention %q", err, tt.wantErr)
			}
		})
	}
}
