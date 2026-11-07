package update

import (
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func installer(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("../../install.sh")
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestInstallerPinsTheReleaseKey(t *testing.T) {
	if !strings.Contains(installer(t), ReleaseKey) {
		t.Fatal("install.sh does not hold update.ReleaseKey")
	}
}

func TestInstallerCannotSkipItsChecks(t *testing.T) {
	text := installer(t)
	if strings.Contains(text, "if command -v sha256sum") {
		t.Fatal("the sum check can be skipped")
	}
	if !strings.Contains(text, "verify_sums \"$tmp\" \"$RELEASE_KEY\" || fail") {
		t.Fatal("the signature is not checked")
	}
}

func TestComposePinsImagesByDigest(t *testing.T) {
	data, err := os.ReadFile("../../compose.yaml")
	if err != nil {
		t.Fatal(err)
	}
	images := regexp.MustCompile(`(?m)^\s+image: (\S+)$`).FindAllStringSubmatch(string(data), -1)
	if len(images) != 2 {
		t.Fatal("images", images)
	}
	for _, image := range images {
		if !regexp.MustCompile(`@sha256:[0-9a-f]{64}$`).MatchString(image[1]) {
			t.Fatal("not pinned: ", image[1])
		}
	}
}

// The installer's own functions, against real signatures.
func TestInstallerSignatureCheck(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("SKIPPED: no openssl to run the installer's check")
	}
	text := installer(t)
	start, end := strings.Index(text, "# ---------- the release's signature"), strings.Index(text, "# ---------- end of the signature functions")
	if start < 0 || end < start {
		t.Fatal("markers")
	}
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	run := func(sums, sig, key string) error {
		dir := t.TempDir()
		os.WriteFile(filepath.Join(dir, "SHA256SUMS"), []byte(sums), 0o644)
		os.WriteFile(filepath.Join(dir, "SHA256SUMS.sig"), []byte(sig), 0o644)
		script := filepath.Join(t.TempDir(), "check.sh")
		os.WriteFile(script, []byte(text[start:end]+"\nverify_sums \"$1\" \"$2\"\n"), 0o755)
		return exec.Command("sh", script, dir, key).Run()
	}
	sums := "aa  compose.yaml\n"
	signature := hex.EncodeToString(ed25519.Sign(private, []byte(sums))) + "\n"
	key := hex.EncodeToString(public)
	if err := run(sums, signature, key); err != nil {
		t.Fatal("good signature refused: ", err)
	}
	if run(sums+"x", signature, key) == nil {
		t.Fatal("changed sums accepted")
	}
	other, _, _ := ed25519.GenerateKey(nil)
	if run(sums, signature, hex.EncodeToString(other)) == nil {
		t.Fatal("another key accepted")
	}
	for _, bad := range []string{"", "zz\n", signature[:64]} {
		if run(sums, bad, key) == nil {
			t.Fatal("bad signature text accepted: ", bad)
		}
	}
}
