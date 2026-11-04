package main

import (
	"context"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/OpenCommunityEdition/opence-master-server/internal/sign"
)

func TestStateIdentityPreservesNativeAndMasterKey(t *testing.T) {
	root := t.TempDir()
	native := filepath.Join(root, "native.db")
	original := []byte("untouched native state")
	if err := os.WriteFile(native, original, 0600); err != nil {
		t.Fatal(err)
	}
	if err := bindState(native, "0011223344556677"); err == nil {
		t.Fatal("accepted unmarked existing DB")
	}
	got, _ := os.ReadFile(native)
	if string(got) != string(original) {
		t.Fatal("native DB changed")
	}
	dce := filepath.Join(root, "dce.db")
	if err := bindState(dce, "0011223344556677"); err != nil {
		t.Fatal(err)
	}
	if err := bindState(dce, "0011223344556677"); err != nil {
		t.Fatal(err)
	}
	if err := bindState(dce, "8899aabbccddeeff"); err == nil {
		t.Fatal("silent master key replacement")
	}
	if err := bindState(":memory:", "0011223344556677"); err == nil {
		t.Fatal("nondurable state accepted")
	}
}

func TestApprovalFileOnlyPublicKeyAndOperatorIPv4(t *testing.T) {
	seed := make([]byte, 32)
	seed[0] = 7
	public := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	path := filepath.Join(t.TempDir(), "approvals.json")
	for _, test := range []struct {
		body string
		good bool
	}{
		{`[{"public_key":"` + sign.PublicKeyText(public) + `","candidate_ip":"192.168.42.2"}]`, true},
		{`[{"public_key":"` + sign.PublicKeyText(public) + `","candidate_ip":"evil.example"}]`, false},
		{`[{"public_key":"` + sign.PublicKeyText(public) + `","private_key":"secret"}]`, false},
		{`[{"public_key":"` + sign.PublicKeyText(public) + `"},{"public_key":"` + sign.PublicKeyText(public) + `"}]`, false},
		{`[] {}`, false},
	} {
		if err := os.WriteFile(path, []byte(test.body), 0600); err != nil {
			t.Fatal(err)
		}
		keys, _, err := approvals(path)
		if (err == nil) != test.good {
			t.Fatalf("approval parse good=%v err=%v", test.good, err)
		}
		if test.good && len(keys) != 1 {
			t.Fatal("approved key missing")
		}
	}
}

func TestCommandRequiresSeparateFiles(t *testing.T) {
	if err := run(context.Background(), nil); err == nil {
		t.Fatal("missing state accepted")
	}
	if err := run(context.Background(), []string{"--key", strings.Repeat("1", 64), "--db", "unused", "--approvals", "unused"}); err == nil {
		t.Fatal("literal private seed accepted as CLI key")
	}
}
