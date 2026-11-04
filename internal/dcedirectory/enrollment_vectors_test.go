package dcedirectory

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/OpenCommunityEdition/opence-master-server/internal/sign"
)

var updateEnrollmentVectors = flag.Bool("update-enrollment-vectors", false, "rewrite synthetic enrollment interoperability fixture")

func TestEnrollmentVectorsFile(t *testing.T) {
	h := newHarness(t, nil)
	public := sign.PublicKeyText(h.host.Public().(ed25519.PublicKey))
	c := EnrollmentChallenge{1, h.s.keyID, sign.KeyID(h.host.Public().(ed25519.PublicKey)), public,
		"000102030405060708090a0b0c0d0e0f", testTime.Add(EnrollmentTTL).Unix(), testTime.Unix(), strings.Repeat("a", 64)}
	message := EnrollmentMessage(c)
	signature := ed25519.Sign(h.host, message)
	challengeResponse := httptest.NewRecorder()
	h.s.signed(challengeResponse, 200, c, testTime)
	registered := httptest.NewRecorder()
	h.s.signed(registered, 200, EnrollmentResult{true, h.s.keyID, c.KeyID, c.PublicKey, true, true, testTime.Unix()}, testTime)
	value := map[string]any{"notice": "SYNTHETIC KNOWN TEST SEED. Never provision in browser, VMU or service.",
		"host_seed_hex": hex.EncodeToString(h.host.Seed()), "host_public": public, "master_public": sign.PublicKeyText(h.master.Public().(ed25519.PublicKey)),
		"canonical_utf8": string(message), "canonical_hex": hex.EncodeToString(message), "signature": base64.StdEncoding.EncodeToString(signature),
		"challenge_response": fixtureResponse(challengeResponse), "register_response": fixtureResponse(registered)}
	made, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	made = append(made, '\n')
	path := "../../testdata/dce_enrollment_vectors.json"
	if *updateEnrollmentVectors {
		if err := os.WriteFile(path, made, 0644); err != nil {
			t.Fatal(err)
		}
	}
	stored, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stored, made) {
		t.Fatal("enrollment fixture changed; coordinate canonical contract before regeneration")
	}
}
