package dcedirectory

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/OpenCommunityEdition/opence-master-server/internal/sign"
)

func keyFromByte(n int) ed25519.PublicKey {
	seed := make([]byte, ed25519.SeedSize)
	seed[0], seed[1] = byte(n), byte(n>>8)
	return ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
}

func emptyApprovals(t *testing.T) *ApprovalFile {
	t.Helper()
	path := filepath.Join(t.TempDir(), "approved.json")
	if err := os.WriteFile(path, []byte("[]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return &ApprovalFile{Path: path}
}

func TestPublicApprovalCapKeepsOperatorSlots(t *testing.T) {
	h := newHarness(t)
	file := emptyApprovals(t)
	for n := 1; n <= MaxPublicApprovals; n++ {
		if _, err := h.s.enroll(file, keyFromByte(n), netipNone, true); err != nil {
			t.Fatal(n, err)
		}
	}
	if _, err := h.s.enroll(file, keyFromByte(MaxPublicApprovals+1), netipNone, true); err != errPublicCapacity {
		t.Fatal("public cap", err)
	}
	// A key already in stays approved; an operator still gets in.
	if created, err := h.s.enroll(file, keyFromByte(1), netipNone, true); err != nil || created {
		t.Fatal("repeat", created, err)
	}
	if created, err := h.s.enroll(file, keyFromByte(MaxPublicApprovals+2), netipNone, false); err != nil || !created {
		t.Fatal("operator refused", err)
	}
	entries, err := ReadApprovalFile(file.Path)
	if err != nil {
		t.Fatal(err)
	}
	public := 0
	for _, entry := range entries {
		if entry.Public {
			public++
		}
	}
	if public != MaxPublicApprovals || len(entries) != MaxPublicApprovals+1 {
		t.Fatal("stored classes", public, len(entries))
	}
}

func TestOldApprovalFilesReadAsOperatorKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "approved.json")
	text, _ := json.Marshal([]map[string]string{{"public_key": sign.PublicKeyText(keyFromByte(1))}})
	if err := os.WriteFile(path, text, 0o600); err != nil {
		t.Fatal(err)
	}
	entries, err := ReadApprovalFile(path)
	if err != nil || len(entries) != 1 || entries[0].Public {
		t.Fatal(entries, err)
	}
}

func TestEnrollmentClassHeader(t *testing.T) {
	h, e, path := enrollmentHarness(t)
	c := getChallenge(t, h, e, testEnrollmentSession)
	bad := enrollmentRequest("register", testEnrollmentSession, registration(c, h.host))
	bad.Header.Set(EnrollmentClassHeader, "root")
	if w := enrollDo(e, bad); w.Code != 400 {
		t.Fatal("bad class", w.Code)
	}
	good := enrollmentRequest("register", testEnrollmentSession, registration(c, h.host))
	good.Header.Set(EnrollmentClassHeader, "public")
	if w := enrollDo(e, good); w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	entries, err := ReadApprovalFile(path)
	if err != nil || len(entries) != 1 || !entries[0].Public {
		t.Fatal("not stored as public", entries, err)
	}
	if !h.s.publicKeys[sign.KeyID(h.host.Public().(ed25519.PublicKey))] {
		t.Fatal("not live as public")
	}
}

func TestPublicRecordsStopAtTheirPoolAndOperatorsStillPublish(t *testing.T) {
	h, publishPublic, publishOperator := publicRecordHarness(t)
	for n := 0; n < MaxPublicRecords; n++ {
		if code := publishPublic(n); code != 202 {
			t.Fatal("public publish", n, code)
		}
	}
	if code := publishPublic(MaxPublicRecords); code != 429 {
		t.Fatal("public pool not enforced", code)
	}
	if code := publishOperator(); code != 202 {
		t.Fatal("operator refused", code)
	}
	_ = h
}
