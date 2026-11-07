package dcedirectory

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

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
	h := newHarness(t, nil)
	file := emptyApprovals(t)
	for n := 1; n <= MaxPublicApprovals; n++ {
		if _, err := h.s.enroll(file, keyFromByte(n), netip.Addr{}, true); err != nil {
			t.Fatal(n, err)
		}
	}
	if _, err := h.s.enroll(file, keyFromByte(MaxPublicApprovals+1), netip.Addr{}, true); err != errPublicCapacity {
		t.Fatal("public cap", err)
	}
	// A key already in stays approved; an operator still gets in.
	if created, err := h.s.enroll(file, keyFromByte(1), netip.Addr{}, true); err != nil || created {
		t.Fatal("repeat", created, err)
	}
	if created, err := h.s.enroll(file, keyFromByte(MaxPublicApprovals+2), netip.Addr{}, false); err != nil || !created {
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
	// Enough public keys that PerKeyServers is not what stops them.
	keys := make([]ed25519.PrivateKey, MaxPublicRecords/PerKeyServers+1)
	h := newHarness(t, func(c *Config) {
		c.PublicKeys = map[string]bool{}
		for n := range keys {
			keys[n] = testKey(byte(0x40 + n))
			public := keys[n].Public().(ed25519.PublicKey)
			c.Approved = append(c.Approved, public)
			c.PublicKeys[sign.KeyID(public)] = true
		}
	})
	put := func(key ed25519.PrivateKey, n int) int {
		advert := h.advert()
		advert.Instance = fmt.Sprintf("%016x", n)
		body, _ := json.Marshal(advert)
		id := sign.ServerID(sign.KeyID(key.Public().(ed25519.PublicKey)), advert.Instance)
		h.now = h.now.Add(time.Second)
		advert.Time = h.now.Unix()
		body, _ = json.Marshal(advert)
		return h.do(h.request("PUT", ListPath+"/"+id, body, key)).Code
	}
	for n := 0; n < MaxPublicRecords; n++ {
		if code := put(keys[n/PerKeyServers], n); code != 202 {
			t.Fatal("public publish", n, code)
		}
	}
	if code := put(keys[len(keys)-1], MaxPublicRecords); code != 429 {
		t.Fatal("public pool not enforced", code)
	}
	if code := put(h.host, 1000); code != 202 {
		t.Fatal("operator refused", code)
	}
}

func (s *Server) enrollOperatorForTest(file *ApprovalFile, public ed25519.PublicKey, candidate netip.Addr) (bool, error) {
	return s.enroll(file, public, candidate, false)
}
