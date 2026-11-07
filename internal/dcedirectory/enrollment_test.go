package dcedirectory

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/OpenCommunityEdition/opence-master-server/internal/sign"
)

const testOperatorToken = "abababababababababababababababababababababababababababababababab"
const testEnrollmentSession = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

func enrollmentHarness(t *testing.T) (*harness, *Enrollment, string) {
	h := newHarness(t, func(c *Config) { c.Approved = nil })
	path := filepath.Join(t.TempDir(), "approved.json")
	if err := os.WriteFile(path, []byte("[]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	e, err := NewEnrollment(h.s, EnrollmentConfig{Token: testOperatorToken, Approvals: &ApprovalFile{Path: path}})
	if err != nil {
		t.Fatal(err)
	}
	return h, e, path
}

func enrollmentRequest(path, session string, value any) *http.Request {
	body, _ := json.Marshal(value)
	r := httptest.NewRequest("POST", EnrollmentPath+path, bytes.NewReader(body))
	r.RemoteAddr = "127.0.0.1:40000"
	r.Header.Set("Authorization", "Bearer "+testOperatorToken)
	r.Header.Set("X-DCE-Enrollment-Session", session)
	return r
}

func enrollDo(e *Enrollment, r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	e.ServeHTTP(w, r)
	return w
}

func getChallenge(t *testing.T, h *harness, e *Enrollment, session string) EnrollmentChallenge {
	t.Helper()
	w := enrollDo(e, enrollmentRequest("challenge", session, map[string]string{"publicKey": sign.PublicKeyText(h.host.Public().(ed25519.PublicKey))}))
	if w.Code != 200 {
		t.Fatalf("challenge%d %s", w.Code, w.Body)
	}
	var c EnrollmentChallenge
	if err := json.Unmarshal(w.Body.Bytes(), &c); err != nil {
		t.Fatal(err)
	}
	if c.ServerTime != h.now.Unix() || c.Expires-c.ServerTime != 60 || c.MasterKeyID != h.s.keyID || c.SessionBinding != session {
		t.Fatal("challenge context")
	}
	if !sign.VerifyBody(h.master.Public().(ed25519.PublicKey), w.Header().Get("Signature"), w.Body.Bytes()) {
		t.Fatal("challenge signature")
	}
	return c
}

func registration(c EnrollmentChallenge, private ed25519.PrivateKey) map[string]string {
	return map[string]string{"publicKey": c.PublicKey, "challenge": c.Challenge, "signature": base64.StdEncoding.EncodeToString(ed25519.Sign(private, EnrollmentMessage(c)))}
}

func TestEnrollmentPersistsActivatesAndSurvivesNewCookie(t *testing.T) {
	h, e, path := enrollmentHarness(t)
	if _, _, w := h.publish(h.advert()); w.Code != 403 {
		t.Fatal("key already approved")
	}
	c := getChallenge(t, h, e, testEnrollmentSession)
	body := registration(c, h.host)
	w := enrollDo(e, enrollmentRequest("register", testEnrollmentSession, body))
	if w.Code != 200 {
		t.Fatal(w.Body)
	}
	var result EnrollmentResult
	json.Unmarshal(w.Body.Bytes(), &result)
	if !result.Approved || !result.Created || result.MasterKeyID != h.s.keyID {
		t.Fatal("approval result")
	}
	stored, err := ReadApprovalFile(path)
	if err != nil || len(stored) != 1 || stored[0].PublicKey != c.PublicKey {
		t.Fatal("durable approval")
	}
	if _, _, w := h.publish(h.advert()); w.Code != 202 {
		t.Fatalf("live approval without restart%d", w.Code)
	}
	before, _ := os.ReadFile(path)
	w = enrollDo(e, enrollmentRequest("register", testEnrollmentSession, body))
	if w.Code != 200 {
		t.Fatal("lost-response retry failed")
	}
	h.now = h.now.Add(time.Second)
	w = enrollDo(e, enrollmentRequest("register", testEnrollmentSession, body))
	var retry EnrollmentResult
	json.Unmarshal(w.Body.Bytes(), &retry)
	if w.Code != 200 || fmt.Sprint(retry.ServerTime) != w.Header().Get("Signature-Time") || retry.ServerTime != h.now.Unix() {
		t.Fatal("retry UTC differs from signed header")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("retry rewrote approval")
	}
	newCookie := strings.Repeat("d", 64)
	if w := enrollDo(e, enrollmentRequest("register", newCookie, body)); w.Code != 409 {
		t.Fatal("old session proof crossed cookie")
	}
	c = getChallenge(t, h, e, newCookie)
	w = enrollDo(e, enrollmentRequest("register", newCookie, registration(c, h.host)))
	json.Unmarshal(w.Body.Bytes(), &result)
	if w.Code != 200 || result.Created || !result.Approved {
		t.Fatal("same device with new cookie not idempotent")
	}
	stored, _ = ReadApprovalFile(path)
	if len(stored) != 1 {
		t.Fatal("duplicate key saved")
	}
	// A recreated server can load the same persisted key; no challenge metadata is persisted.
	public, _ := sign.ParsePublicKey(stored[0].PublicKey)
	if !bytes.Equal(public, h.host.Public().(ed25519.PublicKey)) {
		t.Fatal("restart public key mismatch")
	}
	if bytes.Contains(after, []byte(c.Challenge)) || bytes.Contains(after, []byte(testEnrollmentSession)) || bytes.Contains(after, []byte(testOperatorToken)) {
		t.Fatal("transient context or credential persisted")
	}
}

func TestEnrollmentRefusesAuthProofPrivateFieldsAndPublicRoute(t *testing.T) {
	h, e, path := enrollmentHarness(t)
	pub := sign.PublicKeyText(h.host.Public().(ed25519.PublicKey))
	r := enrollmentRequest("challenge", testEnrollmentSession, map[string]string{"publicKey": pub})
	r.Header.Del("Authorization")
	if w := enrollDo(e, r); w.Code != 401 {
		t.Fatal("unauthenticated enrollment")
	}
	r = enrollmentRequest("challenge", testEnrollmentSession, map[string]string{"publicKey": pub})
	r.RemoteAddr = "8.8.8.8:1234"
	r.Header.Set("X-Forwarded-For", "127.0.0.1")
	if w := enrollDo(e, r); w.Code != 403 {
		t.Fatal("nonloopback enrollment")
	}
	for _, extra := range []string{"privateKey", "seed", "candidate_ip", "PublicKey"} {
		r = enrollmentRequest("challenge", testEnrollmentSession, map[string]string{"publicKey": pub, extra: "forbidden"})
		if w := enrollDo(e, r); w.Code != 400 {
			t.Fatalf("accepted%s", extra)
		}
	}
	// Public registry must never route the private control plane.
	r = enrollmentRequest("challenge", testEnrollmentSession, map[string]string{"publicKey": pub})
	w := httptest.NewRecorder()
	h.s.ServeHTTP(w, r)
	if w.Code != 404 {
		t.Fatal("public enrollment route exposed")
	}
	h.now = h.now.Add(time.Minute)
	c := getChallenge(t, h, e, testEnrollmentSession)
	if w := enrollDo(e, enrollmentRequest("register", testEnrollmentSession, registration(c, h.other))); w.Code != 401 {
		t.Fatal("wrong key proof")
	}
	h.now = h.now.Add(EnrollmentTTL)
	if w := enrollDo(e, enrollmentRequest("register", testEnrollmentSession, registration(c, h.host))); w.Code != 409 {
		t.Fatal("expired proof")
	}
	stored, _ := ReadApprovalFile(path)
	if len(stored) != 0 {
		t.Fatal("failed proof approved")
	}
}

func TestEnrollmentPersistenceFailureAndCollisionFailClosed(t *testing.T) {
	h, e, path := enrollmentHarness(t)
	c := getChallenge(t, h, e, testEnrollmentSession)
	lockPath := path + ".enrollment-lock"
	os.WriteFile(lockPath, []byte("owned test lock"), 0600)
	w := enrollDo(e, enrollmentRequest("register", testEnrollmentSession, registration(c, h.host)))
	if w.Code != 503 || len(h.s.approved) != 0 {
		t.Fatal("failed persistence activated key")
	}
	os.Remove(lockPath)
	id := sign.KeyID(h.host.Public().(ed25519.PublicKey))
	h.s.approved[id] = h.other.Public().(ed25519.PublicKey)
	w = enrollDo(e, enrollmentRequest("register", testEnrollmentSession, registration(c, h.host)))
	if w.Code != 503 {
		t.Fatal("key-id collision accepted")
	}
	stored, _ := ReadApprovalFile(path)
	if len(stored) != 0 {
		t.Fatal("collision persisted")
	}
}

func TestConcurrentApprovalWritesPreserveAllKeys(t *testing.T) {
	h, _, path := enrollmentHarness(t)
	file := &ApprovalFile{Path: path}
	var group sync.WaitGroup
	errorsCh := make(chan error, 20)
	for i := 1; i <= 20; i++ {
		group.Add(1)
		go func(n int) {
			defer group.Done()
			public := testKey(byte(n)).Public().(ed25519.PublicKey)
			_, err := h.s.enrollOperatorForTest(file, public, netip.Addr{})
			errorsCh <- err
		}(i)
	}
	group.Wait()
	close(errorsCh)
	for err := range errorsCh {
		if err != nil {
			t.Fatal(err)
		}
	}
	stored, err := ReadApprovalFile(path)
	if err != nil || len(stored) != 20 || len(h.s.approved) != 20 {
		t.Fatal("concurrent approval update lost records")
	}
}

func TestEnrollmentListenerAndCapacity(t *testing.T) {
	for _, address := range []string{"0.0.0.0:18097", "[::]:18097", "localhost:18097", "192.168.1.2:18097", "127.0.0.1", "127.0.0.1:65536"} {
		if _, err := ValidateEnrollmentListen(address); err == nil {
			t.Fatalf("accepted listener%s", address)
		}
	}
	for _, address := range []string{"127.0.0.1:18097", "[::1]:18097"} {
		if _, err := ValidateEnrollmentListen(address); err != nil {
			t.Fatal(err)
		}
	}
	h, e, _ := enrollmentHarness(t)
	for i := 0; i < 64; i++ {
		getChallenge(t, h, e, fmt.Sprintf("%064x", i))
	}
	w := enrollDo(e, enrollmentRequest("challenge", strings.Repeat("f", 64), map[string]string{"publicKey": sign.PublicKeyText(h.host.Public().(ed25519.PublicKey))}))
	if w.Code != 429 {
		t.Fatal("pending capacity unbounded")
	}
}

func TestEnrollmentApprovalCapacityAndOperatorCandidate(t *testing.T) {
	h, e, path := enrollmentHarness(t)
	entries := make([]Approval, MaxApprovedKeys)
	for i := range entries {
		seed := make([]byte, 32)
		binary.LittleEndian.PutUint32(seed, uint32(i))
		entries[i].PublicKey = sign.PublicKeyText(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))
	}
	data, _ := json.Marshal(entries)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	c := getChallenge(t, h, e, testEnrollmentSession)
	w := enrollDo(e, enrollmentRequest("register", testEnrollmentSession, registration(c, h.host)))
	if w.Code != 503 || len(h.s.approved) != 0 {
		t.Fatal("full durable approval file accepted new key")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(data, after) {
		t.Fatal("full file changed")
	}

	h, _, path = enrollmentHarness(t)
	e, err := NewEnrollment(h.s, EnrollmentConfig{Token: testOperatorToken, Approvals: &ApprovalFile{Path: path}, CandidateIP: netip.MustParseAddr("8.8.8.8")})
	if err != nil {
		t.Fatal(err)
	}
	c = getChallenge(t, h, e, testEnrollmentSession)
	w = enrollDo(e, enrollmentRequest("register", testEnrollmentSession, registration(c, h.host)))
	if w.Code != 200 {
		t.Fatal(w.Body)
	}
	stored, _ := ReadApprovalFile(path)
	if len(stored) != 1 || stored[0].CandidateIP != "8.8.8.8" {
		t.Fatal("operator candidate not persisted")
	}
	if h.s.candidateOverrides[c.KeyID].String() != "8.8.8.8" {
		t.Fatal("operator candidate not activated")
	}
}

func FuzzEnrollmentFields(f *testing.F) {
	f.Add([]byte(`{"publicKey":"ed25519:test"}`))
	f.Add([]byte(`{"publicKey":null}`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 512 {
			t.Skip()
		}
		_, _ = enrollmentFields(data, "publicKey")
		_, _ = enrollmentFields(data, "publicKey", "challenge", "signature")
	})
}
