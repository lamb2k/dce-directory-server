package dcedirectory

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/OpenCommunityEdition/opence-master-server/internal/limit"
	"github.com/OpenCommunityEdition/opence-master-server/internal/sign"
)

const EnrollmentDomain = "DCE-Device-Enrollment-v1"
const EnrollmentTTL = 60 * time.Second
const EnrollmentPath = "/v1/dce/enrollment/"

type EnrollmentConfig struct {
	Token       string
	Approvals   *ApprovalFile
	CandidateIP netip.Addr // operator configuration only
}

type EnrollmentChallenge struct {
	Protocol       int    `json:"protocol"`
	MasterKeyID    string `json:"masterKeyId"`
	KeyID          string `json:"keyId"`
	PublicKey      string `json:"publicKey"`
	Challenge      string `json:"challenge"`
	Expires        int64  `json:"expires"`
	ServerTime     int64  `json:"serverTime"`
	SessionBinding string `json:"sessionBinding"`
}

type EnrollmentResult struct {
	OK          bool   `json:"ok"`
	MasterKeyID string `json:"masterKeyId"`
	KeyID       string `json:"keyId"`
	PublicKey   string `json:"publicKey"`
	Approved    bool   `json:"approved"`
	Created     bool   `json:"created"`
	ServerTime  int64  `json:"serverTime"`
}

type enrollmentPending struct {
	challenge EnrollmentChallenge
	public    ed25519.PublicKey
	result    *EnrollmentResult
	proofHash [32]byte
	attempts  int
}

type Enrollment struct {
	mu                                                         sync.Mutex
	server                                                     *Server
	tokenHash                                                  [32]byte
	file                                                       *ApprovalFile
	candidate                                                  netip.Addr
	pending                                                    map[string]*enrollmentPending
	challenges, registrations, allChallenges, allRegistrations *limit.Limiter
}

func lowerHex(value string, bytes int) bool {
	if len(value) != bytes*2 {
		return false
	}
	for _, c := range value {
		if !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func ValidateEnrollmentListen(address string) (netip.AddrPort, error) {
	parsed, err := netip.ParseAddrPort(address)
	if err != nil || !parsed.Addr().IsLoopback() || parsed.Addr().Zone() != "" {
		return netip.AddrPort{}, errors.New("enrollment listener must be a literal loopback IP and port")
	}
	return parsed, nil
}

func NewEnrollment(server *Server, config EnrollmentConfig) (*Enrollment, error) {
	if len(config.Token) < 64 || len(config.Token) > 128 || len(config.Token)%2 != 0 || !lowerHex(config.Token, len(config.Token)/2) {
		return nil, errors.New("enrollment token file must hold 32..64 random bytes as lowercase hex")
	}
	if config.Approvals == nil || config.Approvals.Path == "" {
		return nil, errors.New("enrollment approval file required")
	}
	if config.CandidateIP.IsValid() && !server.allowedEndpoint(config.CandidateIP) {
		return nil, errors.New("enrollment candidate violates endpoint policy")
	}
	if _, err := ReadApprovalFile(config.Approvals.Path); err != nil {
		return nil, errors.New("cannot read enrollment approval file")
	}
	e := &Enrollment{server: server, tokenHash: sha256.Sum256([]byte(config.Token)), file: config.Approvals,
		candidate: config.CandidateIP, pending: map[string]*enrollmentPending{}}
	e.challenges = limit.PerMinute(5, server.now)
	e.registrations = limit.PerMinute(10, server.now)
	e.allChallenges = limit.PerMinute(120, server.now)
	e.allRegistrations = limit.PerMinute(240, server.now)
	e.challenges.Maximum = 64
	e.registrations.Maximum = 64
	return e, nil
}

func EnrollmentMessage(challenge EnrollmentChallenge) []byte {
	return []byte(strings.Join([]string{EnrollmentDomain, challenge.MasterKeyID, challenge.PublicKey,
		challenge.Challenge, strconv.FormatInt(challenge.Expires, 10), challenge.SessionBinding}, "\n"))
}

func enrollmentFields(data []byte, names ...string) (map[string]string, error) {
	d := json.NewDecoder(bytes.NewReader(data))
	start, err := d.Token()
	if err != nil || start != json.Delim('{') {
		return nil, errors.New("object required")
	}
	allowed := map[string]bool{}
	for _, name := range names {
		allowed[name] = true
	}
	values := map[string]string{}
	for d.More() {
		field, err := d.Token()
		if err != nil {
			return nil, err
		}
		name, ok := field.(string)
		if !ok || !allowed[name] {
			return nil, errors.New("unknown field")
		}
		if _, exists := values[name]; exists {
			return nil, errors.New("duplicate field")
		}
		var value string
		if err := d.Decode(&value); err != nil || value == "" {
			return nil, errors.New("string required")
		}
		values[name] = value
	}
	if _, err := d.Token(); err != nil {
		return nil, err
	}
	if err := d.Decode(new(any)); err != io.EOF || len(values) != len(names) {
		return nil, errors.New("missing or trailing fields")
	}
	return values, nil
}

func (e *Enrollment) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	ip, parseErr := netip.ParseAddr(host)
	if err != nil || parseErr != nil || !ip.IsLoopback() {
		e.server.fail(w, 403, "loopback_only")
		return
	}
	auth := r.Header.Get("Authorization")
	if len(auth) > 256 || !strings.HasPrefix(auth, "Bearer ") {
		e.server.fail(w, 401, "operator_auth")
		return
	}
	provided := sha256.Sum256([]byte(strings.TrimPrefix(auth, "Bearer ")))
	if subtle.ConstantTimeCompare(provided[:], e.tokenHash[:]) != 1 {
		e.server.fail(w, 401, "operator_auth")
		return
	}
	if r.Method != "POST" || r.URL.RawQuery != "" || r.URL.RawPath != "" {
		e.server.fail(w, 400, "request")
		return
	}
	challengeRequest := r.URL.Path == EnrollmentPath+"challenge"
	if !challengeRequest && r.URL.Path != EnrollmentPath+"register" {
		e.server.fail(w, 404, "not_found")
		return
	}
	session := r.Header.Get("X-DCE-Enrollment-Session")
	if !lowerHex(session, 32) {
		e.server.fail(w, 400, "session_binding")
		return
	}
	perSession, global := e.registrations, e.allRegistrations
	if challengeRequest {
		perSession, global = e.challenges, e.allChallenges
	}
	if ok, _ := global.Allow("all"); !ok {
		e.server.fail(w, 429, "rate")
		return
	}
	if ok, _ := perSession.Allow(session); !ok {
		e.server.fail(w, 429, "rate")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 512))
	if err != nil {
		e.server.fail(w, 413, "body_size")
		return
	}
	names := []string{"publicKey"}
	if !challengeRequest {
		names = append(names, "challenge", "signature")
	}
	fields, err := enrollmentFields(body, names...)
	if err != nil {
		e.server.fail(w, 400, "fields")
		return
	}
	public, err := sign.ParsePublicKey(fields["publicKey"])
	if err != nil || sign.PublicKeyText(public) != fields["publicKey"] {
		e.server.fail(w, 400, "public_key")
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.server.now()
	for id, p := range e.pending {
		if p.challenge.Expires <= now.Unix() {
			delete(e.pending, id)
		}
	}
	if challengeRequest {
		if e.pending[session] == nil && len(e.pending) >= 64 {
			e.server.fail(w, 429, "capacity")
			return
		}
		var nonce [16]byte
		if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
			e.server.fail(w, 500, "random")
			return
		}
		c := EnrollmentChallenge{1, e.server.keyID, sign.KeyID(public), fields["publicKey"], hex.EncodeToString(nonce[:]), now.Add(EnrollmentTTL).Unix(), now.Unix(), session}
		e.pending[session] = &enrollmentPending{challenge: c, public: public}
		e.server.signed(w, 200, c, now)
		return
	}
	p := e.pending[session]
	if p == nil || p.challenge.Challenge != fields["challenge"] || p.challenge.PublicKey != fields["publicKey"] {
		e.server.fail(w, 409, "challenge")
		return
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(fields["signature"])
	if err != nil || len(signature) != 64 || base64.StdEncoding.EncodeToString(signature) != fields["signature"] {
		e.server.fail(w, 400, "proof")
		return
	}
	proofHash := sha256.Sum256(signature)
	if p.result != nil {
		if proofHash != p.proofHash {
			e.server.fail(w, 409, "consumed")
			return
		}
		result := *p.result
		result.ServerTime = now.Unix()
		e.server.signed(w, 200, result, now)
		return
	}
	if !ed25519.Verify(public, EnrollmentMessage(p.challenge), signature) {
		p.attempts++
		if p.attempts >= 3 {
			delete(e.pending, session)
		}
		e.server.fail(w, 401, "proof")
		return
	}
	created, err := e.server.enroll(e.file, public, e.candidate)
	if err != nil {
		e.server.fail(w, 503, "approval_not_committed")
		return
	}
	p.result = &EnrollmentResult{true, e.server.keyID, sign.KeyID(public), fields["publicKey"], true, created, now.Unix()}
	p.proofHash = proofHash
	e.server.signed(w, 200, p.result, now)
}
