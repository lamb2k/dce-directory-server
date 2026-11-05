// Package dcedirectory advertises DCE_NET3 endpoints proved by their game UDP
// socket. It does not implement or translate native OpenCE game listings.
package dcedirectory

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/OpenCommunityEdition/opence-master-server/internal/httpx"
	"github.com/OpenCommunityEdition/opence-master-server/internal/limit"
	"github.com/OpenCommunityEdition/opence-master-server/internal/sign"
)

const (
	Protocol       = 1
	Family         = "dce-net"
	NetworkVersion = 4
	MinPlayers     = 2
	MaxPlayers     = 8
	MaxFlags       = 3
	ListPath       = "/v1/dce/servers"
	TTL            = 90 * time.Second
	TicketTTL      = 30 * time.Second
	MaxBody        = 2048
	MaxServers     = 64
	PerKeyServers  = 4
)

// Nonces is implemented by upstream store.Store. Production uses a separate
// durable database; a restart must not reset signed-request replay protection.
type Nonces interface {
	UseNonce(string, string, time.Duration) (bool, error)
}

type Config struct {
	Key                ed25519.PrivateKey
	Approved           []ed25519.PublicKey
	Nonces             Nonces
	CandidateOverrides map[string]netip.Addr
	Relay              *RelayConfig
	Clients            httpx.Clients
	AllowLoopback      bool
	AllowPrivateLAN    []netip.Prefix
	Now                func() time.Time
	Random             io.Reader
	Diagnostics        *PublishDiagnostics
}

// Advertisement contains host claims, authenticated by its signed PUT. It has
// no endpoint: the directory learns that only from the UDP proof.
type Advertisement struct {
	Protocol       int    `json:"protocol"`
	Family         string `json:"family"`
	NetworkVersion int    `json:"network_version"`
	Build          uint32 `json:"build"`
	Map            uint8  `json:"map"`
	MapCRC         uint32 `json:"map_crc"`
	Mode           uint8  `json:"mode"`
	Score          uint8  `json:"score"`
	Players        uint8  `json:"players"`
	Capacity       uint8  `json:"capacity"`
	// Flags: bit 0 dial-up limits apply, bit 1 vehicles on (the game's net_limits.h).
	Flags uint8 `json:"flags"`
	Name           string `json:"name"`
	Sequence       uint32 `json:"sequence"`
	Time           int64  `json:"time"`
	Instance       string `json:"instance"`
	GamePort       uint16 `json:"game_port"`
	// Relay 1 asks for a grant; only images whose reply parser knows the field send it. Catalog version stays.
	Relay uint8 `json:"relay,omitempty"`
}

type Master struct {
	KeyID string `json:"key_id"`
	Time  int64  `json:"time"`
}

type Endpoint struct {
	IP   string `json:"ip"`
	Port uint16 `json:"port"`
}

type Entry struct {
	ID    string `json:"id"`
	KeyID string `json:"key_id"`
	Advertisement
	Endpoint  Endpoint `json:"endpoint"`
	Updated   int64    `json:"updated"`
	Expires   int64    `json:"expires"`
	Reachable bool     `json:"reachable"`
}

type List struct {
	Protocol       int     `json:"protocol"`
	Family         string  `json:"family"`
	NetworkVersion int     `json:"network_version"`
	Master         Master  `json:"master"`
	TTL            int     `json:"ttl"`
	Truncated      bool    `json:"truncated"`
	Servers        []Entry `json:"servers"`
}

type Challenge struct {
	Protocol int    `json:"protocol"`
	Family   string `json:"family"`
	ID       string `json:"id"`
	Master   Master `json:"master"`
	Ticket   string `json:"ticket"`
	Expires  int64  `json:"expires"`
	Interval int    `json:"interval"`
	TTL      int    `json:"ttl"`
	// Present only for network versions that understand it: older parsers refuse unknown fields.
	Relay *RelayGrant `json:"relay,omitempty"`
}

type record struct {
	keyID         string
	advert        Advertisement
	lastPut       time.Time
	verified      *Entry
	ticket        [16]byte
	ticketExpires time.Time
	source        netip.AddrPort
	nonce         [32]byte
	challenge     []byte
	replies       int
	lastReply     time.Time
}

type Server struct {
	mu                                                                               sync.Mutex
	key                                                                              ed25519.PrivateKey
	keyID                                                                            string
	keyIDRaw                                                                         [8]byte
	approved                                                                         map[string]ed25519.PublicKey
	nonces                                                                           Nonces
	candidateOverrides                                                               map[string]netip.Addr
	relay                                                                            *RelayConfig
	clients                                                                          httpx.Clients
	allowLoopback                                                                    bool
	allowPrivateLAN                                                                  []netip.Prefix
	now                                                                              func() time.Time
	random                                                                           io.Reader
	diagnostics                                                                      *PublishDiagnostics
	records                                                                          map[string]*record
	tickets                                                                          map[[16]byte]string
	reads, writes, publishers, udpSources, udpKeys, udpGlobal, ackSources, ackGlobal *limit.Limiter
}

func New(config Config) (*Server, error) {
	if len(config.Key) != ed25519.PrivateKeySize || config.Nonces == nil {
		return nil, errors.New("a master key and durable nonce store are required")
	}
	for _, prefix := range config.AllowPrivateLAN {
		if !validPrivatePrefix(prefix) {
			return nil, errors.New("LAN exceptions must be bounded RFC1918 IPv4 subnets")
		}
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Random == nil {
		config.Random = rand.Reader
	}
	s := &Server{key: append(ed25519.PrivateKey(nil), config.Key...), approved: map[string]ed25519.PublicKey{},
		nonces: config.Nonces, relay: config.Relay, candidateOverrides: map[string]netip.Addr{}, clients: config.Clients,
		allowLoopback: config.AllowLoopback, allowPrivateLAN: append([]netip.Prefix(nil), config.AllowPrivateLAN...),
		now: config.Now, random: config.Random, diagnostics: config.Diagnostics, records: map[string]*record{}, tickets: map[[16]byte]string{}}
	s.keyID = sign.KeyID(s.key.Public().(ed25519.PublicKey))
	raw, _ := hex.DecodeString(s.keyID)
	copy(s.keyIDRaw[:], raw)
	for _, public := range config.Approved {
		if len(public) != ed25519.PublicKeySize || sign.SmallOrder(public) {
			return nil, errors.New("an approved public key is invalid")
		}
		id := sign.KeyID(public)
		if old := s.approved[id]; old != nil && !bytes.Equal(old, public) {
			return nil, errors.New("key id collision")
		}
		s.approved[id] = append(ed25519.PublicKey(nil), public...)
	}
	if len(s.approved) > MaxApprovedKeys {
		return nil, errors.New("approval capacity")
	}
	for keyID, address := range config.CandidateOverrides {
		if s.approved[keyID] == nil || !s.allowedEndpoint(address) {
			return nil, errors.New("candidate overrides require an approved key and allowed IPv4")
		}
		s.candidateOverrides[keyID] = address.Unmap()
	}
	s.reads = limit.PerMinute(60, s.now)
	s.writes = limit.PerMinute(60, s.now)
	s.publishers = limit.New(4, 5*time.Second, s.now)
	s.udpSources = limit.New(8, time.Second, s.now)
	s.udpKeys = limit.New(8, time.Second, s.now)
	s.udpGlobal = limit.New(64, time.Second/64, s.now)
	s.ackSources = limit.New(8, time.Second, s.now)
	s.ackGlobal = limit.New(128, time.Second/128, s.now)
	for _, limiter := range []*limit.Limiter{s.reads, s.writes, s.publishers, s.udpSources, s.udpKeys, s.ackSources} {
		limiter.Maximum = 4096
	}
	return s, nil
}

func validPrivatePrefix(p netip.Prefix) bool {
	if !p.IsValid() || !p.Addr().Is4() {
		return false
	}
	for _, allowed := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"} {
		block := netip.MustParsePrefix(allowed)
		if p.Bits() >= block.Bits() && block.Contains(p.Masked().Addr()) {
			return true
		}
	}
	return false
}

func (s *Server) KeyID() string { return s.keyID }

func (s *Server) fail(w http.ResponseWriter, status int, code string) {
	httpx.JSON(w, status, map[string]any{"ok": false, "error": code, "master_time": s.now().Unix()})
}

func (s *Server) signed(w http.ResponseWriter, status int, value any, now time.Time) {
	body, err := json.Marshal(value)
	if err != nil {
		s.fail(w, 500, "internal")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Signature", sign.SignBody(s.key, body))
	w.Header().Set("Signature-Key", s.keyID)
	w.Header().Set("Signature-Time", strconv.FormatInt(now.Unix(), 10))
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Expose-Headers", "Signature, Signature-Key, Signature-Time, Retry-After")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	client := s.clients.Of(r)
	if client.Secure {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
	}
	if r.URL.RawPath != "" || r.URL.Fragment != "" {
		s.fail(w, 400, "path")
		return
	}
	path := r.URL.Path
	if r.Method == "GET" && path == "/healthz" {
		httpx.JSON(w, 200, map[string]any{"ok": true, "family": Family, "protocol": Protocol})
		return
	}
	isList := path == ListPath
	id := strings.TrimPrefix(path, ListPath+"/")
	joinID, isJoin := strings.CutSuffix(id, RelayJoinSuffix)
	if isJoin && path != id && sign.ValidKeyID(joinID) && s.relay != nil {
		id = joinID
	} else {
		isJoin = false
	}
	isItem := path != id && sign.ValidKeyID(id)
	if !isList && !isItem {
		s.fail(w, 404, "not_found")
		return
	}
	if r.Method == "OPTIONS" {
		w.Header().Set("Access-Control-Allow-Methods", "GET, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		w.WriteHeader(204)
		return
	}
	if isList && r.Method == "GET" {
		if ok, _ := s.reads.Allow(client.Key()); !ok {
			w.Header().Set("Retry-After", "1")
			s.fail(w, 429, "rate")
			return
		}
		s.list(w, r)
		return
	}
	if !isItem || (r.Method != "PUT" && r.Method != "DELETE") || (isJoin && r.Method != "PUT") {
		s.fail(w, 405, "method")
		return
	}
	if !client.Protected() {
		s.fail(w, 403, "tls_required")
		return
	}
	if r.URL.RawQuery != "" || r.ContentLength > MaxBody {
		s.fail(w, 400, "request")
		return
	}
	if ok, _ := s.writes.Allow(client.Key()); !ok {
		w.Header().Set("Retry-After", "1")
		s.fail(w, 429, "rate")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxBody))
	if err != nil {
		s.fail(w, 413, "body_size")
		return
	}
	if r.Method == "DELETE" && len(body) != 0 {
		s.fail(w, 400, "delete_body")
		return
	}
	auth, err := sign.ParseAuthorization(r.Header.Get("Authorization"))
	if err != nil || !auth.InWindow(s.now()) {
		s.fail(w, 401, "signature_or_clock")
		return
	}
	s.mu.Lock()
	public := s.approved[auth.KeyID]
	override, hasOverride := s.candidateOverrides[auth.KeyID]
	s.mu.Unlock()
	if public == nil {
		s.fail(w, 403, "unapproved_key")
		return
	}
	if !auth.Verify(public, s.keyID, r.Method, path, body) {
		s.fail(w, 401, "signature")
		return
	}
	if ok, _ := s.publishers.Allow(auth.KeyID); !ok {
		w.Header().Set("Retry-After", "5")
		s.fail(w, 429, "rate")
		return
	}
	fresh, err := s.nonces.UseNonce(auth.KeyID, auth.Nonce, sign.NonceWindow)
	if err != nil {
		s.fail(w, 500, "nonce_store")
		return
	}
	if !fresh {
		s.fail(w, 401, "replay")
		return
	}
	if r.Method == "DELETE" {
		s.remove(w, id, auth.KeyID)
		return
	}
	if isJoin {
		if len(body) != 0 {
			s.fail(w, 400, "join_body")
			return
		}
		s.relayJoin(w, r, id)
		return
	}
	advert, err := decodeAdvertisement(body, s.now())
	if err != nil {
		if s.diagnostics != nil {
			s.diagnostics.record(advertisementDiagnostic(advert, err))
		}
		s.fail(w, 400, "advertisement")
		return
	}
	if sign.ServerID(auth.KeyID, advert.Instance) != id {
		s.diagnostics.record(DiagAdvertisementID)
		s.fail(w, 400, "advertisement")
		return
	}
	candidate := client.IP.Unmap()
	if hasOverride {
		candidate = override
	}
	if !s.allowedEndpoint(candidate) {
		s.diagnostics.record(DiagCandidate)
		s.fail(w, 400, "candidate_address")
		return
	}
	var grant *RelayGrant
	if s.relay != nil && advert.Relay == 1 {
		var relayed netip.AddrPort
		grant, relayed, err = s.relayAllocate(r.Context(), auth.KeyID, id)
		if err != nil {
			s.fail(w, 503, "relay")
			return
		}
		// The relay's port is what guests use; the proof still has to return through it.
		advert.GamePort = relayed.Port()
		candidate = relayed.Addr()
		// The request field stops here: list rows keep the schema every game's strict row reader accepts.
		advert.Relay = 0
	}
	s.publish(w, id, auth.KeyID, advert, netip.AddrPortFrom(candidate, advert.GamePort), grant)
}

func decodeAdvertisement(body []byte, now time.Time) (Advertisement, error) {
	var advert Advertisement
	// Reject duplicate names rather than letting JSON parsers disagree about
	// which authenticated value is authoritative.
	fieldDecoder := json.NewDecoder(bytes.NewReader(body))
	start, err := fieldDecoder.Token()
	if err != nil || start != json.Delim('{') {
		return advert, errors.New("object required")
	}
	seen := map[string]bool{}
	for fieldDecoder.More() {
		name, err := fieldDecoder.Token()
		if err != nil {
			return advert, err
		}
		key, ok := name.(string)
		if !ok || seen[key] {
			return advert, errors.New("duplicate field")
		}
		switch key {
		case "protocol", "family", "network_version", "build", "map", "map_crc", "mode", "score", "players", "capacity", "flags", "name", "sequence", "time", "instance", "game_port", "relay":
		default:
			return advert, errors.New("noncanonical field")
		}
		seen[key] = true
		var value json.RawMessage
		if err := fieldDecoder.Decode(&value); err != nil {
			return advert, err
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&advert); err != nil {
		return advert, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return advert, errors.New("trailing JSON")
	}
	// Require every field, including fields whose valid value can be zero.
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		return advert, err
	}
	_, relayAsked := fields["relay"]
	if (!relayAsked && len(fields) != 15) || (relayAsked && (len(fields) != 16 || advert.Relay != 1)) {
		return advert, errors.New("missing fields")
	}
	for _, value := range fields {
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return advert, errors.New("null field")
		}
	}
	valid := advert.Protocol == Protocol && advert.Family == Family && advert.NetworkVersion == NetworkVersion &&
		advert.Mode <= 1 && (advert.Score == 10 || advert.Score == 15 || advert.Score == 25 || advert.Score == 50) &&
		advert.Capacity >= MinPlayers && advert.Capacity <= MaxPlayers && advert.Flags <= MaxFlags &&
		advert.Players >= 1 && advert.Players <= advert.Capacity && advert.Sequence > 0 &&
		len(advert.Name) >= 1 && len(advert.Name) <= 32 && strings.TrimSpace(advert.Name) == advert.Name &&
		len(advert.Instance) == 16 && sign.ValidKeyID(advert.Instance) &&
		advert.GamePort >= 1024 &&
		advert.Time >= now.Unix()-300 && advert.Time <= now.Unix()+300
	for _, b := range []byte(advert.Name) {
		if b < 32 || b > 126 {
			valid = false
		}
	}
	if !valid {
		return advert, errors.New("invalid fields")
	}
	return advert, nil
}

func (s *Server) sweep(now time.Time) {
	for id, rec := range s.records {
		if !now.Before(rec.ticketExpires) {
			delete(s.tickets, rec.ticket)
		}
		if now.Sub(rec.lastPut) > sign.NonceWindow {
			delete(s.tickets, rec.ticket)
			delete(s.records, id)
		}
	}
}

func (s *Server) publish(w http.ResponseWriter, id, keyID string, advert Advertisement, candidate netip.AddrPort, grant *RelayGrant) {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweep(now)
	old := s.records[id]
	if old != nil && old.keyID != keyID {
		s.diagnostics.record(DiagPublishOwner)
		s.fail(w, 403, "owner")
		return
	}
	if old != nil && advert.Sequence <= old.advert.Sequence {
		s.diagnostics.record(DiagPublishSequence)
		s.fail(w, 409, "sequence")
		return
	}
	if old == nil {
		count := 0
		for _, rec := range s.records {
			if rec.keyID == keyID {
				count++
			}
		}
		if count >= PerKeyServers || len(s.records) >= MaxServers {
			s.diagnostics.record(DiagPublishQuota)
			s.fail(w, 429, "quota")
			return
		}
	}
	var ticket [16]byte
	if _, err := io.ReadFull(s.random, ticket[:]); err != nil {
		s.diagnostics.record(DiagPublishRandom)
		s.fail(w, 500, "random")
		return
	}
	if _, exists := s.tickets[ticket]; exists {
		s.diagnostics.record(DiagPublishRandom)
		s.fail(w, 500, "random_collision")
		return
	}
	rec := &record{keyID: keyID, advert: advert, lastPut: now, ticket: ticket, ticketExpires: now.Add(TicketTTL), source: candidate}
	if _, err := io.ReadFull(s.random, rec.nonce[:]); err != nil {
		s.diagnostics.record(DiagPublishRandom)
		s.fail(w, 500, "random")
		return
	}
	rec.challenge = SignPacket(s.key, s.keyIDRaw, KindChallenge, ticket, rec.nonce)
	if old != nil {
		rec.verified = old.verified
		delete(s.tickets, old.ticket)
	}
	s.records[id], s.tickets[ticket] = rec, id
	s.diagnostics.record(DiagTicketAccepted)
	s.signed(w, 202, Challenge{Protocol, Family, id, Master{s.keyID, now.Unix()}, hex.EncodeToString(ticket[:]),
		rec.ticketExpires.Unix(), 30, 90, grant}, now)
}

func (s *Server) remove(w http.ResponseWriter, id, keyID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if rec := s.records[id]; rec != nil {
		if rec.keyID != keyID {
			s.fail(w, 403, "owner")
			return
		}
		delete(s.tickets, rec.ticket)
		delete(s.records, id)
	}
	s.signed(w, 200, map[string]bool{"ok": true}, s.now())
}

func (s *Server) list(w http.ResponseWriter, r *http.Request) {
	count := MaxServers
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		s.fail(w, 400, "query")
		return
	}
	if len(query) != 0 {
		values := query["limit"]
		if len(query) != 1 || len(values) != 1 {
			s.fail(w, 400, "query")
			return
		}
		n, err := strconv.Atoi(values[0])
		if err != nil || n < 1 || n > MaxServers || strconv.Itoa(n) != values[0] {
			s.fail(w, 400, "limit")
			return
		}
		count = n
	}
	now := s.now()
	result := List{Protocol: Protocol, Family: Family, NetworkVersion: NetworkVersion,
		Master: Master{s.keyID, now.Unix()}, TTL: 90, Servers: []Entry{}}
	s.mu.Lock()
	s.sweep(now)
	for _, rec := range s.records {
		if rec.verified != nil && rec.verified.Expires > now.Unix() && s.approved[rec.keyID] != nil {
			result.Servers = append(result.Servers, *rec.verified)
		}
	}
	s.mu.Unlock()
	sort.Slice(result.Servers, func(i, j int) bool { return result.Servers[i].ID < result.Servers[j].ID })
	if len(result.Servers) > count {
		result.Truncated = true
		result.Servers = result.Servers[:count]
	}
	s.signed(w, 200, result, now)
}
