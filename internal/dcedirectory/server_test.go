package dcedirectory

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/OpenCommunityEdition/opence-master-server/internal/httpx"
	"github.com/OpenCommunityEdition/opence-master-server/internal/sign"
	"github.com/OpenCommunityEdition/opence-master-server/internal/store"
)

var testTime = time.Unix(1793800000, 0)

func testKey(value byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{value}, ed25519.SeedSize))
}

type harness struct {
	t                   *testing.T
	s                   *Server
	db                  *store.Store
	now                 time.Time
	host, other, master ed25519.PrivateKey
	nonce               int
}

func newHarness(t *testing.T, change func(*Config)) *harness {
	t.Helper()
	h := &harness{t: t, now: testTime, host: testKey(0x22), other: testKey(0x33), master: testKey(0x11)}
	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	h.db = db
	db.Now = func() time.Time { return h.now }
	config := Config{Key: h.master, Approved: []ed25519.PublicKey{h.host.Public().(ed25519.PublicKey), h.other.Public().(ed25519.PublicKey)},
		Nonces: db, Now: func() time.Time { return h.now }, Random: rand.New(rand.NewSource(42)), AllowLoopback: true}
	if change != nil {
		change(&config)
	}
	h.s, err = New(config)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func (h *harness) advert() Advertisement {
	return Advertisement{Protocol: 1, Family: Family, NetworkVersion: 4, Build: 0x12345678, Map: 0,
		MapCRC: 0x9abcdef0, Mode: 0, Score: 15, Players: 1, Capacity: 2, Name: "DCE fixture",
		Sequence: 1, Time: h.now.Unix(), Instance: "0123456789abcdef", GamePort: 5150}
}

func (h *harness) request(method, path string, body []byte, private ed25519.PrivateKey) *http.Request {
	r := httptest.NewRequest(method, path, bytes.NewReader(body))
	r.RemoteAddr = "127.0.0.1:40000"
	if private != nil {
		h.nonce++
		r.Header.Set("Authorization", sign.Authorization(private, h.s.keyID, method, strings.Split(path, "?")[0], body,
			h.now, fmt.Sprintf("%032x", h.nonce)))
	}
	return r
}

func (h *harness) do(r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.s.ServeHTTP(w, r)
	return w
}

func (h *harness) publish(advert Advertisement) (string, Challenge, *httptest.ResponseRecorder) {
	h.t.Helper()
	body, _ := json.Marshal(advert)
	id := sign.ServerID(sign.KeyID(h.host.Public().(ed25519.PublicKey)), advert.Instance)
	w := h.do(h.request("PUT", ListPath+"/"+id, body, h.host))
	var challenge Challenge
	if w.Code == 202 {
		if err := json.Unmarshal(w.Body.Bytes(), &challenge); err != nil {
			h.t.Fatal(err)
		}
	}
	return id, challenge, w
}

func (h *harness) list(path string) List {
	h.t.Helper()
	w := h.do(h.request("GET", path, nil, nil))
	if w.Code != 200 {
		h.t.Fatalf("list status%d: %s", w.Code, w.Body)
	}
	if !sign.VerifyBody(h.master.Public().(ed25519.PublicKey), w.Header().Get("Signature"), w.Body.Bytes()) {
		h.t.Fatal("list signature")
	}
	if w.Header().Get("Signature-Key") != h.s.keyID {
		h.t.Fatal("wrong master key")
	}
	var list List
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
		h.t.Fatal(err)
	}
	if fmt.Sprint(list.Master.Time) != w.Header().Get("Signature-Time") {
		h.t.Fatal("clock header differs")
	}
	return list
}

func (h *harness) ack(probe Probe) []byte {
	var ticket [16]byte
	var nonce [32]byte
	copy(ticket[:], probe.Packet[9:25])
	copy(nonce[:], probe.Packet[25:57])
	return SignPacket(h.host, h.s.keyIDRaw, KindAck, ticket, nonce)
}

func TestProofRefreshExpiryAndDelete(t *testing.T) {
	h := newHarness(t, nil)
	advert := h.advert()
	id, challenge, response := h.publish(advert)
	if response.Code != 202 || challenge.Expires != h.now.Add(TicketTTL).Unix() {
		t.Fatalf("publish: %d %s", response.Code, response.Body)
	}
	if !sign.VerifyBody(h.master.Public().(ed25519.PublicKey), response.Header().Get("Signature"), response.Body.Bytes()) {
		t.Fatal("challenge response signature")
	}
	if len(h.list(ListPath).Servers) != 0 {
		t.Fatal("unproved endpoint listed")
	}
	probes := h.s.NextProbes()
	if len(probes) != 1 || probes[0].Destination.String() != "127.0.0.1:5150" {
		t.Fatalf("probes: %+v", probes)
	}
	if !VerifyPacket(h.master.Public().(ed25519.PublicKey), h.s.keyIDRaw, probes[0].Packet, KindChallenge) {
		t.Fatal("master probe signature")
	}
	ack := h.ack(probes[0])
	if h.s.AcceptAck(ack, netip.MustParseAddrPort("127.0.0.1:5151")) {
		t.Fatal("wrong observed port accepted")
	}
	if h.s.AcceptAck(ack, netip.MustParseAddrPort("127.0.0.2:5150")) {
		t.Fatal("wrong observed IP accepted")
	}
	if !h.s.AcceptAck(ack, probes[0].Destination) {
		t.Fatal("valid proof rejected")
	}
	if h.s.AcceptAck(ack, probes[0].Destination) {
		t.Fatal("proof replay")
	}
	list := h.list(ListPath)
	if len(list.Servers) != 1 || list.Servers[0].Endpoint.IP != "127.0.0.1" || list.Servers[0].Expires != h.now.Add(TTL).Unix() {
		t.Fatalf("list: %+v", list)
	}
	if len(h.s.NextProbes()) != 0 {
		t.Fatal("completed proof reprobed")
	}
	h.now = h.now.Add(30 * time.Second)
	advert.Sequence++
	advert.Time = h.now.Unix()
	advert.Players = 2
	_, _, response = h.publish(advert)
	if response.Code != 202 {
		t.Fatal(response.Body)
	}
	if h.list(ListPath).Servers[0].Players != 1 {
		t.Fatal("unproved refresh replaced proven metadata")
	}
	probes = h.s.NextProbes()
	if !h.s.AcceptAck(h.ack(probes[0]), probes[0].Destination) {
		t.Fatal("refresh proof")
	}
	if h.list(ListPath).Servers[0].Players != 2 {
		t.Fatal("refresh not listed")
	}
	w := h.do(h.request("DELETE", ListPath+"/"+id, nil, h.other))
	if w.Code != 403 || len(h.list(ListPath).Servers) != 1 {
		t.Fatal("different owner removed row")
	}
	w = h.do(h.request("DELETE", ListPath+"/"+id, nil, h.host))
	if w.Code != 200 || len(h.list(ListPath).Servers) != 0 {
		t.Fatal("owner delete failed")
	}

	h.now = h.now.Add(30 * time.Second)
	advert.Time = h.now.Unix()
	advert.Sequence++
	_, _, response = h.publish(advert)
	if response.Code != 202 {
		t.Fatal(response.Body)
	}
	probes = h.s.NextProbes()
	h.s.AcceptAck(h.ack(probes[0]), probes[0].Destination)
	h.now = h.now.Add(TTL)
	if len(h.list(ListPath).Servers) != 0 {
		t.Fatal("expired listing visible")
	}
}

func TestOnlineGameTypesAccepted(t *testing.T) {
	for _, test := range []struct{ mode, score uint8 }{{0, 25}, {1, 50}, {2, 3}, {3, 5}, {4, 1}, {5, 2}, {6, 25}} {
		h := newHarness(t, nil)
		a := h.advert()
		a.Mode, a.Score = test.mode, test.score
		if _, _, w := h.publish(a); w.Code >= 300 {
			t.Fatalf("mode %d score %d: got %d %s", test.mode, test.score, w.Code, w.Body)
		}
	}
}

func TestSignatureReplayAndMetadataRefusals(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*Advertisement)
	}{
		{"native_family", func(a *Advertisement) { a.Family = "opence" }},
		{"old_wire", func(a *Advertisement) { a.NetworkVersion = 2 }},
		{"capacity", func(a *Advertisement) { a.Capacity = 16 }},
		{"players", func(a *Advertisement) { a.Players = 3 }},
		{"name", func(a *Advertisement) { a.Name = "bad\nname" }},
		{"score", func(a *Advertisement) { a.Score = 99 }},
		{"mode", func(a *Advertisement) { a.Mode = 7 }},
		{"mode_score", func(a *Advertisement) { a.Mode = 5; a.Score = 50 }},
		{"old_time", func(a *Advertisement) { a.Time -= 301 }},
		{"future_time", func(a *Advertisement) { a.Time += 301 }},
		{"port", func(a *Advertisement) { a.GamePort = 53 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			h := newHarness(t, nil)
			a := h.advert()
			test.change(&a)
			_, _, w := h.publish(a)
			if w.Code != 400 {
				t.Fatalf("got%d %s", w.Code, w.Body)
			}
		})
	}
	h := newHarness(t, nil)
	a := h.advert()
	body, _ := json.Marshal(a)
	id := sign.ServerID(sign.KeyID(h.host.Public().(ed25519.PublicKey)), a.Instance)
	path := ListPath + "/" + id
	r := h.request("PUT", path, body, h.host)
	header := r.Header.Get("Authorization")
	if w := h.do(r); w.Code != 202 {
		t.Fatal(w.Body)
	}
	r = h.request("PUT", path, body, nil)
	r.Header.Set("Authorization", header)
	if w := h.do(r); w.Code != 401 {
		t.Fatal("HTTP nonce replay")
	}
	if _, _, w := h.publish(a); w.Code != 409 {
		t.Fatal("nonmonotonic sequence")
	}
	r = h.request("PUT", path, body, h.host)
	r.Header.Set("Authorization", strings.Replace(r.Header.Get("Authorization"), "sig=", "sig=A", 1))
	if w := h.do(r); w.Code != 401 {
		t.Fatal("bad signature")
	}
	r = h.request("PUT", path, body, testKey(0x44))
	if w := h.do(r); w.Code != 403 {
		t.Fatal("unapproved key")
	}
}

func TestNoHTTPAddressAssumptionAndRestrictedCandidates(t *testing.T) {
	h := newHarness(t, func(c *Config) {
		c.AllowLoopback = false
		c.CandidateOverrides = map[string]netip.Addr{sign.KeyID(testKey(0x22).Public().(ed25519.PublicKey)): netip.MustParseAddr("8.8.8.8")}
	})
	_, _, response := h.publish(h.advert())
	if response.Code != 202 {
		t.Fatal(response.Body)
	}
	probe := h.s.NextProbes()[0]
	if probe.Destination != netip.MustParseAddrPort("8.8.8.8:5150") {
		t.Fatal("operator override not used")
	}
	if h.s.AcceptAck(h.ack(probe), netip.MustParseAddrPort("127.0.0.1:5150")) {
		t.Fatal("HTTP source accepted as proof")
	}
	// No socket sends to this fixture address: this is pure packet validation.
	if !h.s.AcceptAck(h.ack(probe), probe.Destination) {
		t.Fatal("approved candidate proof failed")
	}
	if h.list(ListPath).Servers[0].Endpoint.IP != "8.8.8.8" {
		t.Fatal("observed source not listed")
	}

	h = newHarness(t, func(c *Config) { c.AllowLoopback = false })
	if _, _, response = h.publish(h.advert()); response.Code != 400 {
		t.Fatal("production accepted loopback candidate")
	}
	if len(h.s.NextProbes()) != 0 {
		t.Fatal("private probe scheduled")
	}
	for _, text := range []string{"10.0.0.1", "169.254.1.1", "203.0.113.1", "224.0.0.1", "0.0.0.0", "::1"} {
		if h.s.allowedEndpoint(netip.MustParseAddr(text)) {
			t.Fatalf("allowed forbidden%s", text)
		}
	}
	h = newHarness(t, func(c *Config) { c.AllowPrivateLAN = []netip.Prefix{netip.MustParsePrefix("192.168.42.0/24")} })
	if !h.s.allowedEndpoint(netip.MustParseAddr("192.168.42.4")) || h.s.allowedEndpoint(netip.MustParseAddr("192.168.43.4")) {
		t.Fatal("LAN exception escaped subnet")
	}
}

func TestUDPBoundsAndTamper(t *testing.T) {
	h := newHarness(t, nil)
	h.publish(h.advert())
	probe := h.s.NextProbes()[0]
	ack := h.ack(probe)
	for _, offset := range []int{0, 8, 9, 25, 57, 120} {
		bad := append([]byte(nil), ack...)
		bad[offset] ^= 1
		if h.s.AcceptAck(bad, probe.Destination) {
			t.Fatalf("accepted tampered byte%d", offset)
		}
	}
	if h.s.AcceptAck(ack[:120], probe.Destination) || h.s.AcceptAck(append(ack, 0), probe.Destination) {
		t.Fatal("packet length")
	}
	if len(h.s.NextProbes()) != 0 {
		t.Fatal("immediate retry")
	}
	for i := 0; i < 2; i++ {
		h.now = h.now.Add(2 * time.Second)
		if len(h.s.NextProbes()) != 1 {
			t.Fatal("missing bounded retry")
		}
	}
	h.now = h.now.Add(2 * time.Second)
	if len(h.s.NextProbes()) != 0 {
		t.Fatal("more than3 probes")
	}
	h.now = testTime.Add(TicketTTL)
	if h.s.AcceptAck(ack, probe.Destination) {
		t.Fatal("expired ticket accepted")
	}
	if len(h.list(ListPath).Servers) != 0 {
		t.Fatal("failed proof listed")
	}
}

func TestTLSPathsLimitAndUnchangedNativeNamespace(t *testing.T) {
	h := newHarness(t, nil)
	a := h.advert()
	body, _ := json.Marshal(a)
	id := sign.ServerID(sign.KeyID(h.host.Public().(ed25519.PublicKey)), a.Instance)
	r := h.request("PUT", ListPath+"/"+id, body, h.host)
	r.RemoteAddr = "8.8.8.8:12345"
	r.Header.Set("X-Forwarded-Proto", "https")
	if w := h.do(r); w.Code != 403 {
		t.Fatal("untrusted proxy accepted")
	}
	h = newHarness(t, func(c *Config) {
		c.Clients = httpx.Clients{Proxies: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}}
	})
	r = h.request("PUT", ListPath+"/"+id, body, h.host)
	if w := h.do(r); w.Code != 403 {
		t.Fatal("proxy without TLS accepted")
	}
	r = h.request("PUT", ListPath+"/"+id, body, h.host)
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-Forwarded-For", "8.8.8.8")
	if w := h.do(r); w.Code != 202 {
		t.Fatal(w.Body)
	}
	for _, path := range []string{"/v1/servers", "/admin/", "/v1/dce/servers/../servers", "/v1/dce/%73ervers"} {
		if w := h.do(h.request("GET", path, nil, nil)); w.Code == 200 {
			t.Fatalf("unwanted path%s", path)
		}
	}
	for _, path := range []string{ListPath + "?limit=0", ListPath + "?limit=65", ListPath + "?limit=16&limit=16", ListPath + "?url=http://127.0.0.1"} {
		if w := h.do(h.request("GET", path, nil, nil)); w.Code != 400 {
			t.Fatalf("query%s", path)
		}
	}
	for i := 0; i < 60; i++ {
		h.do(h.request("GET", ListPath+"?limit=16", nil, nil))
	}
	if w := h.do(h.request("GET", ListPath, nil, nil)); w.Code != 429 {
		t.Fatal("read limiter")
	}
}

func TestDurableNonceReplay(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nonce.db")
	db, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := db.UseNonce("a", strings.Repeat("0", 32), sign.NonceWindow)
	if err != nil || !fresh {
		t.Fatal(err)
	}
	db.Close()
	db, err = store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	fresh, err = db.UseNonce("a", strings.Repeat("0", 32), sign.NonceWindow)
	if err != nil || fresh {
		t.Fatal("nonce replay accepted after database reopen")
	}
}

func TestActualLoopbackHTTPAndGameUDPSocket(t *testing.T) {
	h := newHarness(t, nil)
	httpServer := httptest.NewServer(h.s)
	defer httpServer.Close()
	game, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer game.Close()
	master, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	game.SetDeadline(time.Now().Add(3 * time.Second))
	master.SetDeadline(time.Now().Add(3 * time.Second))
	a := h.advert()
	a.GamePort = uint16(game.LocalAddr().(*net.UDPAddr).Port)
	body, _ := json.Marshal(a)
	id := sign.ServerID(sign.KeyID(h.host.Public().(ed25519.PublicKey)), a.Instance)
	r, _ := http.NewRequest("PUT", httpServer.URL+ListPath+"/"+id, bytes.NewReader(body))
	r.Header.Set("Authorization", sign.Authorization(h.host, h.s.keyID, "PUT", ListPath+"/"+id, body, h.now, strings.Repeat("a", 32)))
	response, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 202 {
		t.Fatalf("HTTP status%d", response.StatusCode)
	}
	probe := h.s.NextProbes()[0]
	if _, err := master.WriteToUDPAddrPort(probe.Packet, probe.Destination); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 256)
	n, from, err := game.ReadFromUDPAddrPort(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if n != PacketSize || !VerifyPacket(h.master.Public().(ed25519.PublicKey), h.s.keyIDRaw, buffer[:n], KindChallenge) {
		t.Fatal("wire challenge signature")
	}
	if _, err := game.WriteToUDPAddrPort(h.ack(Probe{Packet: buffer[:n]}), from); err != nil {
		t.Fatal(err)
	}
	n, observed, err := master.ReadFromUDPAddrPort(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if !h.s.AcceptAck(buffer[:n], observed) {
		t.Fatal("actual source socket proof failed")
	}
	response, err = http.Get(httpServer.URL + ListPath + "?limit=16")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	listed, _ := io.ReadAll(response.Body)
	if !sign.VerifyBody(h.master.Public().(ed25519.PublicKey), response.Header.Get("Signature"), listed) {
		t.Fatal("actual HTTP signature")
	}
	var list List
	json.Unmarshal(listed, &list)
	if len(list.Servers) != 1 || list.Servers[0].Endpoint.Port != a.GamePort {
		t.Fatalf("actual list%s", listed)
	}
}

func TestPacketDomainFixtureShape(t *testing.T) {
	h := newHarness(t, nil)
	var ticket [16]byte
	var nonce [32]byte
	packet := SignPacket(h.host, h.s.keyIDRaw, KindAck, ticket, nonce)
	if len(packet) != 121 || hex.EncodeToString(packet[:8]) != "4443454449523100" {
		t.Fatal("wire shape")
	}
	wrongMaster := h.s.keyIDRaw
	wrongMaster[0] ^= 1
	if VerifyPacket(h.host.Public().(ed25519.PublicKey), wrongMaster, packet, KindAck) {
		t.Fatal("cross-master signature")
	}
}

func TestStrictJSONAndWritePath(t *testing.T) {
	for _, mutate := range []func([]byte) []byte{
		func(b []byte) []byte { return append(b, []byte(` {}`)...) },
		func(b []byte) []byte { return []byte(strings.Replace(string(b), `"map":0`, `"map":0,"map":1`, 1)) },
		func(b []byte) []byte { return []byte(strings.Replace(string(b), `"map":0,`, ``, 1)) },
		func(b []byte) []byte { return []byte(strings.Replace(string(b), `"map":0`, `"Protocol":1`, 1)) },
		func(b []byte) []byte { return []byte(strings.Replace(string(b), `"map":0`, `"MAP":0`, 1)) },
		func(b []byte) []byte { return []byte(strings.Replace(string(b), `"map":0`, `"map":null`, 1)) },
		func(b []byte) []byte {
			return []byte(strings.Replace(string(b), `"map":0`, `"endpoint":"8.8.8.8","map":0`, 1))
		},
	} {
		h := newHarness(t, nil)
		a := h.advert()
		body, _ := json.Marshal(a)
		body = mutate(body)
		id := sign.ServerID(sign.KeyID(h.host.Public().(ed25519.PublicKey)), a.Instance)
		w := h.do(h.request("PUT", ListPath+"/"+id, body, h.host))
		if w.Code != 400 || len(h.s.NextProbes()) != 0 {
			t.Fatalf("invalid JSON status%d", w.Code)
		}
	}
	h := newHarness(t, nil)
	a := h.advert()
	body, _ := json.Marshal(a)
	id := sign.ServerID(sign.KeyID(h.host.Public().(ed25519.PublicKey)), a.Instance)
	w := h.do(h.request("PUT", ListPath+"/"+id+"?x=1", body, h.host))
	if w.Code != 400 {
		t.Fatal("write query accepted")
	}
	w = h.do(h.request("PUT", ListPath+"/"+id, bytes.Repeat([]byte("x"), MaxBody+1), h.host))
	if w.Code != 400 && w.Code != 413 {
		t.Fatal("oversize body accepted")
	}
	w = h.do(h.request("GET", ListPath+"?limit=16;other=1", nil, nil))
	if w.Code != 400 {
		t.Fatal("malformed query silently accepted")
	}
}

func TestSignedTruncationQuotaAndSequenceAcrossExpiry(t *testing.T) {
	h := newHarness(t, nil)
	for i := 0; i < PerKeyServers; i++ {
		a := h.advert()
		a.Instance = fmt.Sprintf("%016x", i)
		_, _, w := h.publish(a)
		if w.Code != 202 {
			t.Fatal(w.Body)
		}
		probe := h.s.NextProbes()[0]
		if !h.s.AcceptAck(h.ack(probe), probe.Destination) {
			t.Fatal("proof")
		}
	}
	list := h.list(ListPath + "?limit=1")
	if len(list.Servers) != 1 || !list.Truncated {
		t.Fatal("signed truncation missing")
	}
	all := h.list(ListPath)
	if len(all.Servers) != PerKeyServers || all.Truncated {
		t.Fatal("default list bound")
	}
	h.now = h.now.Add(5 * time.Second)
	a := h.advert()
	a.Instance = "9999999999999999"
	if _, _, w := h.publish(a); w.Code != 429 {
		t.Fatal("per-key quota")
	}
	h.now = h.now.Add(TTL)
	a.Instance = "0000000000000000"
	a.Time = h.now.Unix()
	if _, _, w := h.publish(a); w.Code != 409 {
		t.Fatal("expiry reset sequence high water")
	}
	if len(h.list(ListPath).Servers) != 0 {
		t.Fatal("expired entries listed")
	}
}

func FuzzAdvertisementAndUDPPacket(f *testing.F) {
	f.Add([]byte(`{"protocol":1}`))
	f.Add([]byte(`null`))
	f.Add(make([]byte, PacketSize))
	f.Fuzz(func(t *testing.T, body []byte) {
		if len(body) > MaxBody {
			t.Skip()
		}
		_, _ = decodeAdvertisement(body, testTime)
		var master [8]byte
		public := testKey(0x11).Public().(ed25519.PublicKey)
		_ = VerifyPacket(public, master, body, KindAck)
		_ = VerifyPacket(nil, master, body, KindAck)
	})
}
