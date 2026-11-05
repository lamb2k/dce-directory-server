package dcedirectory

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

func relayHarness(t *testing.T, status int) (*harness, *[]string) {
	t.Helper()
	calls := &[]string{}
	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*calls = append(*calls, r.URL.Path+" "+r.Header.Get("X-Relay-Key"))
		w.WriteHeader(status)
		w.Write([]byte(`{"port":5401}`))
	}))
	t.Cleanup(control.Close)
	return newHarness(t, func(c *Config) {
		c.Relay = &RelayConfig{Control: control.URL, Key: "k", Public: netip.MustParseAddr("127.0.0.1"), HelloPort: 5400}
	}), calls
}

func TestOldProtocolGetsNoRelayField(t *testing.T) {
	h, calls := relayHarness(t, 200)
	advert := h.advert()
	_, _, response := h.publish(advert)
	if response.Code != 202 || strings.Contains(response.Body.String(), "relay") || len(*calls) != 0 {
		t.Fatalf("old client must be untouched: %d %s", response.Code, response.Body)
	}
}

func TestRelayCandidateAndProofThroughRelayPort(t *testing.T) {
	h, calls := relayHarness(t, 200)
	s := h.s
	grant, relayed, err := s.relayAllocate(t.Context(), "k1", "i1")
	if err != nil || grant.Host != "127.0.0.1" || grant.Port != 5400 || len(grant.Token) != 32 || relayed.Port() != 5401 {
		t.Fatalf("grant %+v %v %v", grant, relayed, err)
	}
	if (*calls)[0] != "/alloc k" {
		t.Fatalf("calls %v", *calls)
	}
	var value map[string]any
	data, _ := json.Marshal(Challenge{Relay: grant})
	json.Unmarshal(data, &value)
	if value["relay"].(map[string]any)["token"] != grant.Token {
		t.Fatal("grant missing from signed reply body")
	}
}

func TestRelayDownFailsClosed(t *testing.T) {
	h, _ := relayHarness(t, 503)
	if _, _, err := h.s.relayAllocate(t.Context(), "k1", "i1"); err == nil {
		t.Fatal("relay failure must not produce a grant")
	}
}

func TestJoinNeedsSignatureAndListedHost(t *testing.T) {
	h, calls := relayHarness(t, 200)
	path := ListPath + "/0123456789abcdef" + RelayJoinSuffix
	unsigned := httptest.NewRequest("PUT", path, nil)
	unsigned.RemoteAddr = "127.0.0.1:1"
	if response := h.do(unsigned); response.Code != 401 {
		t.Fatalf("unsigned join: %d", response.Code)
	}
	if response := h.do(h.request("PUT", path, nil, h.host)); response.Code != 404 {
		t.Fatalf("unlisted join: %d %s", response.Code, response.Body)
	}
	if len(*calls) != 0 {
		t.Fatal("relay contacted for refused join")
	}
}

// Real PUT path: asked grant is in the signed reply and the row's port is the relay's; unasked stays direct.
func TestAskedPutGetsGrant(t *testing.T) {
	h, calls := relayHarness(t, 200)
	advert := h.advert()
	advert.Relay = 1
	_, _, response := h.publish(advert)
	if response.Code != 202 || !strings.Contains(response.Body.String(), `"relay":{"host":"127.0.0.1","port":5400`) || len(*calls) != 1 {
		t.Fatalf("asked PUT: %d %s %v", response.Code, response.Body, *calls)
	}
}

func TestListedRowCarriesNoRelayField(t *testing.T) {
	h, _ := relayHarness(t, 200)
	advert := h.advert()
	advert.Relay = 1
	_, _, response := h.publish(advert)
	if response.Code != 202 {
		t.Fatalf("PUT: %d %s", response.Code, response.Body)
	}
	probe := h.s.NextProbes()[0]
	if !h.s.AcceptAck(h.ack(probe), probe.Destination) {
		t.Fatal("proof failed")
	}
	listed := h.do(h.request("GET", ListPath, nil, nil))
	body := listed.Body.String()
	if !strings.Contains(body, `"game_port":`) || strings.Contains(body, `"relay"`) {
		t.Fatalf("row must keep the game's strict schema: %s", body)
	}
}

func TestRelayFieldOnlyOne(t *testing.T) {
	h, _ := relayHarness(t, 200)
	advert := h.advert()
	advert.Relay = 2
	if _, _, response := h.publish(advert); response.Code == 202 {
		t.Fatal("relay field other than 1 accepted")
	}
}
