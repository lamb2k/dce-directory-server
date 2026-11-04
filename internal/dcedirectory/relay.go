package dcedirectory

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"time"
)

// RelayMinNetworkVersion is the first game protocol whose PUT reply parser accepts a relay field.
const RelayMinNetworkVersion = 5

// RelayJoinSuffix is the signed guest route: PUT /v1/dce/servers/<id>/join with an empty body.
const RelayJoinSuffix = "/join"

// RelayConfig is operator configuration. The signed reply names the relay, so moving it needs no new image.
type RelayConfig struct {
	Control   string // Literal loopback http base.
	Key       string
	Public    netip.Addr
	HelloPort uint16
	Client    *http.Client
}

// RelayGrant is master-signed with its reply. An IPv4 literal needs no DNS on console or in the gateway.
type RelayGrant struct {
	Host  string `json:"host"`
	Port  uint16 `json:"port"`
	Token string `json:"token"`
}

// RelayJoin answers a guest. Port is the allocation port from the signed catalog row.
type RelayJoin struct {
	Protocol int    `json:"protocol"`
	Family   string `json:"family"`
	ID       string `json:"id"`
	Master   Master `json:"master"`
	Host     string `json:"host"`
	Port     uint16 `json:"port"`
	Token    string `json:"token"`
	Expires  int64  `json:"expires"`
}

func relayToken() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}

func (s *Server) relayCall(ctx context.Context, route string, request map[string]string) (uint16, int, error) {
	body, err := json.Marshal(request)
	if err != nil {
		return 0, 0, err
	}
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	call, err := http.NewRequestWithContext(ctx, "POST", s.relay.Control+route, bytes.NewReader(body))
	if err != nil {
		return 0, 0, err
	}
	call.Header.Set("X-Relay-Key", s.relay.Key)
	client := s.relay.Client
	if client == nil {
		client = http.DefaultClient
	}
	response, err := client.Do(call)
	if err != nil {
		return 0, 0, err
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return 0, response.StatusCode, fmt.Errorf("relay status %d", response.StatusCode)
	}
	var reply struct {
		Port uint16 `json:"port"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(nil, response.Body, 256)).Decode(&reply); err != nil {
		return 0, 200, err
	}
	if reply.Port < 1024 {
		return 0, 200, errors.New("relay port")
	}
	return reply.Port, 200, nil
}

func (s *Server) relayAllocate(ctx context.Context, keyID, id string) (*RelayGrant, netip.AddrPort, error) {
	token, err := relayToken()
	if err != nil {
		return nil, netip.AddrPort{}, err
	}
	port, _, err := s.relayCall(ctx, "/alloc", map[string]string{"key": keyID, "id": id, "token": token})
	if err != nil {
		return nil, netip.AddrPort{}, err
	}
	return &RelayGrant{s.relay.Public.String(), s.relay.HelloPort, token}, netip.AddrPortFrom(s.relay.Public, port), nil
}

// relayJoin admits an approved, signed guest only to a host with a fresh proof.
func (s *Server) relayJoin(w http.ResponseWriter, r *http.Request, id string) {
	now := s.now()
	s.mu.Lock()
	s.sweep(now)
	rec := s.records[id]
	listed := rec != nil && rec.verified != nil && rec.verified.Expires > now.Unix()
	s.mu.Unlock()
	if !listed {
		s.fail(w, 404, "no_host")
		return
	}
	token, err := relayToken()
	if err != nil {
		s.fail(w, 500, "random")
		return
	}
	port, status, err := s.relayCall(r.Context(), "/join", map[string]string{"id": id, "token": token})
	if err != nil {
		if status == 409 {
			s.fail(w, 409, "no_host")
			return
		}
		s.fail(w, 503, "relay")
		return
	}
	s.signed(w, 200, RelayJoin{Protocol, Family, id, Master{s.keyID, now.Unix()}, s.relay.Public.String(), port, token, now.Add(30 * time.Second).Unix()}, now)
}
