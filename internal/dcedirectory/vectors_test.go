package dcedirectory

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"flag"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/OpenCommunityEdition/opence-master-server/internal/sign"
)

var updateDCEVectors = flag.Bool("update-dce-vectors", false, "rewrite synthetic DCE protocol fixtures")

func fixtureResponse(w *httptest.ResponseRecorder) map[string]any {
	return map[string]any{"status": w.Code, "body": w.Body.String(), "headers": map[string]string{
		"Signature": w.Header().Get("Signature"), "Signature-Key": w.Header().Get("Signature-Key"),
		"Signature-Time": w.Header().Get("Signature-Time")}}
}

func TestDCEVectorsFile(t *testing.T) {
	entropy := make([]byte, 48)
	for i := range entropy {
		entropy[i] = byte(i)
	}
	h := newHarness(t, func(c *Config) { c.Random = bytes.NewReader(entropy) })
	advert := h.advert()
	body, _ := json.Marshal(advert)
	id := sign.ServerID(sign.KeyID(h.host.Public().(ed25519.PublicKey)), advert.Instance)
	path := ListPath + "/" + id
	authorization := sign.Authorization(h.host, h.s.keyID, "PUT", path, body, h.now, strings.Repeat("c", 32))
	r := h.request("PUT", path, body, nil)
	r.Header.Set("Authorization", authorization)
	registered := h.do(r)
	if registered.Code != 202 {
		t.Fatal(registered.Body)
	}
	probe := h.s.NextProbes()[0]
	ack := h.ack(probe)
	if !h.s.AcceptAck(ack, probe.Destination) {
		t.Fatal("fixture proof failed")
	}
	listed := h.do(h.request("GET", ListPath+"?limit=16", nil, nil))
	fixture := map[string]any{
		"notice":        "SYNTHETIC PUBLIC TEST KEYS ONLY. Never provision these seeds in a service, client profile, VMU or deployment.",
		"protocol_spec": "docs/DCE_DIRECTORY_PROTOCOL.md", "time": h.now.Unix(),
		"master_seed_hex": hex.EncodeToString(h.master.Seed()), "host_seed_hex": hex.EncodeToString(h.host.Seed()),
		"master_public": sign.PublicKeyText(h.master.Public().(ed25519.PublicKey)),
		"host_public":   sign.PublicKeyText(h.host.Public().(ed25519.PublicKey)),
		"master_key_id": h.s.keyID, "host_key_id": sign.KeyID(h.host.Public().(ed25519.PublicKey)),
		"server_id": id, "put_path": path, "put_body": string(body), "authorization": authorization,
		"canonical_request":  sign.Canonical(h.s.keyID, "PUT", path, "1793800000", strings.Repeat("c", 32), body),
		"challenge_response": fixtureResponse(registered), "list_response": fixtureResponse(listed),
		"udp_challenge_hex": hex.EncodeToString(probe.Packet), "udp_ack_hex": hex.EncodeToString(ack),
		"udp_challenge_message_hex": hex.EncodeToString(PacketMessage(h.s.keyIDRaw, probe.Packet)),
		"udp_ack_message_hex":       hex.EncodeToString(PacketMessage(h.s.keyIDRaw, ack)),
		"observed_endpoint":         probe.Destination.String(),
	}
	made, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	made = append(made, '\n')
	pathOnDisk := "../../testdata/dce_directory_vectors.json"
	if *updateDCEVectors {
		if err := os.WriteFile(pathOnDisk, made, 0644); err != nil {
			t.Fatal(err)
		}
	}
	stored, err := os.ReadFile(pathOnDisk)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stored, made) {
		t.Fatal("DCE fixtures changed; review protocol then regenerate -update-dce-vectors")
	}
}
