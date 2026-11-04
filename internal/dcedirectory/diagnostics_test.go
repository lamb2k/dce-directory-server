package dcedirectory

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"math"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/OpenCommunityEdition/opence-master-server/internal/sign"
)

func TestPublicationDiagnosticReasons(t *testing.T) {
	for _, test := range []struct {
		stage  DiagnosticStage
		change func(*Advertisement)
	}{
		{DiagAdvertisementProtocol, func(a *Advertisement) { a.Protocol = 0 }},
		{DiagAdvertisementFamily, func(a *Advertisement) { a.Family = "SECRET_PAYLOAD" }},
		{DiagAdvertisementNetwork, func(a *Advertisement) { a.NetworkVersion = 2 }},
		{DiagAdvertisementMode, func(a *Advertisement) { a.Mode = 9 }},
		{DiagAdvertisementScore, func(a *Advertisement) { a.Score = 9 }},
		{DiagAdvertisementPlayers, func(a *Advertisement) { a.Players = 3 }},
		{DiagAdvertisementSequence, func(a *Advertisement) { a.Sequence = 0 }},
		{DiagAdvertisementName, func(a *Advertisement) { a.Name = " SECRET_PAYLOAD " }},
		{DiagAdvertisementName, func(a *Advertisement) { a.Name = "SECRET\nPAYLOAD" }},
		{DiagAdvertisementInstance, func(a *Advertisement) { a.Instance = "SECRET_PAYLOAD" }},
		{DiagAdvertisementPort, func(a *Advertisement) { a.GamePort = 53 }},
		{DiagAdvertisementTime, func(a *Advertisement) { a.Time -= 301 }},
	} {
		t.Run(diagnosticLabels[test.stage], func(t *testing.T) {
			var output bytes.Buffer
			d := NewPublishDiagnostics(&output)
			h := newHarness(t, func(c *Config) { c.Diagnostics = d })
			a := h.advert()
			test.change(&a)
			_, _, w := h.publish(a)
			if w.Code != 400 || d.Snapshot()[test.stage] != 1 {
				t.Fatalf("status%d counters%v", w.Code, d.Snapshot())
			}
			if strings.Contains(output.String(), "SECRET") || strings.Contains(output.String(), "ed25519:") {
				t.Fatal("payload leaked")
			}
		})
	}
	for _, test := range []struct {
		body  string
		stage DiagnosticStage
	}{
		{"not-json SECRET_PAYLOAD", DiagAdvertisementJSON},
		{`{"private_seed":"SECRET_PAYLOAD"}`, DiagAdvertisementNames},
		{`{}`, DiagAdvertisementPresence},
	} {
		var output bytes.Buffer
		d := NewPublishDiagnostics(&output)
		h := newHarness(t, func(c *Config) { c.Diagnostics = d })
		id := sign.ServerID(sign.KeyID(h.host.Public().(ed25519.PublicKey)), h.advert().Instance)
		w := h.do(h.request("PUT", ListPath+"/"+id, []byte(test.body), h.host))
		if w.Code != 400 || d.Snapshot()[test.stage] != 1 || strings.Contains(output.String(), "SECRET") {
			t.Fatal("JSON classification/leak")
		}
	}
}

func TestCandidatePublicationAndSendCounters(t *testing.T) {
	d := NewPublishDiagnostics(nil)
	h := newHarness(t, func(c *Config) { c.Diagnostics = d; c.AllowLoopback = false })
	if _, _, w := h.publish(h.advert()); w.Code != 400 || d.Snapshot()[DiagCandidate] != 1 {
		t.Fatal("candidate reason")
	}
	d = NewPublishDiagnostics(nil)
	h = newHarness(t, func(c *Config) { c.Diagnostics = d })
	a := h.advert()
	body, _ := json.Marshal(a)
	w := h.do(h.request("PUT", ListPath+"/0000000000000000", body, h.host))
	if w.Code != 400 || d.Snapshot()[DiagAdvertisementID] != 1 {
		t.Fatal("id reason")
	}
	if _, _, w := h.publish(a); w.Code != 202 {
		t.Fatal(w.Body)
	}
	if _, _, w := h.publish(a); w.Code != 409 || d.Snapshot()[DiagPublishSequence] != 1 {
		t.Fatal("sequence reason")
	}
	if len(h.s.NextProbes()) != 1 || d.Snapshot()[DiagTicketAccepted] != 1 || d.Snapshot()[DiagProbeScheduled] != 1 {
		t.Fatal("ticket/probe stages")
	}
	h.s.NoteProbeSend(true)
	h.s.NoteProbeSend(false)
	if d.Snapshot()[DiagProbeSendOK] != 1 || d.Snapshot()[DiagProbeSendFailed] != 1 {
		t.Fatal("send stages")
	}
	d = NewPublishDiagnostics(nil)
	h = newHarness(t, func(c *Config) { c.Diagnostics = d; c.Random = strings.NewReader("") })
	if _, _, w := h.publish(h.advert()); w.Code != 500 || d.Snapshot()[DiagPublishRandom] != 1 {
		t.Fatal("random failure")
	}
	d = NewPublishDiagnostics(nil)
	h = newHarness(t, func(c *Config) { c.Diagnostics = d })
	for i := 0; i < 4; i++ {
		a = h.advert()
		a.Instance = fmt.Sprintf("%016x", i)
		h.publish(a)
	}
	h.now = h.now.Add(5 * time.Second)
	a.Instance = "9999999999999999"
	if _, _, w := h.publish(a); w.Code != 429 || d.Snapshot()[DiagPublishQuota] != 1 {
		t.Fatal("quota reason")
	}
}

func TestAckDiagnosticReasons(t *testing.T) {
	for _, stage := range []DiagnosticStage{DiagAckFormat, DiagAckAddress, DiagAckTicket, DiagAckExpired, DiagAckUnsent, DiagAckSource, DiagAckNonce, DiagAckRate, DiagAckSignature, DiagAckAccepted} {
		t.Run(diagnosticLabels[stage], func(t *testing.T) {
			d := NewPublishDiagnostics(nil)
			h := newHarness(t, func(c *Config) { c.Diagnostics = d })
			id, _, w := h.publish(h.advert())
			if w.Code != 202 {
				t.Fatal(w.Body)
			}
			probe := h.s.NextProbes()[0]
			ack := h.ack(probe)
			source := probe.Destination
			switch stage {
			case DiagAckFormat:
				ack = ack[:120]
			case DiagAckAddress:
				source = netip.MustParseAddrPort("10.0.0.1:5150")
			case DiagAckTicket:
				ack[9] ^= 1
			case DiagAckExpired:
				h.now = h.now.Add(TicketTTL)
			case DiagAckUnsent:
				h.s.records[id].replies = 0
			case DiagAckSource:
				source = netip.MustParseAddrPort("127.0.0.2:5150")
			case DiagAckNonce:
				ack[25] ^= 1
			case DiagAckRate:
				for i := 0; i < 128; i++ {
					h.s.ackGlobal.Allow("all")
				}
			case DiagAckSignature:
				ack[57] ^= 1
			}
			accepted := h.s.AcceptAck(ack, source)
			if accepted != (stage == DiagAckAccepted) || d.Snapshot()[stage] != 1 {
				t.Fatalf("accept%v counters%v", accepted, d.Snapshot())
			}
		})
	}
}

func TestDiagnosticsBoundedSecretFreeAndNoAllocationWhenDisabled(t *testing.T) {
	var output bytes.Buffer
	d := NewPublishDiagnostics(&output)
	d.counts[DiagCandidate] = math.MaxUint64
	for i := 0; i < 100; i++ {
		d.record(DiagCandidate)
	}
	if strings.Count(output.String(), "\n") != DiagnosticLogLimit || output.Len() > 1024 || d.Snapshot()[DiagCandidate] != math.MaxUint64 {
		t.Fatal("log/count cap")
	}
	for _, line := range strings.Split(strings.TrimSpace(output.String()), "\n") {
		if !strings.HasPrefix(line, "dce_publish_diag stage=candidate_address count=") {
			t.Fatal("unbounded log vocabulary")
		}
	}
	var off *PublishDiagnostics
	if allocations := testing.AllocsPerRun(1000, func() { off.record(DiagAckAccepted) }); allocations != 0 {
		t.Fatal("disabled allocation")
	}
	if allocations := testing.AllocsPerRun(1000, func() { d.record(DiagAckAccepted) }); allocations != 0 {
		t.Fatal("post-cap allocation")
	}
	t.Logf("diagnostic object=%d bytes; server pointer=%d bytes; counters=%d", unsafe.Sizeof(PublishDiagnostics{}), unsafe.Sizeof(off), DiagnosticStageCount)
}

func TestDiagnosticsPreserveExactHTTPAndUDPBehavior(t *testing.T) {
	var output bytes.Buffer
	off := newHarness(t, nil)
	on := newHarness(t, func(c *Config) { c.Diagnostics = NewPublishDiagnostics(&output) })
	a := off.advert()
	_, _, left := off.publish(a)
	_, _, right := on.publish(a)
	if left.Code != right.Code || left.Body.String() != right.Body.String() || !reflect.DeepEqual(left.Header(), right.Header()) {
		t.Fatal("diagnostics changed publish wire")
	}
	p := off.s.NextProbes()
	q := on.s.NextProbes()
	if !reflect.DeepEqual(p, q) {
		t.Fatal("diagnostics changed UDP wire")
	}
	if off.s.AcceptAck(off.ack(p[0]), p[0].Destination) != on.s.AcceptAck(on.ack(q[0]), q[0].Destination) {
		t.Fatal("diagnostics changed ACK result")
	}
	if !reflect.DeepEqual(off.list(ListPath), on.list(ListPath)) {
		t.Fatal("diagnostics changed catalog")
	}
	a.Sequence++
	a.Mode = 9
	_, _, left = off.publish(a)
	_, _, right = on.publish(a)
	if left.Code != right.Code || left.Body.String() != right.Body.String() || !reflect.DeepEqual(left.Header(), right.Header()) {
		t.Fatal("diagnostics changed error wire")
	}
	for _, secret := range []string{sign.PublicKeyText(off.master.Public().(ed25519.PublicKey)), sign.PublicKeyText(off.host.Public().(ed25519.PublicKey)), off.s.keyID, p[0].Destination.String(), a.Instance} {
		if strings.Contains(output.String(), secret) {
			t.Fatal("identifier/endpoint leaked")
		}
	}
}

func TestConcurrentDiagnosticCapAndCounts(t *testing.T) {
	var output bytes.Buffer
	d := NewPublishDiagnostics(&output)
	var group sync.WaitGroup
	for i := 0; i < 16; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for j := 0; j < 100; j++ {
				d.record(DiagAckAccepted)
				_ = d.Snapshot()
			}
		}()
	}
	group.Wait()
	if d.Snapshot()[DiagAckAccepted] != 1600 || strings.Count(output.String(), "\n") != 8 || output.Len() > 1024 {
		t.Fatal("concurrent counters/log bound")
	}
}
