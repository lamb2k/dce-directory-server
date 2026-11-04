package dcedirectory

import (
	"bytes"
	"crypto/ed25519"
	"crypto/subtle"
	"net/netip"
	"sort"
	"time"

	"github.com/OpenCommunityEdition/opence-master-server/internal/netaddr"
)

const (
	PacketSize         = 121
	PacketMagic        = "DCEDIR1\x00"
	PacketDomain       = "DCE-Directory-UDP-v1\n"
	KindChallenge byte = 2
	KindAck       byte = 3
)

// PacketMessage is shared by client fixture tests. The final signature covers
// the domain, pinned master's raw key id and the exact first57 packet bytes.
func PacketMessage(master [8]byte, packet []byte) []byte {
	if len(packet) != PacketSize {
		return nil
	}
	message := make([]byte, 0, len(PacketDomain)+8+57)
	message = append(message, PacketDomain...)
	message = append(message, master[:]...)
	return append(message, packet[:57]...)
}

func SignPacket(private ed25519.PrivateKey, master [8]byte, kind byte, ticket [16]byte, nonce [32]byte) []byte {
	packet := make([]byte, PacketSize)
	copy(packet, PacketMagic)
	packet[8] = kind
	copy(packet[9:25], ticket[:])
	copy(packet[25:57], nonce[:])
	copy(packet[57:], ed25519.Sign(private, PacketMessage(master, packet)))
	return packet
}

func VerifyPacket(public ed25519.PublicKey, master [8]byte, packet []byte, kind byte) bool {
	return len(public) == ed25519.PublicKeySize && len(packet) == PacketSize && bytes.Equal(packet[:8], []byte(PacketMagic)) && packet[8] == kind &&
		ed25519.Verify(public, PacketMessage(master, packet), packet[57:])
}

func (s *Server) allowedEndpoint(address netip.Addr) bool {
	address = address.Unmap()
	if !address.Is4() {
		return false
	}
	if netaddr.Global(address) {
		return true
	}
	if s.allowLoopback && address.IsLoopback() {
		return true
	}
	for _, prefix := range s.allowPrivateLAN {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

// Probe is one outbound packet to a constrained candidate, scheduled by a
// signed approved PUT. No inbound UDP ever schedules a probe or a response.
type Probe struct {
	Destination netip.AddrPort
	Packet      []byte
}

// NextProbes schedules up to3 identical probes per ticket, at least2 seconds
// apart. The caller sends them through the same UDP socket that reads ACKs.
func (s *Server) NextProbes() []Probe {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweep(now)
	ids := make([]string, 0, len(s.records))
	for id := range s.records {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	result := []Probe{}
	for _, id := range ids {
		rec := s.records[id]
		if s.tickets[rec.ticket] != id || !now.Before(rec.ticketExpires) || rec.replies >= 3 ||
			(rec.replies != 0 && now.Sub(rec.lastReply) < 2*time.Second) {
			continue
		}
		if ok, _ := s.udpGlobal.Allow("all"); !ok {
			break
		}
		if ok, _ := s.udpSources.Allow(rec.source.Addr().String()); !ok {
			continue
		}
		if ok, _ := s.udpKeys.Allow(rec.keyID); !ok {
			continue
		}
		rec.lastReply = now
		rec.replies++
		s.diagnostics.record(DiagProbeScheduled)
		result = append(result, Probe{rec.source, append([]byte(nil), rec.challenge...)})
	}
	return result
}

// AcceptAck never sends a packet. It binds a host's signature to the current
// nonce and exact observed UDP source, which must equal the constrained
// candidate. This is the only path that makes a listing visible.
func (s *Server) AcceptAck(packet []byte, source netip.AddrPort) bool {
	if len(packet) != PacketSize || !bytes.Equal(packet[:8], []byte(PacketMagic)) || packet[8] != KindAck {
		s.diagnostics.record(DiagAckFormat)
		return false
	}
	if !s.allowedEndpoint(source.Addr()) {
		s.diagnostics.record(DiagAckAddress)
		return false
	}
	source = netip.AddrPortFrom(source.Addr().Unmap(), source.Port())
	var ticket [16]byte
	copy(ticket[:], packet[9:25])
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	id, exists := s.tickets[ticket]
	if !exists {
		s.diagnostics.record(DiagAckTicket)
		return false
	}
	rec := s.records[id]
	if rec == nil {
		s.diagnostics.record(DiagAckTicket)
		return false
	}
	if !now.Before(rec.ticketExpires) {
		s.diagnostics.record(DiagAckExpired)
		return false
	}
	if rec.replies == 0 {
		s.diagnostics.record(DiagAckUnsent)
		return false
	}
	if source != rec.source {
		s.diagnostics.record(DiagAckSource)
		return false
	}
	if subtle.ConstantTimeCompare(packet[25:57], rec.nonce[:]) != 1 {
		s.diagnostics.record(DiagAckNonce)
		return false
	}
	if ok, _ := s.ackGlobal.Allow("all"); !ok {
		s.diagnostics.record(DiagAckRate)
		return false
	}
	if ok, _ := s.ackSources.Allow(source.Addr().String()); !ok {
		s.diagnostics.record(DiagAckRate)
		return false
	}
	public := s.approved[rec.keyID]
	if public == nil || !VerifyPacket(public, s.keyIDRaw, packet, KindAck) {
		s.diagnostics.record(DiagAckSignature)
		return false
	}
	rec.verified = &Entry{ID: id, KeyID: rec.keyID, Advertisement: rec.advert,
		Endpoint: Endpoint{source.Addr().String(), source.Port()}, Updated: now.Unix(),
		Expires: now.Add(TTL).Unix(), Reachable: true}
	delete(s.tickets, ticket)
	s.diagnostics.record(DiagAckAccepted)
	return true
}
