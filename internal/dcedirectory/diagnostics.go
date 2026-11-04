package dcedirectory

import (
	"fmt"
	"io"
	"math"
	"strings"
	"sync"
)

// DiagnosticStage is a fixed code, never text obtained from a request/error.
type DiagnosticStage uint8

const (
	DiagAdvertisementJSON DiagnosticStage = iota
	DiagAdvertisementNames
	DiagAdvertisementPresence
	DiagAdvertisementProtocol
	DiagAdvertisementFamily
	DiagAdvertisementNetwork
	DiagAdvertisementMode
	DiagAdvertisementScore
	DiagAdvertisementPlayers
	DiagAdvertisementSequence
	DiagAdvertisementName
	DiagAdvertisementInstance
	DiagAdvertisementPort
	DiagAdvertisementTime
	DiagAdvertisementID
	DiagCandidate
	DiagPublishOwner
	DiagPublishSequence
	DiagPublishQuota
	DiagPublishRandom
	DiagTicketAccepted
	DiagProbeScheduled
	DiagProbeSendOK
	DiagProbeSendFailed
	DiagAckFormat
	DiagAckAddress
	DiagAckTicket
	DiagAckExpired
	DiagAckUnsent
	DiagAckSource
	DiagAckNonce
	DiagAckRate
	DiagAckSignature
	DiagAckAccepted
	DiagnosticStageCount
)

var diagnosticLabels = [DiagnosticStageCount]string{
	"advertisement_json", "advertisement_field_names", "advertisement_field_presence",
	"advertisement_protocol", "advertisement_family", "advertisement_network_version",
	"advertisement_mode", "advertisement_score", "advertisement_players_capacity",
	"advertisement_sequence", "advertisement_name", "advertisement_instance", "advertisement_game_port",
	"advertisement_time", "advertisement_id", "candidate_address", "publish_owner", "publish_sequence",
	"publish_quota", "publish_random", "ticket_accepted", "probe_scheduled", "probe_send_ok", "probe_send_failed",
	"ack_format", "ack_address", "ack_ticket", "ack_expired", "ack_unsent", "ack_source", "ack_nonce", "ack_rate",
	"ack_signature", "ack_accepted",
}

const DiagnosticLogLimit = 8

// PublishDiagnostics holds only fixed saturating counters. It retains no
// request data and emits at most8 fixed-label lines for the entire process.
// A nil *PublishDiagnostics is the default and does no work or allocation.
type PublishDiagnostics struct {
	mu      sync.Mutex
	counts  [DiagnosticStageCount]uint64
	emitted uint8
	writer  io.Writer
}

func NewPublishDiagnostics(writer io.Writer) *PublishDiagnostics {
	return &PublishDiagnostics{writer: writer}
}

func (d *PublishDiagnostics) record(stage DiagnosticStage) {
	if d == nil || stage >= DiagnosticStageCount {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.counts[stage] < math.MaxUint64 {
		d.counts[stage]++
	}
	if d.writer != nil && d.emitted < DiagnosticLogLimit {
		d.emitted++
		// Never interpolate an error, identifier, address, body or packet here.
		_, _ = fmt.Fprintf(d.writer, "dce_publish_diag stage=%s count=%d event=%d/%d\n", diagnosticLabels[stage], d.counts[stage], d.emitted, DiagnosticLogLimit)
	}
}

func (d *PublishDiagnostics) Snapshot() [DiagnosticStageCount]uint64 {
	if d == nil {
		return [DiagnosticStageCount]uint64{}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.counts
}

// NoteProbeSend accepts a boolean only: socket error text may contain endpoints.
func (s *Server) NoteProbeSend(ok bool) {
	if ok {
		s.diagnostics.record(DiagProbeSendOK)
	} else {
		s.diagnostics.record(DiagProbeSendFailed)
	}
}

// Classify only after the unchanged validator refuses a publication. Error
// text is compared to internal constants and is never retained or logged.
func advertisementDiagnostic(advert Advertisement, err error) DiagnosticStage {
	switch err.Error() {
	case "duplicate field", "noncanonical field":
		return DiagAdvertisementNames
	case "missing fields", "null field":
		return DiagAdvertisementPresence
	case "invalid fields":
		switch {
		case advert.Protocol != Protocol:
			return DiagAdvertisementProtocol
		case advert.Family != Family:
			return DiagAdvertisementFamily
		case advert.NetworkVersion != NetworkVersion:
			return DiagAdvertisementNetwork
		case advert.Mode > 1:
			return DiagAdvertisementMode
		case advert.Score != 10 && advert.Score != 15 && advert.Score != 25 && advert.Score != 50:
			return DiagAdvertisementScore
		case advert.Capacity != 2 || advert.Players < 1 || advert.Players > advert.Capacity:
			return DiagAdvertisementPlayers
		case advert.Sequence == 0:
			return DiagAdvertisementSequence
		case len(advert.Name) < 1 || len(advert.Name) > 32 || strings.TrimSpace(advert.Name) != advert.Name:
			return DiagAdvertisementName
		}
		for _, b := range []byte(advert.Name) {
			if b < 32 || b > 126 {
				return DiagAdvertisementName
			}
		}
		if len(advert.Instance) != 16 || !lowerHex(advert.Instance, 8) {
			return DiagAdvertisementInstance
		}
		if advert.GamePort < 1024 {
			return DiagAdvertisementPort
		}
		return DiagAdvertisementTime
	default:
		return DiagAdvertisementJSON
	}
}
