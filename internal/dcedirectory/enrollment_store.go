package dcedirectory

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sync"

	"github.com/OpenCommunityEdition/opence-master-server/internal/sign"
)

const MaxApprovedKeys = 1024

type Approval struct {
	PublicKey   string `json:"public_key"`
	CandidateIP string `json:"candidate_ip,omitempty"`
}

// ReadApprovalFile reads public metadata only. The file remains operator owned.
func ReadApprovalFile(path string) ([]Approval, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 256*1024+1))
	if err != nil || len(data) > 256*1024 {
		return nil, errors.New("approval file size")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var entries []Approval
	if err := decoder.Decode(&entries); err != nil {
		return nil, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, errors.New("trailing approval data")
	}
	if len(entries) > MaxApprovedKeys {
		return nil, errors.New("approval capacity")
	}
	seen := map[string]bool{}
	for _, entry := range entries {
		public, err := sign.ParsePublicKey(entry.PublicKey)
		if err != nil || sign.PublicKeyText(public) != entry.PublicKey {
			return nil, errors.New("invalid approved public key")
		}
		id := sign.KeyID(public)
		if seen[id] {
			return nil, errors.New("duplicate or colliding approved key")
		}
		seen[id] = true
		if entry.CandidateIP != "" {
			address, err := netip.ParseAddr(entry.CandidateIP)
			if err != nil || !address.Is4() {
				return nil, errors.New("candidate override must be IPv4")
			}
		}
	}
	return entries, nil
}

// ApprovalFile serializes writers in this process and uses an exclusive lock
// file across processes. A stale lock after a crash fails closed for operator
// recovery. No credential or private seed is accepted or persisted here.
type ApprovalFile struct {
	Path string
	mu   sync.Mutex
}

func (a *ApprovalFile) add(public ed25519.PublicKey, candidate netip.Addr) (Approval, bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	lock, err := os.OpenFile(a.Path+".enrollment-lock", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return Approval{}, false, errors.New("approval update locked")
	}
	defer func() { lock.Close(); os.Remove(a.Path + ".enrollment-lock") }()
	entries, err := ReadApprovalFile(a.Path)
	if err != nil {
		return Approval{}, false, errors.New("cannot read approval state")
	}
	keyID := sign.KeyID(public)
	for _, entry := range entries {
		old, _ := sign.ParsePublicKey(entry.PublicKey)
		if sign.KeyID(old) == keyID {
			if !bytes.Equal(old, public) {
				return Approval{}, false, errors.New("key id collision")
			}
			return entry, false, nil
		}
	}
	if len(entries) >= MaxApprovedKeys {
		return Approval{}, false, errors.New("approval capacity")
	}
	entry := Approval{PublicKey: sign.PublicKeyText(public)}
	if candidate.IsValid() {
		entry.CandidateIP = candidate.String()
	}
	entries = append(entries, entry)
	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return Approval{}, false, err
	}
	data = append(data, '\n')
	temp, err := os.CreateTemp(filepath.Dir(a.Path), ".dce-approval-*.tmp")
	if err != nil {
		return Approval{}, false, errors.New("cannot create approval update")
	}
	name := temp.Name()
	defer os.Remove(name)
	if _, err := temp.Write(data); err != nil {
		temp.Close()
		return Approval{}, false, errors.New("cannot write approval update")
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return Approval{}, false, errors.New("cannot sync approval update")
	}
	if err := temp.Close(); err != nil {
		return Approval{}, false, errors.New("cannot close approval update")
	}
	if err := replaceApprovalFile(name, a.Path); err != nil {
		return Approval{}, false, errors.New("cannot commit approval update")
	}
	readback, err := os.ReadFile(a.Path)
	if err != nil || !bytes.Equal(readback, data) {
		return Approval{}, false, errors.New("approval readback failed")
	}
	return entry, true, nil
}

// enroll persists and verifies the approval before publishing it to concurrent
// game requests. Holding mu also prevents inconsistent key/override snapshots.
func (s *Server) enroll(file *ApprovalFile, public ed25519.PublicKey, candidate netip.Addr) (bool, error) {
	if len(public) != ed25519.PublicKeySize || sign.SmallOrder(public) {
		return false, errors.New("invalid public key")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	id := sign.KeyID(public)
	if old := s.approved[id]; old != nil && !bytes.Equal(old, public) {
		return false, errors.New("key id collision")
	}
	if s.approved[id] == nil && len(s.approved) >= MaxApprovedKeys {
		return false, errors.New("approval capacity")
	}
	if candidate.IsValid() && !s.allowedEndpoint(candidate) {
		return false, errors.New("candidate policy")
	}
	entry, created, err := file.add(public, candidate)
	if err != nil {
		return false, err
	}
	var storedCandidate netip.Addr
	if entry.CandidateIP != "" {
		storedCandidate, err = netip.ParseAddr(entry.CandidateIP)
		if err != nil || !s.allowedEndpoint(storedCandidate) {
			return false, errors.New("stored candidate policy")
		}
	}
	s.approved[id] = append(ed25519.PublicKey(nil), public...)
	if storedCandidate.IsValid() {
		s.candidateOverrides[id] = storedCandidate
	}
	return created, nil
}
