// dce-directory is an isolated DCE_NET3 extension. It never opens the native
// master's database and never registers handlers on the native HTTP server.
package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/OpenCommunityEdition/opence-master-server/internal/dcedirectory"
	"github.com/OpenCommunityEdition/opence-master-server/internal/httpx"
	"github.com/OpenCommunityEdition/opence-master-server/internal/sign"
	"github.com/OpenCommunityEdition/opence-master-server/internal/store"
)

type approval = dcedirectory.Approval

// bindState refuses an existing unmarked database and a changed signing key.
// The small adjacent marker also keeps accidental native-state reuse from
// opening or migrating the native master's database at all.
func bindState(path, keyID string) error {
	if path == ":memory:" {
		return errors.New("DCE nonce database must be durable")
	}
	marker := path + ".dce-identity"
	data, err := os.ReadFile(marker)
	if err == nil {
		if string(data) != "dce-directory-v1\n"+keyID+"\n" {
			return errors.New("DCE database identity differs; restore its original key")
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return errors.New("cannot read DCE database identity")
	}
	if _, err := os.Stat(path); err == nil || !errors.Is(err, os.ErrNotExist) {
		return errors.New("refusing existing database without DCE identity marker; use separate new DCE state")
	}
	file, err := os.OpenFile(marker, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errors.New("cannot create DCE database identity marker")
	}
	_, writeErr := io.WriteString(file, "dce-directory-v1\n"+keyID+"\n")
	closeErr := file.Close()
	return errors.Join(writeErr, closeErr)
}

func approvals(path string) ([]ed25519.PublicKey, map[string]netip.Addr, map[string]bool, error) {
	entries, err := dcedirectory.ReadApprovalFile(path)
	if err != nil {
		return nil, nil, nil, err
	}
	publicKeys := map[string]bool{}
	keys := make([]ed25519.PublicKey, 0, len(entries))
	overrides := map[string]netip.Addr{}
	seen := map[string]bool{}
	for _, entry := range entries {
		public, err := sign.ParsePublicKey(entry.PublicKey)
		if err != nil {
			return nil, nil, nil, errors.New("invalid approved public key")
		}
		id := sign.KeyID(public)
		if seen[id] {
			return nil, nil, nil, errors.New("duplicate approved key")
		}
		seen[id] = true
		keys = append(keys, public)
		if entry.Public {
			publicKeys[id] = true
		}
		if entry.CandidateIP != "" {
			address, err := netip.ParseAddr(entry.CandidateIP)
			if err != nil || !address.Is4() {
				return nil, nil, nil, errors.New("candidate override must be IPv4")
			}
			overrides[id] = address
		}
	}
	return keys, overrides, publicKeys, nil
}

func readEnrollmentToken(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", errors.New("cannot open enrollment token file")
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 257))
	if err != nil || len(data) > 256 {
		return "", errors.New("invalid enrollment token file")
	}
	return strings.TrimSpace(string(data)), nil
}

func prefixes(text string) ([]netip.Prefix, error) {
	var result []netip.Prefix
	for _, item := range strings.Split(text, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if ip, err := netip.ParseAddr(item); err == nil {
			result = append(result, netip.PrefixFrom(ip, ip.BitLen()))
			continue
		}
		prefix, err := netip.ParsePrefix(item)
		if err != nil {
			return nil, err
		}
		result = append(result, prefix.Masked())
	}
	return result, nil
}

func run(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("dce-directory", flag.ContinueOnError)
	keyPath := flags.String("key", "", "separate existing master key file; never the native master key")
	dbPath := flags.String("db", "", "separate durable nonce SQLite database")
	approvalPath := flags.String("approvals", "", "local approved public-key JSON file")
	listen := flags.String("listen", "127.0.0.1:18095", "HTTP address behind a trusted HTTPS proxy")
	udpListen := flags.String("udp-listen", "0.0.0.0:0", "outbound probe socket, also receives its replies")
	proxyText := flags.String("trusted-proxies", "", "exact proxy IPs or CIDRs, comma separated")
	lanText := flags.String("allow-private-lan-cidr", "", "explicit reviewed RFC1918 test subnet(s)")
	loopback := flags.Bool("allow-loopback", false, "allow loopback game endpoints for local tests only")
	publishDiagnostics := flags.Bool("publish-diagnostics", false, "fixed publication counters; at most8 secret-free stderr events")
	enrollmentListen := flags.String("enrollment-listen", "", "optional literal loopback operator listener; disabled by default")
	enrollmentToken := flags.String("enrollment-token-file", "", "protected gateway operator token file, never a command-line secret")
	enrollmentCandidate := flags.String("enrollment-candidate-ip", "", "operator-only candidate override for newly enrolled keys")
	relayControl := flags.String("relay-control", "", "literal loopback http base of the relay control port; off when empty")
	relayKeyFile := flags.String("relay-key-file", "", "protected relay control key file")
	relayPublic := flags.String("relay-public-ip", "", "relay public IPv4 named in signed replies")
	relayHello := flags.Uint("relay-hello-port", 5400, "relay port hosts send their outbound hello to")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *keyPath == "" || *dbPath == "" || *approvalPath == "" {
		return errors.New("set --key, --db and --approvals to separate DCE state files")
	}
	if *enrollmentListen != "" {
		if _, err := dcedirectory.ValidateEnrollmentListen(*enrollmentListen); err != nil {
			return err
		}
		if *enrollmentToken == "" {
			return errors.New("enrollment requires a protected operator token file")
		}
	} else if *enrollmentToken != "" || *enrollmentCandidate != "" {
		return errors.New("enrollment listener is disabled")
	}
	absKey, err := filepath.Abs(*keyPath)
	if err != nil {
		return errors.New("master key must be an existing file")
	}
	info, err := os.Stat(absKey)
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("master key must be an existing file")
	}
	private, err := sign.LoadSeed(absKey)
	if err != nil {
		return errors.New("cannot load DCE master key; supply an existing key file")
	}
	keys, overrides, publicKeys, err := approvals(*approvalPath)
	if err != nil {
		return fmt.Errorf("approval file: %w", err)
	}
	proxies, err := prefixes(*proxyText)
	if err != nil {
		return errors.New("invalid trusted proxy")
	}
	lan, err := prefixes(*lanText)
	if err != nil {
		return errors.New("invalid LAN subnet")
	}
	if err := bindState(*dbPath, sign.KeyID(private.Public().(ed25519.PublicKey))); err != nil {
		return err
	}
	db, err := store.Open(*dbPath)
	if err != nil {
		return errors.New("cannot open separate DCE nonce database")
	}
	defer db.Close()
	var diagnostics *dcedirectory.PublishDiagnostics
	if *publishDiagnostics {
		diagnostics = dcedirectory.NewPublishDiagnostics(os.Stderr)
	}
	var relay *dcedirectory.RelayConfig
	if *relayControl != "" {
		if !strings.HasPrefix(*relayControl, "http://127.0.0.1:") || *relayHello < 1024 || *relayHello > 65535 {
			return errors.New("invalid relay control or hello port")
		}
		address, err := netip.ParseAddr(*relayPublic)
		if err != nil || !address.Is4() {
			return errors.New("relay public address must be literal IPv4")
		}
		keyBytes, err := os.ReadFile(*relayKeyFile)
		if err != nil || len(strings.TrimSpace(string(keyBytes))) < 32 {
			return errors.New("relay key file unavailable")
		}
		relay = &dcedirectory.RelayConfig{Control: *relayControl, Key: strings.TrimSpace(string(keyBytes)), Public: address, HelloPort: uint16(*relayHello)}
	}
	service, err := dcedirectory.New(dcedirectory.Config{Relay: relay, Key: private, Approved: keys, PublicKeys: publicKeys, Nonces: db,
		CandidateOverrides: overrides, Clients: httpx.Clients{Proxies: proxies}, AllowLoopback: *loopback, AllowPrivateLAN: lan, Diagnostics: diagnostics})
	if err != nil {
		return err
	}
	var operator *http.Server
	var operatorListener net.Listener
	if *enrollmentListen != "" {
		token, err := readEnrollmentToken(*enrollmentToken)
		if err != nil {
			return err
		}
		var candidate netip.Addr
		if *enrollmentCandidate != "" {
			candidate, err = netip.ParseAddr(*enrollmentCandidate)
			if err != nil || !candidate.Is4() {
				return errors.New("enrollment candidate must be literal IPv4")
			}
		}
		handler, err := dcedirectory.NewEnrollment(service, dcedirectory.EnrollmentConfig{Token: token,
			Approvals: &dcedirectory.ApprovalFile{Path: *approvalPath}, CandidateIP: candidate})
		if err != nil {
			return err
		}
		operatorListener, err = net.Listen("tcp", *enrollmentListen)
		if err != nil {
			return err
		}
		defer operatorListener.Close()
		operator = &http.Server{Handler: handler, ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 10 * time.Second, MaxHeaderBytes: 4096}
		defer operator.Close()
	}
	udpAddress, err := net.ResolveUDPAddr("udp4", *udpListen)
	if err != nil {
		return err
	}
	udp, err := net.ListenUDP("udp4", udpAddress)
	if err != nil {
		return err
	}
	defer udp.Close()
	tcp, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	defer tcp.Close()
	server := &http.Server{Handler: service, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192}
	errorsCh := make(chan error, 3)
	go func() { errorsCh <- server.Serve(tcp) }()
	if operator != nil {
		go func() { errorsCh <- operator.Serve(operatorListener) }()
	}
	go func() {
		// One extra byte detects oversize datagrams without parsing truncated data.
		buffer := make([]byte, dcedirectory.PacketSize+1)
		for {
			n, source, err := udp.ReadFromUDPAddrPort(buffer)
			if err != nil {
				errorsCh <- err
				return
			}
			service.AcceptAck(buffer[:n], source)
		}
	}()
	fmt.Printf("DCE directory listening on %s; outbound UDP %s; key_id=%s\n", tcp.Addr(), udp.LocalAddr(), service.KeyID())
	probeTick := time.NewTicker(200 * time.Millisecond)
	defer probeTick.Stop()
	purgeTick := time.NewTicker(time.Minute)
	defer purgeTick.Stop()
	for {
		select {
		case <-ctx.Done():
			shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if operator != nil {
				if err := operator.Shutdown(shutdown); err != nil {
					return err
				}
			}
			return server.Shutdown(shutdown)
		case err := <-errorsCh:
			_ = server.Close()
			if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		case <-probeTick.C:
			for _, probe := range service.NextProbes() {
				// Failed UDP writes leave no visible row; the bounded next attempt may recover.
				n, err := udp.WriteToUDPAddrPort(probe.Packet, probe.Destination)
				service.NoteProbeSend(err == nil && n == len(probe.Packet))
			}
		case <-purgeTick.C:
			if err := db.Purge(sign.NonceWindow, 24*time.Hour); err != nil {
				_ = server.Close()
				return errors.New("nonce database maintenance failed")
			}
		}
	}
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil {
		log.Fatal(err)
	}
}
