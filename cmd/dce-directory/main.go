// dce-directory is an isolated DCE_NET3 extension. It never opens the native
// master's database and never registers handlers on the native HTTP server.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
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

type approval struct {
	PublicKey   string `json:"public_key"`
	CandidateIP string `json:"candidate_ip,omitempty"`
}

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

func approvals(path string) ([]ed25519.PublicKey, map[string]netip.Addr, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, 256*1024))
	decoder.DisallowUnknownFields()
	var entries []approval
	if err := decoder.Decode(&entries); err != nil {
		return nil, nil, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, nil, errors.New("trailing approval data")
	}
	if len(entries) > 1024 {
		return nil, nil, errors.New("too many approved keys")
	}
	keys := make([]ed25519.PublicKey, 0, len(entries))
	overrides := map[string]netip.Addr{}
	seen := map[string]bool{}
	for _, entry := range entries {
		public, err := sign.ParsePublicKey(entry.PublicKey)
		if err != nil {
			return nil, nil, errors.New("invalid approved public key")
		}
		id := sign.KeyID(public)
		if seen[id] {
			return nil, nil, errors.New("duplicate approved key")
		}
		seen[id] = true
		keys = append(keys, public)
		if entry.CandidateIP != "" {
			address, err := netip.ParseAddr(entry.CandidateIP)
			if err != nil || !address.Is4() {
				return nil, nil, errors.New("candidate override must be IPv4")
			}
			overrides[id] = address
		}
	}
	return keys, overrides, nil
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
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *keyPath == "" || *dbPath == "" || *approvalPath == "" {
		return errors.New("set --key, --db and --approvals to separate DCE state files")
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
	keys, overrides, err := approvals(*approvalPath)
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
	service, err := dcedirectory.New(dcedirectory.Config{Key: private, Approved: keys, Nonces: db,
		CandidateOverrides: overrides, Clients: httpx.Clients{Proxies: proxies}, AllowLoopback: *loopback, AllowPrivateLAN: lan})
	if err != nil {
		return err
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
	errorsCh := make(chan error, 2)
	go func() { errorsCh <- server.Serve(tcp) }()
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
				_, _ = udp.WriteToUDPAddrPort(probe.Packet, probe.Destination)
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
