// Command harborlight-log runs the pilot evidence log: it ingests an NDJSON
// feed into an RFC 6962 SHA-256 log of plaintext records, signs C2SP
// checkpoints, gets them cosigned by tlog-witness witnesses, and serves the
// public directory read-only.
//
// For synthetic or explicitly authorised non-sensitive data only: records
// are published in plaintext.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/bigblue-r4/kiss-protocol/internal/pilot/evlog"
	"github.com/bigblue-r4/kiss-protocol/pkg/checkpoint"
	"golang.org/x/mod/sumdb/note"
)

type multi []string

func (m *multi) String() string     { return strings.Join(*m, " ") }
func (m *multi) Set(s string) error { *m = append(*m, s); return nil }

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func usage(w io.Writer) {
	fmt.Fprint(w, `usage:
  harborlight-log keygen --origin NAME --out FILE
      Write a new log signing key to FILE (mode 0600) and its public
      verifier key to FILE.pub. NAME is the log origin, e.g. pilot.example/log.
  harborlight-log run --key FILE --data DIR --public DIR [--feed FILE]
                      [--witness 'VKEY,URL']... [--operator-witness NAME]...
                      [--interval 30s] [--listen ADDR] [--once]
      Ingest FILE, checkpoint every interval, serve DIR on ADDR.
`)
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	switch args[0] {
	case "keygen":
		return keygen(args[1:], stdout, stderr)
	case "run":
		return serve(args[1:], stderr)
	default:
		usage(stderr)
		return 2
	}
}

func keygen(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	fs.SetOutput(stderr)
	origin := fs.String("origin", "", "log origin")
	out := fs.String("out", "", "private key file")
	if fs.Parse(args) != nil || *origin == "" || *out == "" {
		usage(stderr)
		return 2
	}
	if err := checkpoint.ValidName(*origin); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	skey, vkey, err := note.GenerateKey(nil, *origin)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		fmt.Fprintln(stderr, "refusing to overwrite or create key:", err)
		return 1
	}
	if _, err := f.WriteString(skey + "\n"); err != nil {
		f.Close()
		fmt.Fprintln(stderr, err)
		return 1
	}
	if err := f.Close(); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if err := os.WriteFile(*out+".pub", []byte(vkey+"\n"), 0o644); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintln(stdout, vkey)
	return 0
}

// ParseWitness parses "VKEY,URL".
func parseWitness(s string) (evlog.Witness, error) {
	vkey, url, ok := strings.Cut(s, ",")
	if !ok || url == "" {
		return evlog.Witness{}, errors.New("--witness wants 'VKEY,URL'")
	}
	k, err := checkpoint.ParseCosignerKey(vkey)
	if err != nil {
		return evlog.Witness{}, err
	}
	return evlog.Witness{URL: url, Key: k}, nil
}

func serve(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	keyPath := fs.String("key", "", "log signing key file (from keygen)")
	data := fs.String("data", "", "private state directory")
	public := fs.String("public", "", "public directory")
	feed := fs.String("feed", "", "NDJSON feed to ingest")
	interval := fs.Duration("interval", 30*time.Second, "checkpoint interval")
	listen := fs.String("listen", "", "serve the public directory on this address")
	once := fs.Bool("once", false, "ingest and checkpoint once, then exit")
	var witnesses, operatorRun multi
	fs.Var(&witnesses, "witness", "'VKEY,URL' of a tlog-witness (repeatable)")
	fs.Var(&operatorRun, "operator-witness", "name of a witness run by this operator (disclosed; repeatable)")
	if fs.Parse(args) != nil || *keyPath == "" || *data == "" || *public == "" {
		usage(stderr)
		return 2
	}
	lg := log.New(stderr, "harborlight-log: ", log.LstdFlags|log.LUTC)
	skey, err := os.ReadFile(*keyPath)
	if err != nil {
		lg.Print(err)
		return 1
	}
	signer, err := note.NewSigner(strings.TrimSpace(string(skey)))
	if err != nil {
		lg.Print("key: ", err)
		return 1
	}
	vkey, err := verifierKey(*keyPath)
	if err != nil {
		lg.Print(err)
		return 1
	}
	cfg := evlog.Config{DataDir: *data, PublicDir: *public, Signer: signer, VerifierKey: vkey}
	opRun := map[string]bool{}
	for _, n := range operatorRun {
		opRun[n] = true
	}
	for _, s := range witnesses {
		w, err := parseWitness(s)
		if err != nil {
			lg.Print(err)
			return 2
		}
		w.OperatorControlled = opRun[w.Key.Name]
		cfg.Witnesses = append(cfg.Witnesses, w)
	}
	l, err := evlog.Open(cfg)
	if err != nil {
		lg.Print(err)
		return 1
	}
	defer l.Close()
	for _, r := range l.Recovery {
		lg.Print("RECOVERY: ", r)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if *listen != "" && !*once {
		srv := &http.Server{Addr: *listen, Handler: readOnly(http.FileServer(http.Dir(*public))), ReadHeaderTimeout: 10 * time.Second}
		go func() {
			if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				lg.Print("listen: ", err)
				stop()
			}
		}()
		defer srv.Close()
	}
	round := func() {
		if *feed != "" {
			n, err := l.Ingest(*feed)
			if err != nil {
				lg.Print("ingest: ", err)
			} else if n > 0 {
				lg.Printf("ingested %d record(s), size %d", n, l.Size())
			}
		}
		st, err := l.Checkpoint(ctx)
		if err != nil {
			lg.Print("checkpoint: ", err)
		}
		for _, w := range st {
			if !w.OK {
				lg.Printf("witness %s: %s", w.Name, w.Error)
			}
		}
	}
	round()
	if *once {
		return 0
	}
	t := time.NewTicker(*interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return 0
		case <-t.C:
			round()
		}
	}
}

func verifierKey(keyPath string) (string, error) {
	b, err := os.ReadFile(keyPath + ".pub")
	if err != nil {
		return "", fmt.Errorf("public key %s.pub: %w", keyPath, err)
	}
	return strings.TrimSpace(string(b)), nil
}

func readOnly(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "read only", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		h.ServeHTTP(w, r)
	})
}
