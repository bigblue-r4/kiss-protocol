// Command harborlight-cf-adapter receives Cloudflare Logpush HTTP-destination
// uploads into the pilot's NDJSON feed (serve), and generates synthetic
// ai_gateway_events uploads for demonstrations and tests (synth).
//
// The adapter is a sink: it needs no Cloudflare credential and makes no
// request to Cloudflare.
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

	"github.com/bigblue-r4/kiss-protocol/internal/pilot/cfadapter"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

const usageText = `usage:
  harborlight-cf-adapter serve --feed FILE --token-file FILE [--listen :8443]
                               [--tls-cert FILE --tls-key FILE] [--dataset NAME]
      Accept Logpush uploads (POST, Authorization: Bearer TOKEN; in the
      Logpush destination use header_Authorization=Bearer%20TOKEN).
  harborlight-cf-adapter synth --url URL --token-file FILE [--events 1000]
                               [--batch 500] [--interval 0s] [--seed 1]
                               [--redeliver-batch N]
      Post synthetic ai_gateway_events uploads to an adapter.
`

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usageText)
		return 2
	}
	switch args[0] {
	case "serve":
		return serve(args[1:], stderr)
	case "synth":
		return synth(args[1:], stdout, stderr)
	}
	fmt.Fprint(stderr, usageText)
	return 2
}

func readToken(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	t := strings.TrimSpace(string(b))
	if len(t) < 16 {
		return "", errors.New("token must be at least 16 characters")
	}
	return t, nil
}

func serve(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	listen := fs.String("listen", ":8443", "listen address")
	feed := fs.String("feed", "", "NDJSON feed file to append to")
	tokenFile := fs.String("token-file", "", "file holding the bearer token")
	cert := fs.String("tls-cert", "", "TLS certificate (Logpush requires HTTPS with a trusted certificate)")
	key := fs.String("tls-key", "", "TLS key")
	dataset := fs.String("dataset", "ai_gateway_events", "dataset name when the request has no ?dataset=")
	if fs.Parse(args) != nil || *feed == "" || *tokenFile == "" {
		fmt.Fprint(stderr, usageText)
		return 2
	}
	lg := log.New(stderr, "harborlight-cf-adapter: ", log.LstdFlags|log.LUTC)
	tok, err := readToken(*tokenFile)
	if err != nil {
		lg.Print("token: ", err)
		return 2
	}
	h := &cfadapter.Handler{Feed: *feed, Token: tok, Dataset: *dataset}
	srv := &http.Server{Addr: *listen, Handler: h, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 5 * time.Minute}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	if *cert != "" {
		err = srv.ListenAndServeTLS(*cert, *key)
	} else {
		lg.Print("serving plain HTTP: fine inside the demo network; Cloudflare Logpush itself needs HTTPS with a trusted certificate in front")
		err = srv.ListenAndServe()
	}
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		lg.Print(err)
		return 1
	}
	return 0
}

func synth(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("synth", flag.ContinueOnError)
	fs.SetOutput(stderr)
	o := cfadapter.SynthOptions{}
	fs.StringVar(&o.URL, "url", "", "adapter URL")
	tokenFile := fs.String("token-file", "", "file holding the bearer token")
	fs.IntVar(&o.Events, "events", 1000, "records to send")
	fs.IntVar(&o.BatchSize, "batch", 500, "records per upload")
	fs.DurationVar(&o.Interval, "interval", 0, "pause between uploads")
	fs.Uint64Var(&o.Seed, "seed", 1, "random seed (same seed, same records)")
	fs.IntVar(&o.RedeliverBatch, "redeliver-batch", 0, "send this batch twice (fault injection)")
	if fs.Parse(args) != nil || o.URL == "" || *tokenFile == "" {
		fmt.Fprint(stderr, usageText)
		return 2
	}
	tok, err := readToken(*tokenFile)
	if err != nil {
		fmt.Fprintln(stderr, "token:", err)
		return 2
	}
	o.Token = tok
	if err := cfadapter.Synth(context.Background(), o, stdout); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}
