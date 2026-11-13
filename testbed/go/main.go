// Minimal Go crypto/tls server for the QuantaSeek testbed.
//
// Usage: goserver -addr :4443 -cert leaf+chain.pem -key leaf.key -groups X25519MLKEM768
// Group names are Go's tls.CurveID constant names.
package main

import (
	"crypto/tls"
	"flag"
	"log"
	"net/http"
	"strings"
)

var curves = map[string]tls.CurveID{
	"X25519":             tls.X25519,
	"P256":               tls.CurveP256,
	"P384":               tls.CurveP384,
	"X25519MLKEM768":     tls.X25519MLKEM768,
	"SecP256r1MLKEM768":  tls.SecP256r1MLKEM768,
	"SecP384r1MLKEM1024": tls.SecP384r1MLKEM1024,
}

func main() {
	addr := flag.String("addr", ":4443", "listen address")
	certFile := flag.String("cert", "", "PEM certificate chain, leaf first")
	keyFile := flag.String("key", "", "PEM private key")
	groups := flag.String("groups", "", "colon-separated CurveID names")
	flag.Parse()

	var prefs []tls.CurveID
	for _, name := range strings.Split(*groups, ":") {
		id, ok := curves[name]
		if !ok {
			log.Fatalf("unknown group %q", name)
		}
		prefs = append(prefs, id)
	}
	server := &http.Server{
		Addr: *addr,
		TLSConfig: &tls.Config{
			MinVersion:       tls.VersionTLS13,
			CurvePreferences: prefs,
		},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("quantaseek testbed\n"))
		}),
	}
	log.Fatal(server.ListenAndServeTLS(*certFile, *keyFile))
}
