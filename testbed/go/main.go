// Go programs for the QuantaSeek testbed.
//
// TLS server:  goserver -addr :4443 -cert leaf+chain.pem -key leaf.key -groups X25519MLKEM768
//   Group names are Go's tls.CurveID constant names.
// Middlebox:   goserver -addr :4443 -proxy-to 127.0.0.1:4444 -max-first-record 1024
//   Forwards TCP to the backend, but closes any connection whose first TLS
//   record (the ClientHello) is a handshake record longer than the limit.
package main

import (
	"crypto/tls"
	"encoding/binary"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
)

func middlebox(addr, backend string, maxRecord int) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal(err)
	}
	for {
		client, err := ln.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go func(client net.Conn) {
			defer client.Close()
			header := make([]byte, 5)
			if _, err := io.ReadFull(client, header); err != nil {
				return
			}
			length := int(binary.BigEndian.Uint16(header[3:5]))
			if header[0] == 22 && length > maxRecord {
				log.Printf("closing: first record %d bytes > %d", length, maxRecord)
				return
			}
			server, err := net.Dial("tcp", backend)
			if err != nil {
				return
			}
			defer server.Close()
			if _, err := server.Write(header); err != nil {
				return
			}
			// When either direction ends, close both connections so the
			// backend (single-threaded s_server) is never left waiting.
			done := make(chan struct{}, 2)
			go func() { io.Copy(server, client); done <- struct{}{} }()
			go func() { io.Copy(client, server); done <- struct{}{} }()
			<-done
		}(client)
	}
}

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
	proxyTo := flag.String("proxy-to", "", "run as middlebox in front of this backend")
	maxFirstRecord := flag.Int("max-first-record", 1024, "middlebox: largest first record forwarded")
	flag.Parse()

	if *proxyTo != "" {
		middlebox(*addr, *proxyTo, *maxFirstRecord)
		return
	}

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
