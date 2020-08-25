package main

import (
	"crypto/tls"
	"log"

	"github.com/addigy/go-sct"
)

func main() {
	host := "www.certificate-transparency.org:443"
	// Known to return SCTs in TLS extensions.
	// host := "ritter.vg:443"

	conn, err := tls.Dial("tcp", host, &tls.Config{})
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	err = sct.CheckConnectionState(&state, sct.CheckerConfig{
		CacheCTLogListFilePath:       "/tmp/log_list.json",
		CacheCTLogListSigFilePath:    "/tmp/log_list.sig",
		CacheCTLogListPubKeyFilePath: "/tmp/log_list_pubkey.pem",
		CacheValidSCTFilePath:        "/tmp/valid_scts_cache",
	})
	if err != nil {
		log.Fatalf("failed SCT check: %v", err)
	}

	log.Printf("OK")
}
