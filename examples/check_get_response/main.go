package main

import (
	"log"
	"net/http"

	"github.com/addigy/go-sct"
)

func main() {
	url := "https://www.certificate-transparency.org"
	// Known to return SCTs in TLS extensions.
	// url := "https://ritter.vg"

	resp, err := http.Get(url)
	if err != nil {
		log.Fatalf("get failed for %s: %v", url, err)
	}

	err = sct.CheckConnectionState(resp.TLS, sct.CheckerConfig{
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
