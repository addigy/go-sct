package main

import (
	"github.com/addigy/go-sct"
	"log"
	"net/http"
	"time"
)

func main() {
	// Known to return SCTs in TLS extensions.
	// url := "https://ritter.vg"

	client := &http.Client{
		Transport: sct.NewTransport(sct.TransportConfig{
			UserAgent: "go-sct-example",
			CacheCTLogListFilePath:       "/tmp/log_list.json",
			CacheCTLogListSigFilePath:    "/tmp/log_list.sig",
			CacheCTLogListPubKeyFilePath: "/tmp/log_list_pubkey.pem",
			CacheValidSCTFilePath:        "/tmp/valid_scts_cache",
		}),
	}

	for start := time.Now(); time.Since(start) < time.Second * 30; {
		for _, url := range []string{"https://app-prod.addigy.com", "https://prod.addigy.com/login", "https://www.facebook.com/", "https://ritter.vg"} {
			start := time.Now()
			_, err := client.Get(url)
			if err != nil {
				log.Fatalf("get failed for %s: %v", url, err)
			}

			log.Printf("ellapsed: %v ms", time.Now().Sub(start).Milliseconds())
		}

		time.Sleep(time.Second * 5)
	}
}
