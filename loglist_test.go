package sct

import "testing"

var (
	testLogListPath       = "testdata/log_list.json"
	testLogListSigPath    = "testdata/log_list.sig"
	testLogListPubKeyPath = "testdata/log_list_pubkey.pem"
)

func TestNewLogListSigned(t *testing.T) {
	jsonData := getValidCacheOrLatest(testLogListPath, "", logCacheDuration)
	sigData := getValidCacheOrLatest(testLogListSigPath, "", logCacheDuration)
	pemData := getValidCacheOrLatest(testLogListPubKeyPath, "", logCacheDuration)
	ll := newLogListFromSources(jsonData, sigData, pemData)
	if ll == nil {
		t.Fatal("returned log list is nil")
	}
}
