package sct

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

	ct "github.com/google/certificate-transparency-go"
	ctclient "github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/ctutil"
	ctjsonclient "github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/loglist2"
	ctx509 "github.com/google/certificate-transparency-go/x509"
	ctx509util "github.com/google/certificate-transparency-go/x509util"
)

const (
	logListURL       = loglist2.LogListURL
	logListSigURL    = loglist2.LogListSignatureURL
	logListPubKeyURL = "https://www.gstatic.com/ct/log_list/v2/log_list_pubkey.pem"
)

var (
	logCacheDuration = time.Hour * 24
	qualifiedLogs = []loglist2.LogStatus{
		loglist2.QualifiedLogStatus,
		loglist2.UsableLogStatus,
		loglist2.ReadOnlyLogStatus,
	}
)

type LogListConfig struct {
	CacheCTLogListFilePath string
	CacheCTLogListSigFilePath string
	CacheCTLogListPubKeyFilePath string
}

func newDefaultLogList(config LogListConfig) *loglist2.LogList {
	jsonData := getValidCacheOrLatest(logListURL, config.CacheCTLogListFilePath, logCacheDuration)
	sigData := getValidCacheOrLatest(logListSigURL, config.CacheCTLogListSigFilePath, logCacheDuration)
	pemData := getValidCacheOrLatest(logListPubKeyURL, config.CacheCTLogListPubKeyFilePath, logCacheDuration)
	return newLogListFromSources(jsonData, sigData, pemData)
}

func newLogListFromSources(jsonData []byte, sigData []byte, pemData []byte) *loglist2.LogList {
	pubKey, _, _, err := ct.PublicKeyFromPEM(pemData)
	if err != nil {
		log.Fatalf("could not parse log list public key: %v", err)
	}

	ll, err := loglist2.NewFromSignedJSON(jsonData, sigData, pubKey)
	if err != nil {
		log.Fatalf("could not verify log list signature: %v", err)
	}

	qualifiedLogs := ll.SelectByStatus(qualifiedLogs)
	return &qualifiedLogs
}

func newLogInfoFromLog(ctLog *loglist2.Log) (*ctutil.LogInfo, error) {
	client, err := ctclient.New(
		ctLog.URL,
		http.DefaultClient,
		ctjsonclient.Options{PublicKeyDER: ctLog.Key, UserAgent: "go-st"},
	)
	if err != nil {
		return nil, fmt.Errorf("could not create client for log %q: %v", ctLog.Description, err)
	}

	logKey, err := ctx509.ParsePKIXPublicKey(ctLog.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key for log %q: %v", ctLog.Description, err)
	}

	verifier, err := ct.NewSignatureVerifier(logKey)
	if err != nil {
		return nil, fmt.Errorf("failed to build verifier for log %q: %v", ctLog.Description, err)
	}

	mmd := time.Duration(ctLog.MMD) * time.Second
	logInfo := &ctutil.LogInfo{
		Description: ctLog.Description,
		Client:      client,
		MMD:         mmd,
		Verifier:    verifier,
		PublicKey:   ctLog.Key,
	}

	return logInfo, nil
}

func getValidCacheOrLatest(originalSource string, cacheFilePath string, duration time.Duration) []byte {
	var err error
	var data []byte
	isHit := isCacheHit(cacheFilePath, duration)
	if isHit {
		data, err = ctx509util.ReadFileOrURL(cacheFilePath, http.DefaultClient)
		if err != nil {
			log.Printf("failed to fetch cached file %s: %v", cacheFilePath, err)
			_ = os.Remove(cacheFilePath)
			isHit = false
		}
	}

	if !isHit {
		data, err = ctx509util.ReadFileOrURL(originalSource, http.DefaultClient)
		if err != nil {
			log.Fatalf("failed to fetch original source file %s: %v", originalSource, err)
		}

		if cacheFilePath != "" {
			err = ioutil.WriteFile(cacheFilePath, data, 0755)
			if err != nil {
				log.Printf("failed to write cache file %s: %s", cacheFilePath, err)
			}
		}
	}

	return data
}

func isCacheHit(filePath string, duration time.Duration) bool {
	if filePath == "" {
		return false
	}

	info, err := os.Stat(filePath)
	if err != nil {
		return false
	}

	modTime := info.ModTime()
	cacheExpiration := modTime.Add(duration)
	isHit := time.Now().Before(cacheExpiration)
	return isHit
}
