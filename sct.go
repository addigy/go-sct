// Package sct verifies Signed Certificate Timestamp in TLS connections.
// See [RFC 6962](https://datatracker.ietf.org/doc/rfc6962/).
package sct

import (
	"context"
	"crypto/md5"
	"crypto/tls"
	"errors"
	"fmt"
	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/loglist2"
	ctx509 "github.com/google/certificate-transparency-go/x509"
	ctx509util "github.com/google/certificate-transparency-go/x509util"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	checkerCacheDuration = logCacheDuration
	lastCheckerUpdate    time.Time
	defaultCheckerLock   sync.Mutex
	defaultChecker       *checker

	validTimestampCachePopulateOnce sync.Once
	validTimestampCacheLock         sync.RWMutex
	validTimestampCache             = make(map[string]bool)
)

// checker performs SCT checks.
type checker struct {
	ll *loglist2.LogList
	cc CheckerConfig
}

type CheckerConfig struct {
	CacheCTLogListFilePath       string
	CacheCTLogListSigFilePath    string
	CacheCTLogListPubKeyFilePath string
	CacheValidSCTFilePath        string
}

// getDefaultChecker returns the default Checker, initializing it if needed.
func getDefaultChecker(cc CheckerConfig) *checker {
	populateValidTimestampCache(cc.CacheValidSCTFilePath)
	if isCheckerCacheExpired() {
		defaultCheckerLock.Lock()
		if isCheckerCacheExpired() {
			defaultChecker = &checker {
				ll: newDefaultLogList(LogListConfig{
					CacheCTLogListFilePath:       cc.CacheCTLogListFilePath,
					CacheCTLogListSigFilePath:    cc.CacheCTLogListSigFilePath,
					CacheCTLogListPubKeyFilePath: cc.CacheCTLogListPubKeyFilePath,
				}),
				cc: cc,
			}

			lastCheckerUpdate = time.Now()
		}

		defaultCheckerLock.Unlock()
	}

	return defaultChecker
}

func populateValidTimestampCache(cacheValidSCTFilePath string) {
	if cacheValidSCTFilePath == "" {
		return
	}

	validTimestampCachePopulateOnce.Do(func() {
		bts, err := ioutil.ReadFile(cacheValidSCTFilePath)
		if err != nil {
			log.Printf("could not read cacheValidSCTFile[%s]: %s", cacheValidSCTFilePath, err)
			return
		}

		timestamps := strings.Split(string(bts), "\n")
		for _, timestamp := range timestamps {
			if timestamp == "" {
				continue
			}

			validTimestampCache[timestamp] = true
		}
	})
}

func isCheckerCacheExpired() bool {
	checkerCacheExpiration := lastCheckerUpdate.Add(checkerCacheDuration)
	return time.Now().After(checkerCacheExpiration)
}

// CheckConnectionState examines SCTs (both embedded and in the TLS extension) and returns
// nil if at least one of them is valid.
func CheckConnectionState(state *tls.ConnectionState, cc CheckerConfig) error {
	return getDefaultChecker(cc).checkConnectionState(state)
}

func (c *checker) checkConnectionState(state *tls.ConnectionState) error {
	if state == nil {
		return errors.New("no TLS connection state")
	}

	if len(state.PeerCertificates) == 0 {
		return errors.New("no peer certificates in TLS connection state")
	}

	chain, err := buildCertificateChain(state.PeerCertificates)
	if err != nil {
		return err
	}

	lastError := errors.New("no Signed Certificate Timestamps found")

	// SCTs provided in the TLS handshake.
	if err = c.checkTLSSCTs(state.SignedCertificateTimestamps, chain); err != nil {
		lastError = err
	} else {
		return nil
	}

	// Check SCTs embedded in the leaf certificate.
	if err = c.checkCertSCTs(chain); err != nil {
		lastError = err
	} else {
		return nil
	}

	// TODO(mberhault): check SCTs in OSCP response.
	return lastError
}

// Check SCTs provided with the TLS handshake. Returns an error if no SCT is valid.
func (c *checker) checkTLSSCTs(scts [][]byte, chain []*ctx509.Certificate) error {
	if len(scts) == 0 {
		return errors.New("no SCTs in SSL handshake")
	}

	merkleLeaf, err := ct.MerkleTreeLeafFromChain(chain, ct.X509LogEntryType, 0)
	if err != nil {
		return err
	}

	for _, sct := range scts {
		x509SCT := &ctx509.SerializedSCT{Val: sct}
		err := c.checkOneSCT(x509SCT, merkleLeaf)
		if err == nil {
			// Valid: return early.
			return nil
		}
	}

	return errors.New("no valid SCT in SSL handshake")
}

// Check SCTs embedded in the leaf certificate. Returns an error if no SCT is valid.
func (c *checker) checkCertSCTs(chain []*ctx509.Certificate) error {
	leaf := chain[0]
	if len(leaf.SCTList.SCTList) == 0 {
		return errors.New("no SCTs in leaf certificate")
	}

	if len(chain) < 2 {
		// TODO(mberhault): optionally fetch issuer from IssuingCertificateURL.
		return errors.New("no issuer certificate in chain")
	}
	issuer := chain[1]

	merkleLeaf, err := ct.MerkleTreeLeafForEmbeddedSCT([]*ctx509.Certificate{leaf, issuer}, 0)
	if err != nil {
		return err
	}

	for _, sct := range leaf.SCTList.SCTList {
		err := c.checkOneSCT(&sct, merkleLeaf)
		if err == nil {
			// Valid: return early.
			return nil
		}
	}

	return errors.New("no valid SCT in SSL handshake")
}

func (c *checker) checkOneSCT(x509SCT *ctx509.SerializedSCT, merkleLeaf *ct.MerkleTreeLeaf) error {
	if c.isValidCacheHit(x509SCT) {
		return nil
	}

	sct, err := ctx509util.ExtractSCT(x509SCT)
	if err != nil {
		return err
	}

	ctLog := c.ll.FindLogByKeyHash(sct.LogID.KeyID)
	if ctLog == nil {
		return fmt.Errorf("no log found with KeyID %x", sct.LogID)
	}

	logInfo, err := newLogInfoFromLog(ctLog)
	if err != nil {
		return fmt.Errorf("could not create client for log %s", ctLog.Description)
	}

	err = logInfo.VerifySCTSignature(*sct, *merkleLeaf)
	if err != nil {
		return err
	}

	_, err = logInfo.VerifyInclusion(context.Background(), *merkleLeaf, sct.Timestamp)
	if err != nil {
		age := time.Since(ct.TimestampToTime(sct.Timestamp))
		if age >= logInfo.MMD {
			return fmt.Errorf("failed to verify inclusion in log %q", ctLog.Description)
		}

		// TODO(mberhault): option to fail on timestamp too recent.
		return nil
	}

	c.setValidCache(x509SCT)
	return nil
}

func (c *checker) isValidCacheHit(x509SCT *ctx509.SerializedSCT) bool {
	validTimestampCacheKey := fmt.Sprintf("%x", md5.Sum(x509SCT.Val))
	validTimestampCacheLock.RLock()
	isValid := validTimestampCache[validTimestampCacheKey]
	validTimestampCacheLock.RUnlock()
	return isValid
}

func (c *checker) setValidCache(x509SCT *ctx509.SerializedSCT) {
	validTimestampCacheKey := fmt.Sprintf("%x", md5.Sum(x509SCT.Val))
	validTimestampCacheLock.Lock()
	defer validTimestampCacheLock.Unlock()
	validTimestampCache[validTimestampCacheKey] = true
	if c.cc.CacheValidSCTFilePath != "" {
		f, err := os.OpenFile(c.cc.CacheValidSCTFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Printf("error opening cache file[%s]: %s", c.cc.CacheValidSCTFilePath, err)
			return
		}
		_, err = f.WriteString(validTimestampCacheKey + "\n")
		if err != nil {
			log.Printf("error writing timestamp cache entry: %s", err)
		}

		_ = f.Close()
	}
}
