package sct

import (
	"crypto/tls"
	"net/http"
)

type TransportConfig struct {
	UserAgent                    string
	CacheCTLogListFilePath       string
	CacheCTLogListSigFilePath    string
	CacheCTLogListPubKeyFilePath string
	CacheValidSCTFilePath        string
}

type CertificateTransparencyTransport struct {
	Config TransportConfig
}

func NewTransport(tc TransportConfig) *CertificateTransparencyTransport {
	return &CertificateTransparencyTransport{
		Config: tc,
	}
}

func (t *CertificateTransparencyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.Config.UserAgent != "" {
		req.Header.Set("User-Agent", t.Config.UserAgent)
	}

	return t.getDefaultTransport().RoundTrip(req)
}

func (t *CertificateTransparencyTransport) getDefaultTransport() *http.Transport {
	return &http.Transport{
		TLSClientConfig: &tls.Config{
			VerifyConnection: func(state tls.ConnectionState) error {
				return CheckConnectionState(&state, CheckerConfig{
					CacheCTLogListFilePath:       t.Config.CacheCTLogListFilePath,
					CacheCTLogListSigFilePath:    t.Config.CacheCTLogListSigFilePath,
					CacheCTLogListPubKeyFilePath: t.Config.CacheCTLogListPubKeyFilePath,
					CacheValidSCTFilePath:        t.Config.CacheValidSCTFilePath,
				})
			},
		},
	}
}