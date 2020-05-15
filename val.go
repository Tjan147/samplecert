package samplecert

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"
)

type NodeVal struct {
	Sk          ed25519.PrivateKey
	Certs       *x509.CertPool
	SampleCerts *SampleCertPool
}

// factory
func NewNodeVal() *NodeVal {
	_, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	return &NodeVal{
		Sk:          sk,
		Certs:       x509.NewCertPool(),
		SampleCerts: NewSampleCertPool(),
	}
}

// ------------------------- X509 --------------------------- //

// helper
func templateValCert() *x509.Certificate {
	return &x509.Certificate{
		SerialNumber:          big.NewInt(-1),
		KeyUsage:              x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		Subject:               pkix.Name{Organization: []string{"LambdaIM-test"}},
		NotAfter:              time.Now().Add(24 * time.Hour),
		NotBefore:             time.Now().Add(-1 * time.Hour),
	}
}

func (nv *NodeVal) HandleCertReq(csr *x509.CertificateRequest) (*x509.Certificate, error) {
	if err := csr.CheckSignature(); err != nil {
		return nil, err
	}

	template := templateValCert()

	cBytes, err := x509.CreateCertificate(
		rand.Reader, template, template, csr.PublicKey, nv.Sk,
	)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(cBytes)
	if err != nil {
		return nil, err
	}
	nv.Certs.AddCert(cert)

	return cert, nil
}

func (nv *NodeVal) VerifyCert(cBytes []byte) error {
	c, err := x509.ParseCertificate(cBytes)
	if err != nil {
		return err
	}

	opts := x509.VerifyOptions{
		Roots: nv.Certs,
	}

	_, err = c.Verify(opts)
	return err
}

// ----------------- SampleCert -------------------- //

// TODO: the certification update procedure may need more consideration
func (nv *NodeVal) HandleSampleCertReq(scr *SampleCertRequest) (*SampleCert, error) {
	if err := scr.Verify(); err != nil {
		return nil, err
	}

	endTime := time.Now().Add(scr.Duration)
	cert, err := ChainSign(nil, []byte(scr.PubKey), nv.Sk, endTime)
	if err != nil {
		return nil, err
	}
	nv.SampleCerts.Add(scr.PubKey, endTime)

	return cert, nil
}

func (nv *NodeVal) HandleSampleCertNotify(scn *SampleCertNotify) error {
	rec := nv.SampleCerts.Get(scn.PubKey)
	if rec == nil {
		return fmt.Errorf("unknown cert issuer: %s", wrapPubKeyAsStr(scn.PubKey))
	}

	if err := scn.Verify(rec.pubKey, time.Now()); err != nil {
		return fmt.Errorf("notify signature validation failed: %s", err.Error())
	}

	for _, auth := range scn.AuthKeys {
		nv.SampleCerts.Add(auth, scn.EndTime)
	}

	return nil
}

func (nv *NodeVal) HandleSampleCommit(data []byte, cert *SampleCert) error {
	opt := nv.SampleCerts.GetSampleCertOpt()

	return ChainVerify(cert, opt, data)
}
