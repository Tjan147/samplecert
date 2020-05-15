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

type NodeMiner struct {
	Name              string
	Sk                ed25519.PrivateKey
	Pk                ed25519.PublicKey
	Intermediate      *x509.Certificate
	SampleCerts       *SampleCertPool
	SampleCertEndTime time.Time
}

// factory
func NewNodeMiner(name string) *NodeMiner {
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	return &NodeMiner{
		Name:        name,
		Sk:          sk,
		Pk:          pk,
		SampleCerts: NewSampleCertPool(),
	}
}

// ---------------------- X509 ----------------------- //

func templateMinerReq(mn *NodeMiner) *x509.CertificateRequest {
	return &x509.CertificateRequest{
		PublicKeyAlgorithm: x509.Ed25519,
		Subject:            pkix.Name{Organization: []string{mn.Name}},
	}
}

func (mn *NodeMiner) Register() *x509.CertificateRequest {
	csrBytes, err := x509.CreateCertificateRequest(
		rand.Reader, templateMinerReq(mn), mn.Sk,
	)
	if err != nil {
		panic(err)
	}

	csr, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		panic(err)
	}

	return csr
}

func (mn *NodeMiner) HandleValCertRes(cert *x509.Certificate) {
	fmt.Printf("%s got certificated\n", mn.Name)
	mn.Intermediate = cert
}

func templateMinerCert(mn *NodeMiner) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber:          big.NewInt(-1),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		Subject:               pkix.Name{Organization: []string{mn.Name}},
		NotAfter:              time.Now().Add(24 * time.Hour),
		NotBefore:             time.Now().Add(-1 * time.Hour),
	}
}

func (mn *NodeMiner) HandleCertReq(csr *x509.CertificateRequest) (*x509.Certificate, error) {
	if err := csr.CheckSignature(); err != nil {
		return nil, err
	}

	template := templateMinerCert(mn)

	cBytes, err := x509.CreateCertificate(
		rand.Reader, template, mn.Intermediate, csr.PublicKey, mn.Sk,
	)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(cBytes)
}

// -------------------------- SampleCert ------------------------------- //

func (mn *NodeMiner) RegisterSampleCert() (*SampleCertRequest, error) {
	return CreateSampleCertRequest(24*time.Hour, mn.Sk)
}

func (mn *NodeMiner) HandleSampleCertRes(sc *SampleCert) error {
	if err := sc.VerifyHeadCertification(mn.Pk, time.Now()); err != nil {
		return err
	}
	mn.SampleCertEndTime = sc.GetHeadCertification().notAfter

	return nil
}

func (mn *NodeMiner) HandleStorageSampleCertReq(scr *SampleCertRequest) (*SampleCert, *SampleCertNotify, error) {
	if err := scr.Verify(); err != nil {
		return nil, nil, err
	}

	endTime := time.Now().Add(scr.Duration)
	cert, err := ChainSign(nil, []byte(scr.PubKey), mn.Sk, endTime)
	if err != nil {
		return nil, nil, err
	}
	mn.SampleCerts.Add(scr.PubKey, endTime)

	// pack single notify in this demo for simplicity
	notify, err := CreateSampleCertNotify(endTime, []ed25519.PublicKey{scr.PubKey}, mn.Sk)
	if err != nil {
		return nil, nil, err
	}

	return cert, notify, nil
}

func (mn *NodeMiner) PackStorageCommit(storageCommitData []byte, storageCert *SampleCert) (*SampleCert, error) {
	opt := mn.SampleCerts.GetSampleCertOpt()

	if err := ChainVerify(storageCert, opt, storageCommitData); err != nil {
		return nil, fmt.Errorf("failed to verify storage cert: %s", err.Error())
	}

	return ChainSign(storageCert, storageCommitData, mn.Sk, mn.SampleCertEndTime)
}
