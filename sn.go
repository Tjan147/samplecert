package samplecert

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"time"
)

type NodeStorage struct {
	Name              string
	Sk                ed25519.PrivateKey
	Pk                ed25519.PublicKey
	LeafCert          *x509.Certificate
	SampleCertEndTime time.Time
}

// factory
func NewNodeStorage(name string) *NodeStorage {
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	return &NodeStorage{
		Name: name,
		Sk:   sk,
		Pk:   pk,
	}
}

// ---------------------- X509 -------------------------- //

func templateStorageReq(sn *NodeStorage) *x509.CertificateRequest {
	return &x509.CertificateRequest{
		PublicKeyAlgorithm: x509.Ed25519,
		Subject:            pkix.Name{Organization: []string{sn.Name}},
	}
}

func (sn *NodeStorage) Register() *x509.CertificateRequest {
	csrBytes, err := x509.CreateCertificateRequest(
		rand.Reader, templateStorageReq(sn), sn.Sk,
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

func (sn *NodeStorage) HandleValCertRes(cert *x509.Certificate) {
	fmt.Printf("%s got certificated\n", sn.Name)
	sn.LeafCert = cert
}

func (sn *NodeStorage) GetCertBytes() []byte {
	return sn.LeafCert.Raw
}

// --------------------- SampleCert ------------------------ //

func (sn *NodeStorage) RegisterSampleCert() (*SampleCertRequest, error) {
	return CreateSampleCertRequest(12*time.Hour, sn.Sk)
}

func (sn *NodeStorage) HandleSampleCertRes(sc *SampleCert) error {
	if err := sc.VerifyHeadCertification(sn.Pk, time.Now()); err != nil {
		return err
	}
	sn.SampleCertEndTime = sc.GetHeadCertification().notAfter

	return nil
}

var mockDataStr string

func mockCommitData() []byte {
	mockData := make([]byte, ed25519.SignatureSize)
	rand.Read(mockData)

	mockDataStr = base64.StdEncoding.EncodeToString(mockData)

	return []byte(mockDataStr)
}

func (sn *NodeStorage) MockCommitData() ([]byte, *SampleCert) {
	commitData := mockCommitData()

	cert, err := ChainSign(nil, commitData, sn.Sk, sn.SampleCertEndTime)
	if err != nil {
		panic(err)
	}

	return commitData, cert
}
