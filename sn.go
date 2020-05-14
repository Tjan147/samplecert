package samplecert

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
)

type NodeStorage struct {
	Name     string
	Sk       ed25519.PrivateKey
	LeafCert *x509.Certificate
}

// factory
func NewNodeStorage(name string) *NodeStorage {
	_, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	return &NodeStorage{
		Name: name,
		Sk:   sk,
	}
}

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

// helper
func (sn *NodeStorage) GetCertBytes() []byte {
	return sn.LeafCert.Raw
}

// TODO: impl commit
