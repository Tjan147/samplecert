package samplecert

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"time"
)

type unitCert struct {
	pubKey   ed25519.PublicKey
	notAfter time.Time
}

func unitSign(t time.Time, data []byte, priv ed25519.PrivateKey) (*unitCert, []byte, error) {
	sig, err := priv.Sign(rand.Reader, data, crypto.Hash(0))
	if err != nil {
		return nil, nil, err
	}

	pubKey, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, nil, fmt.Errorf("failed to restore public key")
	}

	return &unitCert{
		pubKey:   pubKey,
		notAfter: t,
	}, sig, nil
}

func (uc *unitCert) unitVerify(t time.Time, data, sig []byte) error {
	if t.After(uc.notAfter) {
		return fmt.Errorf(
			"cert expired: %s is after %s",
			t.String(), uc.notAfter.String(),
		)
	}

	if !ed25519.Verify(uc.pubKey, data, sig) {
		return fmt.Errorf("invalid signature")
	}

	return nil
}

// ------------------------------------------------ //

type SampleCert struct {
	CertChain []*unitCert
	Signature []byte
}

func (sc *SampleCert) expectedSignatureLength() int {
	return len(sc.CertChain) * ed25519.SignatureSize
}

func (sc *SampleCert) basicValidate() error {
	if len(sc.Signature) != sc.expectedSignatureLength() {
		return fmt.Errorf(
			"SampleCert.Signature length invalid(want %d, got %d)",
			sc.expectedSignatureLength(), len(sc.Signature),
		)
	}

	return nil
}

func ChainSign(
	parent *SampleCert,
	data []byte,
	priv ed25519.PrivateKey,
	endTime time.Time,
) (*SampleCert, error) {
	var signData []byte
	if parent == nil {
		signData = data
	} else {
		signData = append(data, parent.Signature...)
	}

	mySign, sig, err := unitSign(endTime, signData, priv)
	if err != nil {
		return nil, err
	}

	return &SampleCert{
		CertChain: append(parent.CertChain, mySign),
		Signature: append(parent.Signature, sig...),
	}, nil
}

func (sc *SampleCert) ChainVerify(data []byte) error {
	if len(sc.CertChain) < 1 {
		return fmt.Errorf("empty cert chain")
	}

	if err := sc.basicValidate(); err != nil {
		return err
	}

	// chained verification impl
	for index := 0; index < len(sc.CertChain); index++ {
		start := index * ed25519.SignatureSize
		verifySig := sc.Signature[start : start+ed25519.SignatureSize]

		var verifyData []byte
		if index == 0 {
			verifyData = data
		} else {
			// TODO: is deep copy required ?
			verifyData = append(data, sc.Signature[:start]...)
		}

		if err := sc.CertChain[index].unitVerify(time.Now(), verifyData, verifySig); err != nil {
			return fmt.Errorf(
				"SampleCert chain verification failed on %dth signature: %s",
				index+1, err.Error(),
			)
		}
	}

	return nil
}

// ----------------------------------------------------- //

type SampleCertRequest struct {
	ID        string
	Duration  time.Duration
	PubKey    ed25519.PublicKey
	Signature []byte
}

func marshalAsBytes(s string, d time.Duration, pk ed25519.PublicKey) []byte {
	temp := append([]byte(s), []byte(d.String())...)
	return append(temp, []byte(pk)...)
}

// factory
func CreateSampleCertRequest(id string, length time.Duration, priv ed25519.PrivateKey) (*SampleCertRequest, error) {
	pubKey, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("failed to restore public key")
	}

	data := marshalAsBytes(id, length, pubKey)

	sig, err := priv.Sign(rand.Reader, data, crypto.Hash(0))
	if err != nil {
		return nil, err
	}

	return &SampleCertRequest{
		ID:        id,
		Duration:  length,
		PubKey:    pubKey,
		Signature: sig,
	}, nil
}

func (scr *SampleCertRequest) verify() error {
	data := marshalAsBytes(scr.ID, scr.Duration, scr.PubKey)

	if !ed25519.Verify(scr.PubKey, data, scr.Signature) {
		return fmt.Errorf("request %s verification failed", scr.ID)
	}

	return nil
}
