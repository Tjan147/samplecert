package samplecert

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"
)

// ------------------------------------------------ //

type unitCert struct {
	pubKey   ed25519.PublicKey // in place of account address/ID
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

func checkEqualPublicKeys(known, given ed25519.PublicKey) bool {
	return bytes.Compare([]byte(known), []byte(given)) == 0
}

func unitVerify(uc *unitCert, pk ed25519.PublicKey, t time.Time, data, sig []byte) error {
	if t.After(uc.notAfter) {
		return fmt.Errorf(
			"cert expired: %s is after %s",
			t.String(), uc.notAfter.String(),
		)
	}

	if !checkEqualPublicKeys(uc.pubKey, pk) {
		return fmt.Errorf("cert public key and given public key mismatch")
	}

	if !ed25519.Verify(pk, data, sig) {
		return fmt.Errorf("invalid signature")
	}

	return nil
}

// ------------------------------------------------ //

type SampleCertPool struct {
	knownCerts map[string]*unitCert
}

// factory
func NewSampleCertPool() *SampleCertPool {
	return &SampleCertPool{
		knownCerts: make(map[string]*unitCert),
	}
}

func (scp *SampleCertPool) GetSampleCertOpt() *SampleCertOpt {
	// TODO: is deep copy necessary ?
	return &SampleCertOpt{
		knownCerts: scp.knownCerts,
	}
}

func (scp *SampleCertPool) Has(pk ed25519.PublicKey) bool {
	_, ret := scp.knownCerts[wrapPubKeyAsStr(pk)]
	return ret
}

func (scp *SampleCertPool) Add(pk ed25519.PublicKey, t time.Time) {
	scp.knownCerts[wrapPubKeyAsStr(pk)] = &unitCert{
		pubKey:   pk,
		notAfter: t,
	}
}

func (scp *SampleCertPool) AddUnit(uc *unitCert) {
	scp.knownCerts[wrapPubKeyAsStr(uc.pubKey)] = uc
}

func (scp *SampleCertPool) Get(pk ed25519.PublicKey) *unitCert {
	return scp.knownCerts[wrapPubKeyAsStr(pk)]
}

// ------------------------------------------------ //

type SampleCert struct {
	CertChain []*unitCert
	Signature []byte
}

type SampleCertOpt struct {
	knownCerts map[string]*unitCert
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

func (sc *SampleCert) GetHeadCertification() *unitCert {
	return sc.CertChain[0]
}

func (sc *SampleCert) VerifyHeadCertification(pk ed25519.PublicKey, t time.Time) error {
	head := sc.CertChain[0]

	return unitVerify(head, head.pubKey, t, []byte(pk), sc.Signature)
}

func ChainSign(
	previous *SampleCert,
	data []byte,
	priv ed25519.PrivateKey,
	endTime time.Time,
) (*SampleCert, error) {
	var signData []byte
	if previous == nil {
		signData = data
	} else {
		signData = append(data, previous.Signature...)
	}

	mySign, sig, err := unitSign(endTime, signData, priv)
	if err != nil {
		return nil, err
	}

	if previous == nil {
		return &SampleCert{
			CertChain: []*unitCert{mySign},
			Signature: sig,
		}, nil
	}

	return &SampleCert{
		CertChain: append(previous.CertChain, mySign),
		Signature: append(previous.Signature, sig...),
	}, nil
}

// helper
func singleVerify(uc *unitCert, scvo *SampleCertOpt, t time.Time, data, sig []byte) error {
	knownCert, known := scvo.knownCerts[wrapPubKeyAsStr(uc.pubKey)]
	if !known {
		return fmt.Errorf("unknown certification")
	}

	return unitVerify(uc, knownCert.pubKey, t, data, sig)
}

func pickVerifyDataAndSignature(index int, data, sig []byte) (verifyData, verifySig []byte) {
	start := index * ed25519.SignatureSize
	verifySig = sig[start : start+ed25519.SignatureSize]

	if index == 0 {
		verifyData = data
	} else {
		// TODO: is deep copy required ?
		verifyData = append(data, sig[:start]...)
	}

	return
}

func ChainVerify(sc *SampleCert, scvo *SampleCertOpt, data []byte) error {
	if len(sc.CertChain) < 1 {
		return fmt.Errorf("empty cert chain")
	}

	if err := sc.basicValidate(); err != nil {
		return err
	}

	// chained verification impl
	for idx, cert := range sc.CertChain {
		vData, vSig := pickVerifyDataAndSignature(idx, data, sc.Signature)

		if err := singleVerify(cert, scvo, time.Now(), vData, vSig); err != nil {
			return fmt.Errorf(
				"chain verification failed on %dth signature: %s",
				idx+1, err.Error(),
			)
		}
	}

	return nil
}

// ----------------------------------------------------- //

type SampleCertRequest struct {
	Duration  time.Duration
	PubKey    ed25519.PublicKey // pk used as both an ID and the committed public key
	Signature []byte
}

func marshalSCR(d time.Duration, pk ed25519.PublicKey) []byte {
	return append([]byte(d.String()), []byte(pk)...)
}

// factory
func CreateSampleCertRequest(length time.Duration, priv ed25519.PrivateKey) (*SampleCertRequest, error) {
	pubKey, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("failed to restore public key")
	}

	sig, err := priv.Sign(rand.Reader, marshalSCR(length, pubKey), crypto.Hash(0))
	if err != nil {
		return nil, err
	}

	return &SampleCertRequest{
		Duration:  length,
		PubKey:    pubKey,
		Signature: sig,
	}, nil
}

// helper
func wrapPubKeyAsStr(pk ed25519.PublicKey) string {
	return base64.StdEncoding.EncodeToString([]byte(pk))
}

func (scr *SampleCertRequest) Verify() error {
	data := marshalSCR(scr.Duration, scr.PubKey)

	if !ed25519.Verify(scr.PubKey, data, scr.Signature) {
		return fmt.Errorf("request from %s verification failed", wrapPubKeyAsStr(scr.PubKey))
	}

	return nil
}

// ------------------------------------------------------- //

type SampleCertNotify struct {
	EndTime   time.Time
	AuthKeys  []ed25519.PublicKey
	PubKey    ed25519.PublicKey // pk used as both an ID and the committed public key
	Signature []byte
}

func marshalSCN(t time.Time, ks []ed25519.PublicKey, pk ed25519.PublicKey) []byte {
	temp := []byte(t.String())
	for _, k := range ks {
		temp = append(temp, []byte(k)...)
	}

	return append(temp, []byte(pk)...)
}

// factory
func CreateSampleCertNotify(
	endTime time.Time,
	authKeys []ed25519.PublicKey,
	priv ed25519.PrivateKey,
) (*SampleCertNotify, error) {
	pubKey, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("failed to restore public key")
	}

	sig, err := priv.Sign(rand.Reader, marshalSCN(endTime, authKeys, pubKey), crypto.Hash(0))
	if err != nil {
		return nil, err
	}

	return &SampleCertNotify{
		EndTime:   endTime,
		AuthKeys:  authKeys,
		PubKey:    pubKey,
		Signature: sig,
	}, nil
}

func (scn *SampleCertNotify) Verify(knownKey ed25519.PublicKey, refTime time.Time) error {
	if !checkEqualPublicKeys(knownKey, scn.PubKey) {
		return fmt.Errorf(
			"notify's public key(%s) dismatch local record",
			wrapPubKeyAsStr(knownKey),
		)
	}

	if refTime.After(scn.EndTime) {
		return fmt.Errorf("notification expired already")
	}

	data := marshalSCN(scn.EndTime, scn.AuthKeys, scn.PubKey)
	if !ed25519.Verify(scn.PubKey, data, scn.Signature) {
		return fmt.Errorf("request from %s verification failed", wrapPubKeyAsStr(knownKey))
	}

	return nil
}
