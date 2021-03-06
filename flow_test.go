package samplecert

import (
	"testing"
)

func TestCertificationFlowUsingX509(t *testing.T) {
	v := NewNodeVal()
	m := NewNodeMiner("sample_miner")
	s := NewNodeStorage("sample_machine")

	mcert, err := v.HandleCertReq(m.Register())
	if err != nil {
		t.Fatalf(err.Error())
	}
	m.HandleValCertRes(mcert)

	scert, err := m.HandleCertReq(s.Register())
	if err != nil {
		t.Fatalf(err.Error())
	}
	s.HandleValCertRes(scert)

	if err := v.VerifyCert(s.GetCertBytes()); err != nil {
		t.Fatalf(err.Error())
	}
}

func TestCertificationFlowUsingSampleCert(t *testing.T) {
	v := NewNodeVal()
	m := NewNodeMiner("sample_miner")
	s := NewNodeStorage("sample_machine")

	// phase 1
	// the Miner(m) request a cert from the Validator(v)
	mReq, err := m.RegisterSampleCert()
	if err != nil {
		t.Fatalf(err.Error())
	}
	vRes, err := v.HandleSampleCertReq(mReq)
	if err != nil {
		t.Fatalf(err.Error())
	}
	if err := m.HandleSampleCertRes(vRes); err != nil {
		t.Fatalf(err.Error())
	}

	// phase 2
	// the Storage(s) request a cert from the Miner(m)
	// and Miner(m) notify this cert response to the Validator(v)
	sReq, err := s.RegisterSampleCert()
	if err != nil {
		t.Fatalf(err.Error())
	}
	mRes, mNotify, err := m.HandleStorageSampleCertReq(sReq)
	if err != nil {
		t.Fatalf(err.Error())
	}
	if err := v.HandleSampleCertNotify(mNotify); err != nil {
		t.Fatalf(err.Error())
	}
	if err := s.HandleSampleCertRes(mRes); err != nil {
		t.Fatalf(err.Error())
	}

	// phase 3
	// the Storage(s) commit some business data to the Miner(m)
	// and the Miner(m) pack the data up and give it to the Validator(v)
	data, sCert := s.MockCommitData()
	mCert, err := m.PackStorageCommit(data, sCert)
	if err != nil {
		t.Fatalf(err.Error())
	}
	if err := v.HandleSampleCommit(data, mCert); err != nil {
		t.Fatalf(err.Error())
	}
}
