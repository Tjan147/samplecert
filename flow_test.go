package samplecert

import (
	"testing"
)

func TestCertificationFlow(t *testing.T) {
	v := NewNodeVal()
	m := NewNodeMiner("sample_miner")
	s := NewNodeStorage("sample_machine")

	mcert, err := v.HandleCertReq(m.Register())
	if err != nil {
		panic(err)
	}
	m.HandleValCertRes(mcert)

	scert, err := m.HandleCertReq(s.Register())
	if err != nil {
		panic(err)
	}
	s.HandleValCertRes(scert)

	if err := v.VerifyCert(s.GetCertBytes()); err != nil {
		panic(err)
	}
}
