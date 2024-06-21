package utils

import "testing"

func TestPoissonSpeed(t *testing.T) {
	for i := 1; i < 300; i++ {
		t.Logf("lambda=%d", i)
		NewPoissonSlots(i)
	}
}

func TestPoisson(t *testing.T) {
	p := NewPoissonSlots(10)
	for i, slot := range p.probabilities {
		t.Logf("slot %d: %+v", i, slot)
	}
	for i := 0; i < 50; i++ {
		t.Logf("iter %v value %v", i, p.Poll())
	}
}
