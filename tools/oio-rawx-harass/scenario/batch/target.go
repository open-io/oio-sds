package batch

import (
	"math/rand"
)

type targetPopulation struct {
	rawx      string
	quotaDel  uint32
	scenarios []*Behavior
}

// get a pointer to a random element
func (pop *targetPopulation) choose() *Behavior {
	l := len(pop.scenarios)
	if l <= 0 {
		return nil
	}
	idx := rand.Intn(l)
	return pop.scenarios[idx]
}

func (pop *population) resolveTarget(url string) *targetPopulation {
	for _, p := range pop.scenarios {
		if p.rawx == url {
			return p
		}
	}
	panic("unknown target")
}

func (pop *population) peekPopForGet() *targetPopulation {
	l := len(pop.scenarios)
	return pop.scenarios[rand.Intn(l)]
}

func (pop *population) peekPopForDelete(honorCounter bool) *targetPopulation {
	total := uint32(0)
	for _, p := range pop.scenarios {
		total += p.quotaDel
	}

	needle := uint32(0)
	if total == 0 {
		if honorCounter {
			return nil
		}
	} else {
		total = 0
		for _, p := range pop.scenarios {
			total += p.quotaDel
			if needle < total {
				return p
			}
		}
	}

	l := len(pop.scenarios)
	return pop.scenarios[rand.Intn(l)]
}

func (pop *population) choose() (*targetPopulation, *Behavior) {
	p := pop.peekPopForGet()
	return p, p.choose()
}

// choose and remove the chosen
func (pop *population) steal(honorCounter bool) (*targetPopulation, *Behavior) {
	p := pop.peekPopForDelete(honorCounter)
	return p, p.choose()
}
