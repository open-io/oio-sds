// OpenIO SDS oio-rawx-harass
// Copyright (C) 2024 OVH SAS
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public
// License along with this program. If not, see <http://www.gnu.org/licenses/>.

package distribution

import (
	"math"
	"math/big"
	"math/rand/v2"
)

type poissonSlot struct {
	slot        int
	probability float64
	cumul       float64
}

type PoissonDistribution struct {
	probabilities []poissonSlot

	// Position in the array where probabilities begin to be strictly positive
	start  int
	lambda int
}

// Computes "x / y" without the burden of pointers
func div(x, y big.Float) big.Float { return *x.Quo(&x, &y) }

// Computes "x * y" without the burden of pointers
func mul(x, y big.Float) big.Float { return *x.Mul(&x, &y) }

// Computes "x ** y" without the burden of pointers
func pow(x big.Float, y int) big.Float {
	result := big.NewFloat(1.0)
	base := new(big.Float).Set(&x)

	for y > 0 {
		if y%2 != 0 {
			result.Mul(result, base)
		}
		base.Mul(base, base)
		y /= 2
	}

	return *result
}

type factorialAsFloat struct {
	acc []big.Float
}

func newFactorialAsFloat() factorialAsFloat {
	result := factorialAsFloat{
		acc: make([]big.Float, 0),
	}
	result.Ensure(1)
	return result
}

func (factorials *factorialAsFloat) Ensure(n int) big.Float {
	if len(factorials.acc) == 0 {
		factorials.acc = append(factorials.acc, *big.NewFloat(1))
	}
	for i := len(factorials.acc); i <= n; i++ {
		bigI := big.NewFloat(float64(i))
		prev := &factorials.acc[i-1]
		factorials.acc = append(factorials.acc, mul(*prev, *bigI))
	}
	return factorials.acc[n]
}

func NewPoissonSlots(lambda int) PoissonDistribution {
	if lambda < 0 {
		panic("negative lambda")
	}

	result := PoissonDistribution{lambda: lambda, probabilities: make([]poissonSlot, 0)}

	if lambda == 0 {
		return result
	}

	// Pre-computes values reused in each computation round
	factorials := newFactorialAsFloat()

	eFloat := *big.NewFloat(math.E)
	lambdaFloat := *big.NewFloat(float64(lambda))
	expLambda := pow(eFloat, lambda)

	const epsilonUnit = 0.0000001
	const epsilonRemaining = 0.000001
	var remaining float64 = 1.0
	var maxK int = lambda * 10

	result.probabilities = append(result.probabilities, poissonSlot{slot: 0, probability: 0, cumul: 0})

	// Many stop conditions that ensure the loop stops under any circumstances
	// - 'k > lambda && p < epsilon' means it's not worth continuing on the long tail
	// - 'remaining > epsilon' is a variant of the previous
	// - 'k < maxK' ensures the termination for little values of lambda, and a not-to-long tail
	for k := 1; remaining > epsilonUnit && k < maxK; k++ {
		pFloat := div(div(pow(lambdaFloat, k), expLambda), factorials.Ensure(k))
		p, _ := pFloat.Float64()

		if k <= lambda && result.start == 0 && p > epsilonUnit {
			// store where  it starts
			result.start = k
		}

		remaining -= p
		result.probabilities = append(result.probabilities, poissonSlot{slot: k, probability: p, cumul: 0})

		if k > lambda && p < epsilonRemaining {
			break
		}
	}

	result.probabilities[lambda].probability += remaining
	remaining = 0

	// Compute the cumulative probability
	var cumul float64
	for i, _ := range result.probabilities {
		cumul += result.probabilities[i].probability
		result.probabilities[i].cumul = cumul
	}

	return result
}

func (d *PoissonDistribution) Poll() int {
	if d.lambda <= 0 {
		return 0
	}
	r := rand.Float64()
	for i := d.start; i < len(d.probabilities); i++ {
		slot := &d.probabilities[i]
		if slot.cumul >= r {
			return i
		}
	}
	return 0
}

func (d *PoissonDistribution) PollAtScale(total, slice int) int {
	tail := total % slice
	count := total / slice

	result := 0
	for i := 0; i < count; i++ {
		result += d.Poll()
	}
	if tail > 0 {
		nb := d.Poll()
		result += int((float64(tail) * float64(nb)) / float64(slice))
	}
	return result
}

func (d *PoissonDistribution) Lambda() int { return d.lambda }
