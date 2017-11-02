/*
 * Copyright 2017 XLAB d.o.o.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package dlog

import (
	"math/big"
	"github.com/xlab-si/emmy/crypto/common"
)

type SpecialRSA struct {
	N  *big.Int // N = P * Q, P = 2*p + 1, Q = 2*q + 1
	P *big.Int
	Q *big.Int
	SmallP *big.Int
	SmallQ *big.Int
}

func NewSpecialRSA(safePrimeBitLength int) (*SpecialRSA, error) {
	P, Q, p, q, err := common.GetSpecialRSAPrimes(safePrimeBitLength)
	if err != nil {
		return nil, err
	}
	N := new(big.Int).Mul(P, Q)
	return &SpecialRSA{
		N: N,
		P: P,
		Q: Q,
		SmallP: p,
		SmallQ: q,
	}, nil
}

// GetGeneratorOfCompositeQR returns a generator of a group of quadratic residues.
// The parameters p and q need to be safe primes.
func (rsa *SpecialRSA) GetGeneratorOfQR() (g *big.Int, err error) {
	one := big.NewInt(1)
	tmp := new(big.Int)

	// The possible orders are 2, p1, q1, 2 * p1, 2 * q1, and 2 * p1 * q1.
	// We need to make sure that all elements of orders smaller than 2 * p1 * q1 are ruled out.

	for {
		a := common.GetRandomInt(rsa.N)
		a_plus := new(big.Int).Add(a, one)
		a_min := new(big.Int).Sub(a, one)
		tmp.GCD(nil, nil, a, rsa.P)
		// p
		if tmp.Cmp(one) != 0 {
			continue
		}
		tmp.GCD(nil, nil, a_plus, rsa.P)
		if tmp.Cmp(one) != 0 {
			continue
		}
		tmp.GCD(nil, nil, a_min, rsa.Q)
		if tmp.Cmp(one) != 0 {
			continue
		}

		// q
		tmp.GCD(nil, nil, a, rsa.Q)
		if tmp.Cmp(one) != 0 {
			continue
		}
		tmp.GCD(nil, nil, a_plus, rsa.Q)
		if tmp.Cmp(one) != 0 {
			continue
		}
		tmp.GCD(nil, nil, a_min, rsa.Q)
		if tmp.Cmp(one) != 0 {
			continue
		}

		g := a.Mul(a, big.NewInt(2))
		return g, nil
	}
}
