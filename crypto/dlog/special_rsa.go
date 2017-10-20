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

