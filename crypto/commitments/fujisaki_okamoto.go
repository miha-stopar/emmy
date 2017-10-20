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

package commitments

import (
	"github.com/xlab-si/emmy/crypto/common"
	"github.com/xlab-si/emmy/crypto/dlog"
	"math/big"
	"errors"
	"fmt"
)

func FujisakiOkamoto() (bool, error){
	receiver, err := NewFujisakiOkamotoReceiver(1024, 1024)
	if err != nil {
		return false, err
	}
	committer := NewFujisakiOkamotoCommitter(receiver.SpecialRSA.N, receiver.B0, receiver.B1,
		receiver.SecureParam)

	a := common.GetRandomInt(receiver.SpecialRSA.N)
	c, err := committer.GetCommitMsg(a)
	if err != nil {
		return false, err
	}

	receiver.SetCommitment(c)
	committedVal, r := committer.GetDecommitMsg()
	success := receiver.CheckDecommitment(r, committedVal)

	return success, nil
}

// Fujisaki-Okamoto commitment scheme is an extension of Pedersen commitment to the RSA modulus.
type FujisakiOkamotoCommitter struct {
	N               *big.Int
	B0              *big.Int
	B1              *big.Int
	SecureParam		int // random value r in commitment is chosen such that < 2^SecureParam * N
	committedValue  *big.Int
	r               *big.Int
}

func NewFujisakiOkamotoCommitter(N, B0, B1 *big.Int, secureParam int) *FujisakiOkamotoCommitter {
	return &FujisakiOkamotoCommitter{
		N: N,
		B0: B0,
		B1: B1,
		SecureParam: secureParam,
	}
}

func (committer *FujisakiOkamotoCommitter) GetCommitMsg(a *big.Int) (*big.Int, error) {
	if a.Cmp(committer.N) != -1 {
		err := errors.New("the committed value needs to be < N")
		return nil, err
	}
	max := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(committer.SecureParam)), nil)
	max.Mul(max, committer.N) // r is random from [0, 2^m * N)
	r := common.GetRandomInt(committer.N)

	H := common.NewZnGroup(committer.N)
	// c = b0^a * b1^r mod N
	t1 := H.Exp(committer.B0, a)
	t2 := H.Exp(committer.B1, r)
	c := H.Mul(t1, t2)
	committer.committedValue = a
	committer.r = r
	return c, nil
}

func (committer *FujisakiOkamotoCommitter) GetDecommitMsg() (*big.Int, *big.Int) {
	return committer.committedValue, committer.r
}

type FujisakiOkamotoReceiver struct {
	SpecialRSA 		*dlog.SpecialRSA
	B0				*big.Int
	B1				*big.Int
	SecureParam		int // random value r in commitment is chosen such that < 2^SecureParam * N
	commitment      *big.Int
}

func NewFujisakiOkamotoReceiver(safePrimeBitLength, secureParam int) (*FujisakiOkamotoReceiver, error) {
	rsa, err := dlog.NewSpecialRSA(safePrimeBitLength)
	if err != nil {
		return nil, err
	}

	// get generator for a subgroup of Z_P* of order p
	g_p, err := common.GetGeneratorOfZnSubgroup(rsa.P, new(big.Int).Sub(rsa.P, big.NewInt(1)), rsa.SmallP)
	if err != nil {
		return nil, err
	}
	// get generator for a subgroup of Z_Q* of order q
	g_q, err := common.GetGeneratorOfZnSubgroup(rsa.Q, new(big.Int).Sub(rsa.Q, big.NewInt(1)), rsa.SmallQ)
	if err != nil {
		return nil, err
	}

	// compute via CRT b_0 such that:
	// b_0 = g_p mod P
	// b_0 = g_q mod Q
	b0, err := common.CRT(g_p, g_q, rsa.P, rsa.Q)
	if err != nil {
		return nil, err
	}
	// Note that b0 is the generator of the group of order p*q in Z_(P*Q)* because:
	// b0^(p*q) = (b0^p)^q = (g_p^p)^q = 1^q = 1 (mod P)
	// b0^(p*q) = 1 (mod Q)
	// So: b0^(p*q) = 1 (mod P*Q)

	// choose random alpha from Z_(p*q)*:
	alpha := common.GetRandomZnInvertibleElement(new(big.Int).Mul(rsa.SmallP, rsa.SmallQ))

	// b1 = b0^alpha mod N
	b1 := new(big.Int).Exp(b0, alpha, rsa.N)

	return &FujisakiOkamotoReceiver{
		SpecialRSA: rsa,
		B0: b0,
		B1: b1,
		SecureParam: secureParam,
	}, nil
}

// When receiver receives a commitment, it stores the value using SetCommitment method.
func (receiver *FujisakiOkamotoReceiver) SetCommitment(c *big.Int) {
	receiver.commitment = c
}

func (receiver *FujisakiOkamotoReceiver) CheckDecommitment(r, a *big.Int) bool {
	H := common.NewZnGroup(receiver.SpecialRSA.N) // TODO: SpecialRSA should itself has add, mul ... methods
	// c = b0^a * b1^r mod N
	t1 := H.Exp(receiver.B0, a)
	t2 := H.Exp(receiver.B1, r)
	c := H.Mul(t1, t2)

	return c.Cmp(receiver.commitment) == 0
}

