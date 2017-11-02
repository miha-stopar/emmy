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
)

func DamgardFujisaki() (bool, error){
	receiver, err := NewDamgardFujisakiReceiver(1024)
	if err != nil {
		return false, err
	}
	committer := NewDamgardFujisakiCommitter(receiver.SpecialRSA.N, receiver.G, receiver.G1)

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

type DamgardFujisakiCommitter struct {
	N               *big.Int
	G               *big.Int
	G1               *big.Int
	committedValue  *big.Int
	r               *big.Int
}

func NewDamgardFujisakiCommitter(n, g, g1 *big.Int) *DamgardFujisakiCommitter {
	return &DamgardFujisakiCommitter{
		N: n,
		G: g,
		G1: g1,
	}
}

func (committer *DamgardFujisakiCommitter) GetCommitMsg(a *big.Int) (*big.Int, error) {
	if a.Cmp(committer.N) != -1 {
		err := errors.New("the committed value needs to be < N")
		return nil, err
	}
	r := common.GetRandomInt(committer.N)

	c := r

	committer.committedValue = a
	committer.r = r
	return c, nil
}

func (committer *DamgardFujisakiCommitter) GetDecommitMsg() (*big.Int, *big.Int) {
	return committer.committedValue, committer.r
}

type DamgardFujisakiReceiver struct {
	SpecialRSA 		*dlog.SpecialRSA
	G				*big.Int
	G1				*big.Int
	commitment      *big.Int
}

func NewDamgardFujisakiReceiver(safePrimeBitLength int) (*DamgardFujisakiReceiver, error) {
	rsa, err := dlog.NewSpecialRSA(safePrimeBitLength)
	if err != nil {
		return nil, err
	}

	// choose g, g1 from QR_n:
	g, err := rsa.GetGeneratorOfQR()
	if err != nil {
		return nil, err
	}
	g1, err := rsa.GetGeneratorOfQR()
	if err != nil {
		return nil, err
	}

	return &DamgardFujisakiReceiver{
		SpecialRSA: rsa,
		G: g,
		G1: g1,
	}, nil
}

// When receiver receives a commitment, it stores the value using SetCommitment method.
func (receiver *DamgardFujisakiReceiver) SetCommitment(c *big.Int) {
	receiver.commitment = c
}

func (receiver *DamgardFujisakiReceiver) CheckDecommitment(r, a *big.Int) bool {
	/*
	H := common.NewZnGroup(receiver.SpecialRSA.N) // TODO: SpecialRSA should itself has add, mul ... methods
	// c = b0^a * b1^r mod N
	t1 := H.Exp(receiver.B0, a)
	t2 := H.Exp(receiver.B1, r)
	c := H.Mul(t1, t2)
	*/
	c := big.NewInt(0)

	return c.Cmp(receiver.commitment) == 0
}

