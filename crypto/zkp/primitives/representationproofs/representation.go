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

package representationproofs

import (
	"fmt"
	"math/big"

	"github.com/xlab-si/emmy/crypto/common"
	"github.com/xlab-si/emmy/crypto/groups"
)

type RepresentationProver struct {
	Group               groups.CyclicGroup
	randomnessSpace *big.Int // GetProofRandomData needs to know how big r could be (problem only in hidden order group)
	secrets             []*big.Int
	bases               []*big.Int
	randomValues        []*big.Int
	y                   *big.Int
}

func NewRepresentationProver(group groups.CyclicGroup, randomnessSpace *big.Int, secrets,
	bases []*big.Int, y *big.Int) (*RepresentationProver, error) {
	if len(secrets) != len(bases) {
		return nil, fmt.Errorf("number of secrets and representation bases shoud be the same")
	}

	return &RepresentationProver{
		Group:               group,
		randomnessSpace: randomnessSpace,
		secrets:             secrets,
		bases:               bases,
		y:                   y,
	}, nil
}

func (prover *RepresentationProver) GetProofRandomData() *big.Int {
	// t = g_1^r_1 * ... * g_k^r_k where g_i are bases and r_i are random values
	t := big.NewInt(1)
	var randomValues []*big.Int
	for i := 0; i < len(prover.bases); i++ {
		r := common.GetRandomInt(prover.randomnessSpace)
		randomValues = append(randomValues, r)
		f := prover.Group.Exp(prover.bases[i], r)
		t = prover.Group.Mul(t, f)
	}
	prover.randomValues = randomValues
	return t
}

func (prover *RepresentationProver) GetProofData(challenge *big.Int) []*big.Int {
	// z_i = r_i + challenge * secrets[i]
	var proofData []*big.Int
	for i := 0; i < len(prover.bases); i++ {
		z_i := prover.Group.Mul(challenge, prover.secrets[i])
		z_i = prover.Group.Add(z_i, prover.randomValues[i])
		proofData = append(proofData, z_i)
	}
	return proofData
}

type RepresentationVerifier struct {
	Group           groups.CyclicGroup
	bases           []*big.Int
	proofRandomData *big.Int
	y               *big.Int
	challengeSpaceSize int
	challenge       *big.Int
}

func NewRepresentationVerifier(group groups.CyclicGroup, bases []*big.Int,
	y *big.Int, challengeSpaceSize int) *RepresentationVerifier {
	return &RepresentationVerifier{
		Group: group,
		bases: bases,
		y:     y,
		challengeSpaceSize: challengeSpaceSize,
	}
}

func (verifier *RepresentationVerifier) SetProofRandomData(proofRandomData *big.Int) {
	verifier.proofRandomData = proofRandomData
}

func (verifier *RepresentationVerifier) GetChallenge() *big.Int {
	challenge := common.GetRandomIntOfLength(verifier.challengeSpaceSize)
	verifier.challenge = challenge
	return challenge
}

func (verifier *RepresentationVerifier) Verify(proofData []*big.Int) bool {
	// check:
	// g_1^z_1 * ... * g_k^z_k = (g_1^x_1 * ... * g_k^x_k)^challenge * (g_1^r_1 * ... * g_k^r_k)
	left := big.NewInt(1)
	for i := 0; i < len(verifier.bases); i++ {
		t := verifier.Group.Exp(verifier.bases[i], proofData[i])
		left = verifier.Group.Mul(left, t)
	}

	right := verifier.Group.Exp(verifier.y, verifier.challenge)
	right = verifier.Group.Mul(right, verifier.proofRandomData)

	return left.Cmp(right) == 0
}
