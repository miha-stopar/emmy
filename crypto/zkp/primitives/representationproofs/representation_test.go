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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/xlab-si/emmy/crypto/common"
	"github.com/xlab-si/emmy/crypto/groups"
	"math/big"
)

// TestRepresentationProof demonstrates how the prover proves that it knows (x_1,...,x_k)
// such that y = g_1^x_1 * ... * g_k^x_k where g_i are given generators of cyclic group G.
// Note that Schnorr is a special case of RepresentationProver where only one base is used.
func TestRepresentationProofWithSchnorr(t *testing.T) {
	group, err := groups.NewSchnorrGroup(256)
	if err != nil {
		t.Errorf("error when generating SchnorrGroup: %v", err)
	}

	var bases [3]*big.Int
	for i := 0; i < len(bases); i++ {
		base := group.GetRandomElement()
		bases[i] = base
	}

	var secrets [3]*big.Int
	for i := 0; i < 3; i++ {
		secret := common.GetRandomInt(group.Q)
		secrets[i] = secret
	}

	// y = g_1^x_1 * ... * g_k^x_k where g_i are bases and x_i are secrets
	y := big.NewInt(1)
	for i := 0; i < 3; i++ {
		f := group.Exp(bases[i], secrets[i])
		y = group.Mul(y, f)
	}

	prover, err := NewRepresentationProver(group, group.Q, secrets[:], bases[:], y)
	if err != nil {
		t.Errorf("error when instantiating RepresentationProver with Schnorr group")
	}
	verifier := NewRepresentationVerifier(group, bases[:], y, 80)

	proofRandomData := prover.GetProofRandomData()
	verifier.SetProofRandomData(proofRandomData)

	challenge := verifier.GetChallenge()
	proofData := prover.GetProofData(challenge)
	verified := verifier.Verify(proofData)

	assert.Equal(t, true, verified,
		"proof of knowledge of representation with Schnorr does not work correctly")
}

func TestRepresentationProofWithQRSpecialRSA(t *testing.T) {
	group, err := groups.NewQRSpecialRSA(512)
	if err != nil {
		t.Errorf("error when generating QRSpecialRSA group: %v", err)
	}

	var bases [3]*big.Int
	for i := 0; i < len(bases); i++ {
		base, err := group.GetRandomElement()
		if err != nil {
			t.Errorf("error when search for random element: %v", err)
		}
		bases[i] = base
	}

	var secrets [3]*big.Int
	for i := 0; i < 3; i++ {
		secret := common.GetRandomInt(new(big.Int).Div(group.N, big.NewInt(100)))
		secrets[i] = secret
	}

	// y = g_1^x_1 * ... * g_k^x_k where g_i are bases and x_i are secrets
	y := big.NewInt(1)
	for i := 0; i < 3; i++ {
		f := group.Exp(bases[i], secrets[i])
		y = group.Mul(y, f)
	}

	b := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(group.N.BitLen() + 80)), nil)
	prover, err := NewRepresentationProver(group, b, secrets[:], bases[:], y)
	if err != nil {
		t.Errorf("error when instantiating RepresentationProver with QRSpecialRSA group")
	}
	verifier := NewRepresentationVerifier(group, bases[:], y, 80)

	proofRandomData := prover.GetProofRandomData()
	verifier.SetProofRandomData(proofRandomData)

	challenge := verifier.GetChallenge()
	proofData := prover.GetProofData(challenge)
	verified := verifier.Verify(proofData)

	assert.Equal(t, true, verified,
		"proof of knowledge of representation with QRSpecialRSA does not work correctly")
}
