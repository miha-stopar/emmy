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

package cl

import (
	"fmt"
	"math/big"

	"github.com/xlab-si/emmy/crypto/common"
	"github.com/xlab-si/emmy/crypto/groups"
	"github.com/xlab-si/emmy/crypto/zkp/primitives/dlogproofs"
	"github.com/xlab-si/emmy/crypto/zkp/primitives/qrspecialrsaproofs"
)

type UserCredentialReceiver struct {
	User      *User
	v1        *big.Int // v1 is the random element in U, which is constructed also from clPubKey.R_list and attrs
	U         *big.Int
	nymProver *dlogproofs.SchnorrProver // for proving that nym is of the proper form
	// TODO: not sure what would be the most appropriate name for UProver and UTilde - currently
	// they have upper case U as it is in paper
	UProver  *qrspecialrsaproofs.RepresentationProver // for proving that U is of the proper form
	nymTilde *big.Int                                 // proof random data for nym (proving that nym is of proper form)
	UTilde   *big.Int                                 // proof random data for U (proving that U is of proper form)
}

func NewUserCredentialReceiver(user *User) *UserCredentialReceiver {
	return &UserCredentialReceiver{
		User: user,
	}
}

// GetU returns U = S^v1 * R_1^m_1 * ... * R_NumAttrs^m_NumAttrs (mod n) where v1 is from +-{0,1}^(NLength + SecParam)
func (r *UserCredentialReceiver) GetU() *big.Int { // TODO: should be SetU?
	exp := big.NewInt(int64(r.User.ParamSizes.NLength + r.User.ParamSizes.SecParam))
	b := new(big.Int).Exp(big.NewInt(2), exp, nil)
	v1 := common.GetRandomIntAlsoNeg(b)
	r.v1 = v1

	group := groups.NewQRSpecialRSAPublic(r.User.PubKey.N)
	U := group.Exp(r.User.PubKey.S, v1)

	// the number of attributes, type (A_k - issuer knows an attribute, A_c - issuer knows
	// a commitment to the attribute, A_h - issuer does not know the attribute)
	// TODO: currently only for A_k
	for i, attr := range r.User.attrs {
		t := group.Exp(r.User.PubKey.RsKnown[i], attr) // R_i^m_i
		U = group.Mul(U, t)
	}
	r.U = U

	return U
}

// getNymProofRandomData return proof random data for nym.
func (rcv *UserCredentialReceiver) getNymProofRandomData(nymName string) (*big.Int, error) {
	// use Schnorr with two bases for proving that you know nym opening:
	bases := []*big.Int{
		rcv.User.PedersenParams.Group.G,
		rcv.User.PedersenParams.H,
	}
	committer := rcv.User.Committers[nymName]
	val, r := committer.GetDecommitMsg() // val is actually master key
	secrets := []*big.Int{val, r}

	prover, err := dlogproofs.NewSchnorrProver(rcv.User.PedersenParams.Group, secrets[:], bases[:],
		committer.Commitment)
	if err != nil {
		return nil, fmt.Errorf("error when creating Schnorr prover: %s", err)
	}
	rcv.nymProver = prover

	nymTilde := prover.GetProofRandomData()
	return nymTilde, nil
}

func (r *UserCredentialReceiver) getUProofRandomData() (*big.Int, error) {
	group := groups.NewQRSpecialRSAPublic(r.User.PubKey.N)
	// secrets are [attr_1, ..., attr_L, v1]
	secrets := append(r.User.attrs, r.v1)

	// bases are [R_1, ..., R_L, S]
	bases := append(r.User.PubKey.RsKnown, r.User.PubKey.S)

	prover := qrspecialrsaproofs.NewRepresentationProver(group, r.User.ParamSizes.SecParam,
		secrets[:], bases[:], r.U)
	r.UProver = prover

	// boundary for m_tilde
	b_m := r.User.ParamSizes.AttrBitLen + r.User.ParamSizes.SecParam + r.User.ParamSizes.HashBitLen + 1
	// boundary for v1
	b_v1 := r.User.ParamSizes.NLength + 2* r.User.ParamSizes.SecParam + r.User.ParamSizes.HashBitLen

	boundaries := make([]int, len(r.User.PubKey.RsKnown))
	for i := 0; i < len(r.User.PubKey.RsKnown); i++ {
		boundaries[i] = b_m
	}
	boundaries = append(boundaries, b_v1)

	UTilde, err := prover.GetProofRandomDataGivenBoundaries(boundaries, true)
	if err != nil {
		return nil, fmt.Errorf("error when generating representation proof random data: %s", err)
	}

	return UTilde, nil
}

// GetChallenge returns Hash(context||U||nym||U_tilde||nym_tilde||n1). Thus, Fiat-Shamir is used to
// generate a challenge, instead of asking verifier to generate it.
func (r *UserCredentialReceiver) GetChallenge(U, nym, n1 *big.Int) *big.Int {
	context := r.User.PubKey.GetContext()
	return common.Hash(context, U, nym, n1)
}

func (r *UserCredentialReceiver) getCredentialRequestProoRandomfData(nymName string) (*big.Int, *big.Int, error) {
	nymProofRandomData, err := r.getNymProofRandomData(nymName)
	if err != nil {
		return nil, nil, fmt.Errorf("error when obtaining nym proof random data: %v", err)
	}

	UProofRandomData, err := r.getUProofRandomData()
	if err != nil {
		return nil, nil, fmt.Errorf("error when obtaining U proof random data: %v", err)
	}
	return nymProofRandomData, UProofRandomData, nil
}

func (r *UserCredentialReceiver) getCredentialRequestProofData(challenge *big.Int) ([]*big.Int, []*big.Int) {
	return r.nymProver.GetProofData(challenge), r.UProver.GetProofData(challenge)
}

func (r *UserCredentialReceiver) GetCredentialRequest(nymName string, nym, U, n1 *big.Int) (*dlogproofs.SchnorrProof,
	*qrspecialrsaproofs.RepresentationProof, error) {
	nymProofRandomData, UProofRandomData, err := r.getCredentialRequestProoRandomfData(nymName)
	if err != nil {
		return nil, nil, err
	}

	challenge := r.GetChallenge(U, nym, n1)
	nymProofData, UProofData := r.getCredentialRequestProofData(challenge)
	return dlogproofs.NewSchnorrProof(nymProofRandomData, challenge, nymProofData),
		qrspecialrsaproofs.NewRepresentationProof(UProofRandomData, challenge, UProofData), nil
}

func (r *UserCredentialReceiver) GetNonce() *big.Int {
	b := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(r.User.ParamSizes.SecParam)), nil)
	return common.GetRandomInt(b)
}

func (r *UserCredentialReceiver) VerifyCredential(A, e, v11 *big.Int,
	AProof *qrspecialrsaproofs.RepresentationProof, n2 *big.Int) (bool, error) {
	// check bit length of e:
	b1 := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(r.User.ParamSizes.EBitLen-1)), nil)
	b22 := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(r.User.ParamSizes.E1BitLen-1)), nil)
	b2 := new(big.Int).Add(b1, b22)

	if (e.Cmp(b1) != 1) || (b2.Cmp(e) != 1) {
		return false, fmt.Errorf("e is not of the proper bit length")
	}
	// check that e is prime
	if !e.ProbablyPrime(20) {
		return false, fmt.Errorf("e is not prime")
	}

	v := new(big.Int).Add(r.v1, v11)
	group := groups.NewQRSpecialRSAPublic(r.User.PubKey.N)
	// denom = S^v * R_1^attr_1 * ... * R_j^attr_j where only attributes from A_k (known)
	denom := group.Exp(r.User.PubKey.S, v) // s^v
	/*
		for i := 0; i < len(u.User.attrs); i++ { // TODO: from not known attributes
			t1 := group.Exp(u.User.PubKey.R_list[i], u.User.attrs[i]) // TODO: R_list should be replaced with those that correspond to A_k
			denom = group.Mul(denom, t1)
		}
	*/

	denomInv := group.Inv(denom)
	Q := group.Mul(r.User.PubKey.Z, denomInv)
	Q1 := group.Exp(A, e)
	if Q1.Cmp(Q) != 0 {
		return false, fmt.Errorf("Q should be A^e (mod n)")
	}

	// verify signature proof:
	credentialVerifier := qrspecialrsaproofs.NewRepresentationVerifier(group, r.User.ParamSizes.SecParam)
	credentialVerifier.SetProofRandomData(AProof.ProofRandomData, []*big.Int{Q}, A)
	// check challenge
	context := r.User.PubKey.GetContext()
	c := common.Hash(context, Q, A, AProof.ProofRandomData, n2)
	if AProof.Challenge.Cmp(c) != 0 {
		return false, fmt.Errorf("challenge is not correct")
	}

	credentialVerifier.SetChallenge(AProof.Challenge)
	return credentialVerifier.Verify(AProof.ProofData), nil
}
