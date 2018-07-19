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

	"github.com/xlab-si/emmy/crypto/commitments"
	"github.com/xlab-si/emmy/crypto/common"
	"github.com/xlab-si/emmy/crypto/groups"
	"github.com/xlab-si/emmy/crypto/zkp/primitives/qrspecialrsaproofs"
)

// CredentialManager should be created by a user when a credential is to be issued, updated or proved.
// If a new credential under a new nym is needed, new CredentialManager instance is needed.
type CredentialManager struct {
	Params             *Params
	PubKey             *PubKey
	credentialReceiver *UserCredentialReceiver
	nymCommitter       *commitments.PedersenCommitter // nym is actually a commitment to masterSecret
	nym                *big.Int
	masterSecret       *big.Int
	knownAttrs         []*big.Int // attributes that are known to the credential receiver and issuer
	committedAttrs     []*big.Int // attributes for which the issuer knows only commitment
	hiddenAttrs        []*big.Int // attributes which are known only to the credential receiver
	// v1 is a random element in credential - it is generated in GetCredentialRequest and needed when
	// proving the possesion of a credential - this is why it is stored in User and not in UserCredentialReceiver
	v1                 *big.Int                                // v1 is random element in U; U = S^v1 * R_i^m_i where m_i are hidden attributes
	attrsCommitters    []*commitments.DamgardFujisakiCommitter // committers for committedAttrs
	commitmentsOfAttrs []*big.Int                              // commitments of committedAttrs
	credReqNonce       *big.Int
}

func checkAttributesLength(attributes []*big.Int, params *Params) bool {
	for _, attr := range attributes {
		if attr.BitLen() > params.AttrBitLen {
			return false
		}
	}

	return true
}

func NewCredentialManager(params *Params, pubKey *PubKey, masterSecret *big.Int, knownAttrs, committedAttrs,
	hiddenAttrs []*big.Int) (*CredentialManager, error) {
	if !checkAttributesLength(knownAttrs, params) || !checkAttributesLength(committedAttrs, params) ||
		!checkAttributesLength(hiddenAttrs, params) {
		return nil, fmt.Errorf("attributes length not ok")
	}

	attrsCommitters := make([]*commitments.DamgardFujisakiCommitter, len(committedAttrs))
	commitmentsOfAttrs := make([]*big.Int, len(committedAttrs))
	for i, attr := range committedAttrs {
		committer := commitments.NewDamgardFujisakiCommitter(pubKey.N1, pubKey.G, pubKey.H,
			pubKey.N1, params.SecParam)
		com, err := committer.GetCommitMsg(attr)
		if err != nil {
			return nil, fmt.Errorf("error when creating Pedersen commitment: %s", err)
		}
		commitmentsOfAttrs[i] = com
		attrsCommitters[i] = committer
	}

	credManager := CredentialManager{
		Params:             params,
		PubKey:             pubKey,
		knownAttrs:         knownAttrs,
		committedAttrs:     committedAttrs,
		hiddenAttrs:        hiddenAttrs,
		commitmentsOfAttrs: commitmentsOfAttrs,
		attrsCommitters:    attrsCommitters,
		masterSecret:       masterSecret,
	}
	credManager.generateNym()

	return &credManager, nil
}

func NewCredentialManagerFromExisting(params *Params, pubKey *PubKey, masterSecret *big.Int, knownAttrs, committedAttrs,
	hiddenAttrs, commitmentsOfAttrs []*big.Int, credReqNonce *big.Int) (*CredentialManager, error) {

	// nymCommitter is needed only for IssueCredential (when proving that nym can be opened), so we do not need it here
	// the same for attrsCommitters

	return &CredentialManager{
		Params:             params,
		PubKey:             pubKey,
		knownAttrs:         knownAttrs,
		committedAttrs:     committedAttrs,
		hiddenAttrs:        hiddenAttrs,
		commitmentsOfAttrs: commitmentsOfAttrs,
		//attrsCommitters:    attrsCommitters,
		masterSecret: masterSecret,
		credReqNonce: credReqNonce,
	}, nil
}

// generateNym creates a pseudonym to be used with a given organization. Authentication can be done
// with respect to the pseudonym or not.
func (m *CredentialManager) generateNym() error {
	committer := commitments.NewPedersenCommitter(m.PubKey.PedersenParams)
	nym, err := committer.GetCommitMsg(m.masterSecret)
	if err != nil {
		return fmt.Errorf("error when creating Pedersen commitment: %s", err)
	}
	m.nym = nym
	m.nymCommitter = committer

	return nil
}

func (m *CredentialManager) GetCredentialRequest(nonceOrg *big.Int) (*CredentialRequest, error) {
	m.credentialReceiver = NewUserCredentialReceiver(m)
	credReq, err := m.credentialReceiver.GetCredentialRequest(m.nym, nonceOrg)
	if err != nil {
		return nil, err
	}
	m.credReqNonce = credReq.Nonce

	return credReq, nil
}

func (m *CredentialManager) VerifyCredential(cred *Credential,
	AProof *qrspecialrsaproofs.RepresentationProof) (bool, error) {
	// check bit length of e:
	b1 := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(m.Params.EBitLen-1)), nil)
	b22 := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(m.Params.E1BitLen-1)), nil)
	b2 := new(big.Int).Add(b1, b22)

	if (cred.e.Cmp(b1) != 1) || (b2.Cmp(cred.e) != 1) {
		return false, fmt.Errorf("e is not of the proper bit length")
	}
	// check that e is prime
	if !cred.e.ProbablyPrime(20) {
		return false, fmt.Errorf("e is not prime")
	}

	v := new(big.Int).Add(m.v1, cred.v11)
	group := groups.NewQRSpecialRSAPublic(m.PubKey.N)
	// denom = S^v * R_1^attr_1 * ... * R_j^attr_j
	denom := group.Exp(m.PubKey.S, v) // s^v
	for i := 0; i < len(m.knownAttrs); i++ {
		t1 := group.Exp(m.PubKey.RsKnown[i], m.knownAttrs[i])
		denom = group.Mul(denom, t1)
	}

	for i := 0; i < len(m.committedAttrs); i++ {
		t1 := group.Exp(m.PubKey.RsCommitted[i], m.commitmentsOfAttrs[i])
		denom = group.Mul(denom, t1)
	}

	for i := 0; i < len(m.hiddenAttrs); i++ {
		t1 := group.Exp(m.PubKey.RsHidden[i], m.hiddenAttrs[i])
		denom = group.Mul(denom, t1)
	}

	denomInv := group.Inv(denom)
	Q := group.Mul(m.PubKey.Z, denomInv)
	Q1 := group.Exp(cred.A, cred.e)
	if Q1.Cmp(Q) != 0 {
		return false, fmt.Errorf("Q should be A^e (mod n)")
	}

	// verify signature proof:
	ver := qrspecialrsaproofs.NewRepresentationVerifier(group, m.Params.SecParam)
	ver.SetProofRandomData(AProof.ProofRandomData, []*big.Int{Q}, cred.A)
	// check challenge
	context := m.PubKey.GetContext()
	c := common.Hash(context, Q, cred.A, AProof.ProofRandomData, m.credReqNonce)
	if AProof.Challenge.Cmp(c) != 0 {
		return false, fmt.Errorf("challenge is not correct")
	}

	ver.SetChallenge(AProof.Challenge)

	return ver.Verify(AProof.ProofData), nil
}

func (m *CredentialManager) UpdateCredential(knownAttrs []*big.Int) {
	m.knownAttrs = knownAttrs
}

func (m *CredentialManager) randomizeCredential(cred *Credential) *Credential {
	b := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(m.Params.NLength+m.Params.SecParam)), nil)
	r := common.GetRandomInt(b)
	group := groups.NewQRSpecialRSAPublic(m.PubKey.N)
	t := group.Exp(m.PubKey.S, r)
	A := group.Mul(cred.A, t) // cred.A * S^r
	t = new(big.Int).Mul(cred.e, r)
	v11 := new(big.Int).Sub(cred.v11, t) // cred.v11 - e*r (in Z)

	t = new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(m.Params.EBitLen-1)), nil)
	//e1 := new(big.Int).Sub(cred.e, t) // cred.e - 2^(EBitLen-1) // TODO: when is this needed?

	return NewCredential(A, cred.e, v11)
}

func (m *CredentialManager) GetChallenge(credProofRandomData, nonceOrg *big.Int) *big.Int {
	context := m.PubKey.GetContext()
	l := []*big.Int{context, credProofRandomData, nonceOrg}
	//l = append(l, ...) // TODO: add other values

	return common.Hash(l...)
}

func (m *CredentialManager) BuildCredentialProof(cred *Credential, nonceOrg *big.Int) (*Credential,
	*qrspecialrsaproofs.RepresentationProof, error) {
	if m.v1 == nil {
		return nil, nil, fmt.Errorf("v1 is not set in User (generated in GetCredentialRequest)")
	}
	rCred := m.randomizeCredential(cred)
	// Z = cred.A^cred.e * S^cred.v11 * R_1^m_1 * ... * R_l^m_l
	// Z = rCred.A^rCred.e * S^rCred.v11 * R_1^m_1 * ... * R_l^m_l
	group := groups.NewQRSpecialRSAPublic(m.PubKey.N)
	bases := append(m.PubKey.RsHidden, rCred.A)
	bases = append(bases, m.PubKey.S)
	secrets := append(m.hiddenAttrs, rCred.e)
	v := new(big.Int).Add(rCred.v11, m.v1)
	secrets = append(secrets, v)

	denom := big.NewInt(1)
	for i := 0; i < len(m.knownAttrs); i++ {
		t1 := group.Exp(m.PubKey.RsKnown[i], m.knownAttrs[i])
		denom = group.Mul(denom, t1)
	}

	for i := 0; i < len(m.committedAttrs); i++ {
		t1 := group.Exp(m.PubKey.RsCommitted[i], m.commitmentsOfAttrs[i])
		denom = group.Mul(denom, t1)
	}
	denomInv := group.Inv(denom)
	y := group.Mul(m.PubKey.Z, denomInv)

	prover := qrspecialrsaproofs.NewRepresentationProver(group, m.Params.SecParam,
		secrets, bases, y)

	// boundary for m_tilde
	b_m := m.Params.AttrBitLen + m.Params.SecParam + m.Params.HashBitLen
	// boundary for e
	b_e := m.Params.EBitLen + m.Params.SecParam + m.Params.HashBitLen
	// boundary for v1
	b_v1 := m.Params.VBitLen + m.Params.SecParam + m.Params.HashBitLen

	boundaries := make([]int, len(m.PubKey.RsHidden))
	for i, _ := range m.PubKey.RsHidden {
		boundaries[i] = b_m
	}
	boundaries = append(boundaries, b_e)
	boundaries = append(boundaries, b_v1)

	proofRandomData, err := prover.GetProofRandomDataGivenBoundaries(boundaries, true)
	if err != nil {
		return nil, nil, fmt.Errorf("error when generating representation proof random data: %s", err)
	}

	challenge := m.GetChallenge(proofRandomData, nonceOrg)
	proofData := prover.GetProofData(challenge)

	return rCred, qrspecialrsaproofs.NewRepresentationProof(proofRandomData, challenge, proofData), nil
}