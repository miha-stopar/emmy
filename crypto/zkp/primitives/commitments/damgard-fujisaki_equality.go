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

package commitmentzkp

import (
	"math/big"

	"github.com/xlab-si/emmy/crypto/commitments"
	"github.com/xlab-si/emmy/crypto/common"
)

type DFCommitmentEqualityProver struct {
	committer1         *commitments.DamgardFujisakiCommitter
	committer2         *commitments.DamgardFujisakiCommitter
	challengeSpaceSize int
	r1                 *big.Int
	r21                *big.Int
	r22                *big.Int
}

func NewDFCommitmentEqualityProver(committer1, committer2 *commitments.DamgardFujisakiCommitter,
	challengeSpaceSize int) *DFCommitmentEqualityProver {
	return &DFCommitmentEqualityProver{
		committer1:         committer1,
		committer2:         committer2,
		challengeSpaceSize: challengeSpaceSize,
	}
}

func (prover *DFCommitmentEqualityProver) GetProofRandomData() (*big.Int, *big.Int) {
	// r1 from [0, T * 2^(NLength + ChallengeSpaceSize))
	nLen := prover.committer1.QRSpecialRSA.N.BitLen()
	exp := big.NewInt(int64(nLen + prover.challengeSpaceSize))
	b := new(big.Int).Exp(big.NewInt(2), exp, nil)
	b.Mul(b, prover.committer1.T)
	r1 := common.GetRandomInt(b)
	prover.r1 = r1

	// r21 from [0, 2^(B + 2*NLength + ChallengeSpaceSize))
	b = new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(
		prover.committer1.B+2*nLen+prover.challengeSpaceSize)), nil)
	r21 := common.GetRandomInt(b)
	prover.r21 = r21

	// r12 from [0, 2^(B + 2*NLength + ChallengeSpaceSize))
	b = new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(
		prover.committer1.B+2*nLen+prover.challengeSpaceSize)), nil)
	r22 := common.GetRandomInt(b)
	prover.r22 = r22
	// G^r1 * H^r12, G^r1 * H^r22
	t1 := prover.committer1.ComputeCommit(r1, r21)
	t2 := prover.committer2.ComputeCommit(r1, r22)
	return t1, t2
}

func (prover *DFCommitmentEqualityProver) GetProofData(challenge *big.Int) (*big.Int,
	*big.Int, *big.Int) {
	// s1 = r1 + challenge*a (in Z, not modulo)
	// s21 = r21 + challenge*rr1 (in Z, not modulo)
	// s22 = r21 + challenge*rr2 (in Z, not modulo)
	a, rr1 := prover.committer1.GetDecommitMsg()
	_, rr2 := prover.committer2.GetDecommitMsg()
	s1 := new(big.Int).Mul(challenge, a)
	s1.Add(s1, prover.r1)
	s21 := new(big.Int).Mul(challenge, rr1)
	s21.Add(s21, prover.r21)
	s22 := new(big.Int).Mul(challenge, rr2)
	s22.Add(s22, prover.r22)
	return s1, s21, s22
}

type DFCommitmentEqualityVerifier struct {
	receiver1          *commitments.DamgardFujisakiReceiver
	receiver2          *commitments.DamgardFujisakiReceiver
	challengeSpaceSize int
	challenge          *big.Int
	proofRandomData1   *big.Int
	proofRandomData2   *big.Int
}

func NewDFCommitmentEqualityVerifier(receiver1, receiver2 *commitments.DamgardFujisakiReceiver,
	challengeSpaceSize int) *DFCommitmentEqualityVerifier {
	return &DFCommitmentEqualityVerifier{
		receiver1:          receiver1,
		receiver2:          receiver2,
		challengeSpaceSize: challengeSpaceSize,
	}
}

func (verifier *DFCommitmentEqualityVerifier) SetProofRandomData(proofRandomData1,
	proofRandomData2 *big.Int) {
	verifier.proofRandomData1 = proofRandomData1
	verifier.proofRandomData2 = proofRandomData2
}

func (verifier *DFCommitmentEqualityVerifier) GetChallenge() *big.Int {
	exp := big.NewInt(int64(verifier.challengeSpaceSize))
	b := new(big.Int).Exp(big.NewInt(2), exp, nil)
	challenge := common.GetRandomInt(b)
	verifier.challenge = challenge
	return challenge
}

func (verifier *DFCommitmentEqualityVerifier) Verify(s1, s21, s22 *big.Int) bool {
	// verify proofRandomData1 * verifier.receiver1.Commitment^challenge = G^s1 * H^s21 mod n1
	// verify proofRandomData2 * verifier.receiver2.Commitment^challenge = G^s1 * H^s22 mod n2
	left1 := verifier.receiver1.QRSpecialRSA.Exp(verifier.receiver1.Commitment, verifier.challenge)
	left1 = verifier.receiver1.QRSpecialRSA.Mul(verifier.proofRandomData1, left1)
	right1 := verifier.receiver1.ComputeCommit(s1, s21)

	left2 := verifier.receiver2.QRSpecialRSA.Exp(verifier.receiver2.Commitment, verifier.challenge)
	left2 = verifier.receiver2.QRSpecialRSA.Mul(verifier.proofRandomData2, left2)
	right2 := verifier.receiver2.ComputeCommit(s1, s22)
	return left1.Cmp(right1) == 0 && left2.Cmp(right2) == 0
}
