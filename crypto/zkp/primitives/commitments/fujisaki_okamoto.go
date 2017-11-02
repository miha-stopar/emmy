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
	"github.com/xlab-si/emmy/crypto/commitments"
	"github.com/xlab-si/emmy/crypto/common"
	"fmt"
)

// ProveFujisakiOkamotoCommitmentPreimageKnowledge demonstrates how to prove that for c you know
// (x, r) such that commit(x, r) = c.
func ProveFujisakiOkamotoCommitmentPreimageKnowledge() (bool, error) {
	receiver, err := commitments.NewFujisakiOkamotoReceiver(1024, 1024)
	if err != nil {
		return false, err
	}
	committer := commitments.NewFujisakiOkamotoCommitter(receiver.SpecialRSA.N, receiver.B0, receiver.B1,
		receiver.SecureParam)

	a := common.GetRandomInt(receiver.SpecialRSA.N)
	c, err := committer.GetCommitMsg(a)
	if err != nil {
		return false, err
	}

	receiver.SetCommitment(c)

	prover := NewFujisakiOkamotoPreimageKnowledgeProver()



	fmt.Println(prover)

	return false, nil
}

type FujisakiOkamotoPreimageKnowledgeProver struct {

}

func NewFujisakiOkamotoPreimageKnowledgeProver() *FujisakiOkamotoPreimageKnowledgeProver {

	return &FujisakiOkamotoPreimageKnowledgeProver {

	}
}


type FujisakiOkamotoPreimageKnowledgeVerifier struct {

}

func NewFujisakiOkamotoPreimageKnowledgeVerifier() *FujisakiOkamotoPreimageKnowledgeVerifier {

	return &FujisakiOkamotoPreimageKnowledgeVerifier {

	}
}


