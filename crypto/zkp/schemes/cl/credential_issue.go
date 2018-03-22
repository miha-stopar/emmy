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
	"math/big"
	"github.com/xlab-si/emmy/crypto/common"
	"github.com/xlab-si/emmy/crypto/groups"
	"fmt"
	"github.com/xlab-si/emmy/crypto/commitments"
)

type CLParamSizes struct {
	RhoBitLen int // bit length of order of the commitment group
}

// TODO: load params from file or blockchain or wherever they will be stored.
func GetParamSizes() *CLParamSizes {
	return &CLParamSizes{
		RhoBitLen: 256,
	}
}

type CLParams struct {
	CommitmentGroup *groups.SchnorrGroup
	CommitmentH *big.Int
}

func GenerateParams(paramSizes *CLParamSizes) (*CLParams, error) {
	// There are only a few possibilities for RhoBitLen. 256 implies that the modulus
	// bit length is 2048 (this number corresponds to the Gamma in idemix technical report).
	commitmentGroup, err := groups.NewSchnorrGroup(paramSizes.RhoBitLen)
	if err != nil {
		return nil, fmt.Errorf("error when creating SchnorrGroup: %s", err)
	}

	a := common.GetRandomInt(commitmentGroup.Q)
	h := commitmentGroup.Exp(commitmentGroup.G, a)

	// what to do with h? trapdoor not needed any more due to different ZKP technique
	// should be h pushed into PedersenCommitter constructor?

	return &CLParams{
		CommitmentGroup: commitmentGroup, // commitmentGroup.G is Rho from idemix technical report
		CommitmentH: h,
	}, nil
}

type User struct {
	CLParams *CLParams
	masterSecret               *big.Int
	nyms map[string]*big.Int
}

func NewUser(clParams *CLParams) *User {
	nyms := make(map[string]*big.Int)

	return &User{
		CLParams: clParams,
		nyms: nyms,
	}
}

func (u *User) GenerateMasterSecret() {
	u.masterSecret = common.GetRandomInt(u.CLParams.CommitmentGroup.Q)
}

// GenerateNym creates a pseudonym to be used with a given organization. Multiple pseudonyms
// can be generated for the same organization (on the contrary domain pseudonym can be only
// one per organization - not implemented yet). Authentication can be done with respect to
// the pseudonym or not (depends on the server configuration).
func (u *User) GenerateNym(orgName string) (*big.Int, error) {
	committer := commitments.NewPedersenCommitter(u.CLParams.CommitmentGroup)
	com, err := committer.GetCommitMsg(u.masterSecret)
	if err != nil {
		return nil, fmt.Errorf("error when creating Pedersen commitment: %s", err)
	}
	u.nyms[orgName] = com
	return com, nil
}




