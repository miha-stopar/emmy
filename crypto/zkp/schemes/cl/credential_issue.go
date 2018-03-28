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
	"github.com/xlab-si/emmy/crypto/commitments"
	"github.com/xlab-si/emmy/crypto/common"
	"github.com/xlab-si/emmy/crypto/groups"
	"math/big"
)

type CLParamSizes struct {
	RhoBitLen int // bit length of order of the commitment group
	L_n       int // bit length of RSA modulus
	L_attrs   int // number of attributes
}

// TODO: load params from file or blockchain or wherever they will be stored.
func GetParamSizes() *CLParamSizes {
	return &CLParamSizes{
		RhoBitLen: 256,
		L_n:       1024,
		L_attrs:   3,
	}
}

type CommitmentParams struct {
	Group *groups.SchnorrGroup
	H     *big.Int
}

func GenerateCommitmentParams(bitLengthGroupOrder int) (*CommitmentParams, error) {
	receiver, err := commitments.NewPedersenReceiver(bitLengthGroupOrder)
	if err != nil {
		return nil, fmt.Errorf("error when creating Pedersen receiver: %s", err)
	}

	return &CommitmentParams{
		Group: receiver.Group,
		H:     receiver.H,
	}, nil
}

type User struct {
	CommitmentParams *CommitmentParams
	masterSecret     *big.Int
	nyms             map[string]*big.Int
}

func NewUser(commitmentParams *CommitmentParams) *User {
	nyms := make(map[string]*big.Int)

	return &User{
		CommitmentParams: commitmentParams,
		nyms:             nyms,
	}
}

func (u *User) GenerateMasterSecret() {
	u.masterSecret = common.GetRandomInt(u.CommitmentParams.Group.Q)
}

// GenerateNym creates a pseudonym to be used with a given organization. Multiple pseudonyms
// can be generated for the same organization (on the contrary domain pseudonym can be only
// one per organization - not implemented yet). Authentication can be done with respect to
// the pseudonym or not (depends on the server configuration).
func (u *User) GenerateNym(orgName string) (*big.Int, error) {
	committer := commitments.NewPedersenCommitter(u.CommitmentParams.Group)
	com, err := committer.GetCommitMsg(u.masterSecret)
	if err != nil {
		return nil, fmt.Errorf("error when creating Pedersen commitment: %s", err)
	}
	u.nyms[orgName] = com
	return com, nil
}
