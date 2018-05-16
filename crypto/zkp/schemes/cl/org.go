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
)

type PubKey struct {
	N       *big.Int
	S       *big.Int
	Z       *big.Int
	RsKnown []*big.Int // one R corresponds to one attribute - these R are used for attributes that are known to the issuer
	// TODO: RsCommitted, RsHidden
}

func NewCLPubKey(N *big.Int, S, Z *big.Int, R_L []*big.Int) *PubKey {
	return &PubKey{
		N:       N,
		S:       S,
		Z:       Z,
		RsKnown: R_L,
	}
}

// GetContext concatenates public parameters and returns a corresponding number.
func (k *PubKey) GetContext() *big.Int {
	numbers := make([]*big.Int, len(k.RsKnown)+3)
	numbers[0] = k.N
	numbers[1] = k.S
	numbers[2] = k.Z
	for i, r := range k.RsKnown {
		numbers[i+3] = r
	}
	concatenated := common.ConcatenateNumbers(numbers...)
	return new(big.Int).SetBytes(concatenated)
}

type Org struct {
	Name             string
	ParamSizes       *CLParamSizes
	Group            *groups.QRSpecialRSA
	PedersenReceiver *commitments.PedersenReceiver
	PubKey           *PubKey
	x_Z              *big.Int   // Z = S^x_Z
	x_R              []*big.Int // R_i = S^x_R_i
}

func NewOrg(name string, clParamSizes *CLParamSizes) (*Org, error) {
	group, err := groups.NewQRSpecialRSA(clParamSizes.NLength / 2)
	if err != nil {
		return nil, fmt.Errorf("error when creating QRSpecialRSA group: %s", err)
	}

	S, Z, R_L, x_Z, x_R, err := generateQuadraticResidues(group, clParamSizes.AttrsNum)
	pubKey := NewCLPubKey(group.N, S, Z, R_L)
	if err != nil {
		return nil, fmt.Errorf("error when creating QRSpecialRSA group: %s", err)
	}

	pedersenParams, err := commitments.GeneratePedersenParams(clParamSizes.RhoBitLen)
	if err != nil {
		return nil, fmt.Errorf("error when creating Pedersen receiver: %s", err)
	}

	primes := common.NewSpecialRSAPrimes(group.P, group.Q, group.P1, group.Q1)
	return NewOrgFromParams(name, clParamSizes, primes, pubKey, x_Z, x_R, pedersenParams)
}

func NewOrgFromParams(name string, clParamSizes *CLParamSizes, primes *common.SpecialRSAPrimes,
	pubKey *PubKey, x_Z *big.Int, x_R []*big.Int,
	pedersenParams *commitments.PedersenParams) (*Org, error) {
	group, err := groups.NewQRSpecialRSAFromParams(primes)
	if err != nil {
		return nil, fmt.Errorf("error when creating QRSpecialRSA group: %s", err)
	}

	return &Org{
		Name:             name,
		ParamSizes:       clParamSizes,
		Group:            group,
		PubKey:           pubKey,
		x_Z:              x_Z,
		x_R:              x_R,
		PedersenReceiver: commitments.NewPedersenReceiverFromParams(pedersenParams),
	}, nil
}

func generateQuadraticResidues(group *groups.QRSpecialRSA, num_of_attrs int) (*big.Int, *big.Int, []*big.Int,
	*big.Int, []*big.Int, error) {
	S, err := group.GetRandomGenerator()
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("error when searching for QRSpecialRSA generator: %s", err)
	}
	x_Z := common.GetRandomInt(group.Order)
	Z := group.Exp(S, x_Z)

	R_L := make([]*big.Int, num_of_attrs)
	x_R := make([]*big.Int, num_of_attrs)
	for i, _ := range R_L {
		x_R_i := common.GetRandomInt(group.Order)
		x_R[i] = x_R_i
		R_i := group.Exp(S, x_R_i)
		R_L[i] = R_i
	}
	return S, Z, R_L, x_Z, x_R, nil
}
