package cl

import (
	"fmt"
	"github.com/xlab-si/emmy/crypto/common"
	"github.com/xlab-si/emmy/crypto/groups"
	"math/big"
)

type CLPubKey struct {
	N   *big.Int
	R_L []*big.Int
	S   *big.Int
	Z   *big.Int
}

func NewCLPubKey(N *big.Int, R_L []*big.Int, S, Z *big.Int) *CLPubKey {
	return &CLPubKey{
		N:   N,
		R_L: R_L,
		S:   S,
		Z:   Z,
	}
}

type CLIssuer struct {
}

func NewIssuer() *CLIssuer {

	return &CLIssuer{}
}

func (i *CLIssuer) GenerateKey(clParamSizes *CLParamSizes) (*CLPubKey, error) {
	group, err := groups.NewQRSpecialRSA(clParamSizes.L_n / 2)
	if err != nil {
		return nil, fmt.Errorf("error when generating QRSpecialRSA group: %s", err)
	}

	S, err := group.GetRandomGenerator()
	if err != nil {
		return nil, fmt.Errorf("error when searching for QRSpecialRSA generator: %s", err)
	}
	x_Z := common.GetRandomInt(group.Order)
	Z := group.Exp(S, x_Z)

	R_L := make([]*big.Int, clParamSizes.L_attrs)
	for i, _ := range R_L {
		x_R_i := common.GetRandomInt(group.Order)
		R_i := group.Exp(S, x_R_i)
		R_L[i] = R_i
	}

	return NewCLPubKey(group.N, R_L, S, Z), nil
}
