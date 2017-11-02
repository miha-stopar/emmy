package test

import (
	"github.com/stretchr/testify/assert"
	"github.com/xlab-si/emmy/crypto/dlog"
	"math/big"
	"testing"
	"log"
)

func TestGeneratorOfCompositeQR(t *testing.T) {
	rsa, err := dlog.NewSpecialRSA(512)
	if err != nil {
		log.Println(err)
	}

	g, _ := rsa.GetGeneratorOfQR()
	n := rsa.N
	p1 := rsa.SmallP
	q1 := rsa.SmallQ

	// order of g should be 2*p1*q1
	order := new(big.Int).Mul(p1, q1)
	order.Mul(order, big.NewInt(2))
	tmp := new(big.Int).Exp(g, order, n)

	assert.Equal(t, tmp, big.NewInt(1), "g is not a generator")
	// other possible orders in this group are: 2, p1, q1, 2 * p1, and 2 * q1.
	tmp = new(big.Int).Exp(g, big.NewInt(2), n)
	assert.NotEqual(t, tmp, big.NewInt(1), "g is not a generator")

	tmp = new(big.Int).Exp(g, p1, n)
	assert.NotEqual(t, tmp, big.NewInt(1), "g is not a generator")

	tmp = new(big.Int).Exp(g, q1, n)
	assert.NotEqual(t, tmp, big.NewInt(1), "g is not a generator")

	tmp = new(big.Int).Exp(g, q1.Mul(p1, big.NewInt(2)), n)
	assert.NotEqual(t, tmp, big.NewInt(1), "g is not a generator")

	tmp = new(big.Int).Exp(g, q1.Mul(q1, big.NewInt(2)), n)
	assert.NotEqual(t, tmp, big.NewInt(1), "g is not a generator")
}
