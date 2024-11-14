package main

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	mathrand "math/rand"
	"time"

	"github.com/Mirzazhar/elgamal"
)

var one = big.NewInt(1)
var two = big.NewInt(2)

type PublicKey struct {
	p, g, q, h big.Int
}

func genKeys(p, q, g *big.Int) (*big.Int, PublicKey) {

	randSource := mathrand.New(mathrand.NewSource(time.Now().UnixNano()))
	// a := new(big.Int).Rand(randSource, q)
	a := new(big.Int).Rand(randSource, p)
	h := new(big.Int).Exp(g, a, p)

	var publicKey PublicKey
	publicKey.p.Set(p)
	publicKey.g.Set(g)
	publicKey.q.Set(q)
	publicKey.h.Set(h)

	return a, publicKey

}

func sign(message *big.Int, PublicKey PublicKey, privateKey *big.Int) (*big.Int, *big.Int, error) {

	k := new(big.Int)
	gcd := new(big.Int)
	var err error
	for {
		k, err = rand.Int(rand.Reader, new(big.Int).Sub(&PublicKey.p, two))
		if err != nil {
			return nil, nil, err
		}
		if k.Cmp(one) == 0 {
			continue
		} else {
			gcd = gcd.GCD(nil, nil, k, new(big.Int).Sub(&PublicKey.p, one))
			if gcd.Cmp(one) == 0 {
				break
			}
		}
	}

	gamma := new(big.Int).Exp(&PublicKey.g, k, &PublicKey.p)

	x_gamma := new(big.Int).Mod(
		new(big.Int).Mul(gamma, privateKey),
		new(big.Int).Sub(&PublicKey.p, one),
	)

	sub := new(big.Int).Sub(message, x_gamma)

	k = k.ModInverse(k, new(big.Int).Sub(&PublicKey.p, one))

	delta := new(big.Int).Mod(
		new(big.Int).Mul(sub, k),
		new(big.Int).Sub(&PublicKey.p, one),
	)

	return gamma, delta, nil
}

func verify(gamma *big.Int, delta *big.Int, m *big.Int, PublicKey PublicKey) (string, error) {

	ga_la_gamma := new(big.Int).Exp(&PublicKey.h, gamma, &PublicKey.p)

	gamma_la_delta := new(big.Int).Exp(gamma, delta, &PublicKey.p)

	g_la_m := new(big.Int).Exp(&PublicKey.g, m, &PublicKey.p)

	right := new(big.Int).Mod(
		new(big.Int).Mul(ga_la_gamma, gamma_la_delta), &PublicKey.p,
	)

	if right.Cmp(g_la_m) == 0 {
		return "Success", nil
	} else {
		return "", errors.New("Fail")
	}
}

func main() {

	messageString := "secret message"
	message := new(big.Int).SetBytes([]byte(messageString))

	fmt.Println("Initial Message: ", messageString)

	p, q, g, err := elgamal.Gen(256, 20)

	if err != nil {
		fmt.Println("Eroare la generarea p, q, g:", err)
		return
	}

	fmt.Println("p = ", p)
	fmt.Println("g = ", g)
	privateKey, publicKey := genKeys(p, q, g)

	gamma, delta, err := sign(message, publicKey, privateKey)
	// gamma.Add(gamma, big.NewInt(1))

	if err == nil {
		fmt.Println("gamma = ", gamma)
		fmt.Println("delta = ", delta)
	} else {
		fmt.Println(err)
	}

	output, err := verify(gamma, delta, message, publicKey)
	if err == nil {
		fmt.Println(output)
	} else {
		fmt.Println(err)
	}
}
