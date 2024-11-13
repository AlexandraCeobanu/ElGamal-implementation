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

type PublicKey struct {
	p, g, q, h big.Int
}

func genKeys(p, q, g *big.Int) (*big.Int, PublicKey) {

	randSource := mathrand.New(mathrand.NewSource(time.Now().UnixNano()))

	a := new(big.Int).Rand(randSource, p)
	h := new(big.Int).Exp(g, a, p)

	var publicKey PublicKey
	publicKey.p.Set(p)
	publicKey.g.Set(g)
	publicKey.q.Set(q)
	publicKey.h.Set(h)

	return a, publicKey

}

func encrypt(m *big.Int, publicKey PublicKey) (*big.Int, *big.Int, error) {

	if m.Cmp(&publicKey.p) == 1 {
		return nil, nil, errors.New("message to long")
	}

	k, _ := rand.Int(rand.Reader, &publicKey.p)

	c1 := new(big.Int).Exp(&publicKey.g, k, &publicKey.p)
	h_la_k := new(big.Int).Exp(&publicKey.h, k, &publicKey.p)

	c2 := new(big.Int).Mod(new(big.Int).Mul(m, h_la_k), &publicKey.p)

	return c1, c2, nil

}
func decrypt(c1 *big.Int, c2 *big.Int, privateKey *big.Int, p *big.Int) (*big.Int, error) {

	c1_la_a := new(big.Int).Exp(c1, privateKey, p)

	if c1_la_a.ModInverse(c1_la_a, p) == nil {
		return nil, errors.New("invalid private key")
	}

	message := new(big.Int).Mod(new(big.Int).Mul(c1_la_a, c2), p)
	return message, nil

}
func main() {

	// messageString := "ajashfjashgajjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjj"
	messageString := "secret message"
	message := new(big.Int).SetBytes([]byte(messageString))
	fmt.Println(message)
	// message := big.NewInt(12333333333333)

	fmt.Println("Initial Message: ", messageString)

	p, q, g, err := elgamal.Gen(256, 20)

	if err != nil {
		fmt.Println("Eroare la generarea p, q, g:", err)
		return
	}

	fmt.Println("p = ", p)
	fmt.Println("g = ", g)
	privateKey, publicKey := genKeys(p, q, g)

	fmt.Println("Destinatar Cheie Publica:  ", &publicKey.h)
	fmt.Println("Destinatar Cheie Privata:  ", privateKey)

	c1, c2, err := encrypt(message, publicKey)
	if err == nil {
		fmt.Println("C1 = ", c1)
		fmt.Println("C2 = ", c2)
	} else {
		fmt.Println(err)
	}
	decryptedMessage, err := decrypt(c1, c2, privateKey, p)
	if err == nil {
		fmt.Println("Decrypted Message: ", string(decryptedMessage.Bytes()))
	} else {
		fmt.Println(err)
	}
}
