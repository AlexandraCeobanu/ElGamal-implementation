package main

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
	mathrand "math/rand"
	"time"

	"github.com/Mirzazhar/elgamal"
)

// var one = big.NewInt(1)
// var p1 = big.NewInt(23)
// var g1 = big.NewInt(5)

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

func XOR(a, b []byte) []byte {
	result := make([]byte, len(a))
	for i := 0; i < len(a); i++ {
		result[i] = a[i] ^ b[i]
	}
	return result
}

func encrypt(m []byte, publicKey PublicKey) (*big.Int, []byte, error) {

	k, _ := rand.Int(rand.Reader, &publicKey.p)

	c1 := new(big.Int).Exp(&publicKey.g, k, &publicKey.p)
	h_la_k := new(big.Int).Exp(&publicKey.h, k, &publicKey.p)

	hash := sha256.Sum256(h_la_k.Bytes())
	fmt.Println("Message hash: ", hash)
	newHash := make([]byte, len(m))
	for i := range newHash {
		newHash[i] = hash[i%len(hash)]
	}

	c2 := XOR(m, newHash)

	return c1, c2, nil

}
func decrypt(c1 *big.Int, c2 []byte, privateKey *big.Int, p *big.Int) ([]byte, error) {

	c1_la_a := new(big.Int).Exp(c1, privateKey, p)

	hash := sha256.Sum256(c1_la_a.Bytes())

	newHash := make([]byte, len(c2))

	for i := range newHash {
		newHash[i] = hash[i%len(hash)]
	}

	message := XOR(c2, newHash)
	return message, nil

}
func main() {

	message := "secret message"
	messageBytes := []byte(message)

	fmt.Println("Initial Message: ", message)

	p, q, g, err := elgamal.Gen(256, 20)

	if err != nil {
		fmt.Println("Eroare la generarea p, q, g:", err)
		return
	}

	fmt.Println("p = ", p)
	fmt.Println("g = ", g)
	privateKey, publicKey := genKeys(p, q, g)

	c1, c2, err := encrypt(messageBytes, publicKey)
	if err == nil {
		fmt.Println("C1 = ", c1)
		fmt.Println("C2 = ", c2)
	} else {
		fmt.Println(err)
	}
	decryptedMessageBytes, err := decrypt(c1, c2, privateKey, p)

	decryptedMessage := string(decryptedMessageBytes)

	if err == nil {
		fmt.Println("Decrypted Message: ", decryptedMessage)
	} else {
		fmt.Println(err)
	}
}
