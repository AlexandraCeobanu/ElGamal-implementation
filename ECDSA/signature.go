package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
)

func genKeys(curve elliptic.Curve) (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {

	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("eroare la generarea cheii private: %v", err)
	}
	return privateKey, &privateKey.PublicKey, nil
}
func sign(message []byte, curve elliptic.Curve, privateKey *big.Int) (*big.Int, *big.Int, *big.Int) {

	k, _ := rand.Int(rand.Reader, curve.Params().N)
	R_x, _ := curve.ScalarBaseMult(k.Bytes())

	hash := sha256.Sum256(message)
	hashInt := new(big.Int).SetBytes(hash[:])

	sigma := new(big.Int).Mod(R_x, curve.Params().N)

	a_sigma := new(big.Int).Mul(privateKey, sigma)
	a_sigma.Mod(a_sigma, curve.Params().N)

	add := new(big.Int).Add(hashInt, a_sigma)
	add.Mod(add, curve.Params().N)

	inv_k := new(big.Int).ModInverse(k, curve.Params().N)

	delta := new(big.Int).Mul(inv_k, add)
	delta.Mod(delta, curve.Params().N)

	return hashInt, sigma, delta
}

func Verify(message []byte, sigma, delta *big.Int, curve elliptic.Curve, publicKey *ecdsa.PublicKey) string {

	hash := sha256.Sum256(message)
	hashInt := new(big.Int).SetBytes(hash[:])

	inv_delta := new(big.Int).ModInverse(delta, curve.Params().N)
	hash_invDelta := new(big.Int).Mul(inv_delta, hashInt)
	hash_invDelta.Mod(hash_invDelta, curve.Params().N)

	sigma_delta := new(big.Int).Mul(inv_delta, sigma)
	sigma_delta.Mod(sigma_delta, curve.Params().N)

	Rprim1_x, Rprim1_y := curve.ScalarBaseMult(hash_invDelta.Bytes())

	Rprim2_x, Rprim2_y := curve.ScalarMult(publicKey.X, publicKey.Y, sigma_delta.Bytes())

	Rprim_x, _ := curve.Add(Rprim1_x, Rprim1_y, Rprim2_x, Rprim2_y)

	Rprim_x.Mod(Rprim_x, curve.Params().N)
	fmt.Println("Rprimx : ", Rprim_x)

	if sigma.Cmp(Rprim_x) == 0 {
		return "Semnatura verificata"
	} else {
		return "Semnatura invalida"
	}

}
func main() {

	curve := elliptic.P256()

	privateKey, publicKey, err := genKeys(curve)
	if err != nil {
		fmt.Println("Eroare la generarea cheilor:", err)
		return
	}

	x, y := publicKey.X, publicKey.Y
	privateValue := new(big.Int).SetBytes(privateKey.D.Bytes())

	fmt.Println("Cheia privată:", privateValue)
	fmt.Println("Cheia publică X:", x)
	fmt.Println("Cheia publică Y:", y)

	message := "secret"
	fmt.Println("Message:  ", message)

	hash, sigma, delta := sign([]byte(message), curve, privateKey.D)
	sigma.Add(sigma, big.NewInt(1))
	fmt.Println("Hash : ", hash)
	fmt.Println("Sigma : ", sigma)
	fmt.Println("Delta : ", delta)

	fmt.Println(Verify([]byte(message), sigma, delta, curve, publicKey))

}
