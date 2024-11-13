package main

import (
	"fmt"
	"log"

	"github.com/Mirzazhar/elgamal"
)

func main() {

	bitsize := 512
	probability := 20

	privateKey, err := elgamal.GenerateKey(bitsize, probability)
	if err != nil {
		fmt.Println("Eroare la generarea cheii:", err)
		return
	}

	fmt.Println("Cheia privată:", privateKey.X)
	fmt.Println("Cheia publică (P, G, Y):", privateKey.PublicKey.P, privateKey.PublicKey.G, privateKey.PublicKey.Y)

	publicKey := &privateKey.PublicKey

	message := []byte("Ceva secret")
	c1, c2, err := publicKey.Encrypt(message)

	if err != nil {
		fmt.Println("Eroare la criptare:", err)
		return
	}
	fmt.Printf("Mesajul criptat (c1): %x\n", c1)
	fmt.Printf("Mesajul criptat (c2): %x\n", c2)

	decryptedMessage, err := privateKey.Decrypt(c1, c2)
	if err != nil {
		log.Fatal("Eroare la decriptare:", err)
	}

	fmt.Printf("Mesajul decriptat: %s\n", decryptedMessage)
}
