package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"
)

func genKeys(curve elliptic.Curve) (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {

	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("eroare la generarea cheii private: %v", err)
	}
	return privateKey, &privateKey.PublicKey, nil
}

func encrypt(m_x *big.Int, m_y *big.Int, curve elliptic.Curve, publicKey *ecdsa.PublicKey) (*big.Int, *big.Int, *big.Int, *big.Int) {

	b, err := rand.Int(rand.Reader, curve.Params().N)
	if err != nil {
		// return nil, nil, fmt.Errorf("eroare la alegerea valorii k: %v", err)
	}

	bP_x, bP_y := curve.ScalarBaseMult(b.Bytes())

	bap_x, bap_y := curve.ScalarMult(publicKey.X, publicKey.Y, b.Bytes())

	fmt.Println(" apartine m_x ,m y : ", checkPointOnCurve(m_x, m_y, curve))
	fmt.Println(" apartine bap_x ,bap _y : ", checkPointOnCurve(bap_x, bap_y, curve))
	c_x, c_y := curve.Add(m_x, m_y, bap_x, bap_y)

	return bP_x, bP_y, c_x, c_y

}
func checkPointOnCurve(x, y *big.Int, curve elliptic.Curve) bool {

	y2 := new(big.Int).Exp(y, big.NewInt(2), curve.Params().P)
	x3 := new(big.Int).Exp(x, big.NewInt(3), curve.Params().P)
	ax := new(big.Int).Mul(big.NewInt(-3), x)
	rightSide := new(big.Int).Add(x3, ax)
	rightSide.Add(rightSide, curve.Params().B)
	rightSide.Mod(rightSide, curve.Params().P)

	return y2.Cmp(rightSide) == 0
}
func toBits(arrayOfBytes []byte) string {

	var stringOfBits strings.Builder
	for _, byteElement := range arrayOfBytes {
		stringOfBits.WriteString(fmt.Sprintf("%08b", byteElement))

	}
	return stringOfBits.String()
}

func mapMessageToPoint(m []byte, curve elliptic.Curve) (*big.Int, *big.Int, *big.Int, error) {

	P := curve.Params().P

	bits := toBits(m)
	var newBits string
	var newx *big.Int
	var right *big.Int
	var seqR string
	cpy := bits
	fmt.Println("Message bits : ", bits)
	seqR = generateR(big.NewInt(int64(len(bits))), P)
	newBits = "0" + seqR + bits
	bitWords := toWord(newBits)
	newx = new(big.Int).SetBits(bitWords)
	right = computeY(newx, curve)
	i := 0
	for new(big.Int).ModSqrt(right, curve.Params().P) == nil {
		seqR = generateR(big.NewInt(int64(len(bits))), P)
		newBits = "0" + seqR + bits
		bitWords := toWord(newBits)
		newx = new(big.Int).SetBits(bitWords)
		right = computeY(newx, curve)
		i = i + 1
	}
	fmt.Println(" 0 | r | m : ", 0, seqR, cpy)

	var R1 *big.Int = big.NewInt(0)
	var R2 *big.Int = big.NewInt(0)

	if new(big.Int).ModSqrt(right, curve.Params().P) != nil {

		R1.ModSqrt(right, P)
		R2.Sub(curve.Params().P, R1)

	}
	x := newx
	y := R1

	if !checkPointOnCurve(x, y, curve) {
		fmt.Println("nu existaaaaaaaaaaaaaaaaaaaaa")
	}

	return x, y, nil, nil

}
func generateR(l *big.Int, p *big.Int) string {

	pBytes := p.Bytes()
	lengthP := big.NewInt(int64(len(toBits(pBytes))))

	max := new(big.Int).Sub(lengthP, l)
	r, _ := rand.Int(rand.Reader, max)

	var bitString strings.Builder

	limit := int(r.Int64())

	for i := 0; i < limit; i++ {
		bit, err := rand.Int(rand.Reader, big.NewInt(2))
		if err != nil {
			return ""
		}
		bitString.WriteString(bit.String())
	}

	return bitString.String()

}
func toWord(bitString string) []big.Word {

	var words []big.Word
	if len(bitString)%64 != 0 {
		bitString = strings.Repeat("0", 64-len(bitString)%64) + bitString
	}
	for i := 0; i < len(bitString); i += 64 {
		bitSegment := bitString[i : i+64]
		word, _ := new(big.Int).SetString(bitSegment, 2)

		words = append([]big.Word{big.Word(word.Uint64())}, words...)
	}
	return words

}
func computeY(x *big.Int, curve elliptic.Curve) *big.Int {
	x3 := new(big.Int).Exp(x, big.NewInt(3), curve.Params().P)
	ax := new(big.Int).Mul(big.NewInt(-3), x)
	y := new(big.Int).Add(x3, ax)
	y.Add(y, curve.Params().B)
	y.Mod(y, curve.Params().P)
	return y
}
func decrypt(curve elliptic.Curve, bP_x, bP_y *big.Int, C_x *big.Int, C_y *big.Int, privateKey *ecdsa.PrivateKey) (*big.Int, *big.Int) {

	abp_x, abp_y := curve.ScalarMult(bP_x, bP_y, privateKey.D.Bytes())
	opAbp_y := new(big.Int).Neg(abp_y)
	opAbp_y.Mod(opAbp_y, curve.Params().P)
	m_x, m_y := curve.Add(C_x, C_y, abp_x, opAbp_y)

	return m_x, m_y

}

func main() {

	curve := elliptic.P256()
	params := curve.Params()
	fmt.Println("Numele curbei:", params.Name)
	fmt.Println("Ordinul:", params.N)
	fmt.Println("Punctul generator (Gx, Gy):", params.Gx, params.Gy)
	fmt.Println("P:", params.P)
	fmt.Println("B:", params.B)

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
	fmt.Println("Initial message: ", message)
	x_m, y_m, _, _ := mapMessageToPoint([]byte(message), curve)

	fmt.Println("M_x: ", x_m)
	fmt.Println("M_y: ", y_m)

	bP_x, bP_y, c_x, c_y := encrypt(x_m, y_m, curve, publicKey)

	fmt.Println("bP_x: ", bP_x)
	fmt.Println("bp_y: ", bP_y)

	fmt.Println("c_x: ", c_x)
	fmt.Println("c_y: ", c_y)

	m_x, _ := decrypt(curve, bP_x, bP_y, c_x, c_y, privateKey)

	twoPowerL := new(big.Int).Lsh(big.NewInt(1), uint(((len(message)) * 8)))

	dm := new(big.Int).Mod(m_x, twoPowerL)
	// fmt.Println("Decrypted message bytes : ", dm.Bytes())

	fmt.Println("Decrypted message : ", string(dm.Bytes()))
}
