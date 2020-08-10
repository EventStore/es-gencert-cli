package certificates

import (
	"crypto/rand"
	"crypto/sha256"
	"math/big"
)

const defaultKeySize = 2048

func generateSerialNumber(bits uint) (*big.Int, error) {
	maxValue := new(big.Int).Lsh(big.NewInt(1), bits)
	randValue, err := rand.Int(rand.Reader, maxValue)
	if err != nil {
		return nil, err
	}
	return randValue, nil
}

func generateKeyIDFromRSAPublicKey(N *big.Int, e int) []byte {
	//according to RFC 3280, the Subject key ID must be derived from the public key
	x := new(big.Int).Lsh(N, 32)
	x.Add(x, big.NewInt(int64(e)))
	h := sha256.New()
	h.Write(x.Bytes())
	return h.Sum(nil)
}
