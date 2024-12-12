package secp256r1

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
	"testing"
)

func prepareSignatureTest() (*ecdsa.PrivateKey, []byte, [32]byte, *big.Int, *big.Int, error) {
	// Generate a new private key using P-256 curve
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, [32]byte{}, nil, nil, fmt.Errorf("error generating private key: %w", err)
	}

	// Message to be signed
	message := []byte("xyz")

	// Hash the message using SHA-256
	hash := sha256.Sum256(message)

	// Sign the hash using the private key
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	if err != nil {
		return nil, nil, [32]byte{}, nil, nil, fmt.Errorf("error signing message: %w", err)
	}

	return privateKey, message, hash, r, s, nil
}

func TestVerifySignatureMalleable_ValidSignature(t *testing.T) {
	privateKey, _, hash, r, s, err := prepareSignatureTest()
	if err != nil {
		t.Fatalf("Preparation failed: %v", err)
	}

	x := privateKey.PublicKey.X
	y := privateKey.PublicKey.Y
	nCurve := elliptic.P256().Params().N

	// make sure s is less than half of the curve order to simulate normalization
	sPrime := new(big.Int).Sub(nCurve, s)
	if sPrime.Cmp(s) == -1 {
		s = sPrime
	}

	_, err = Verify(hash[:], r, s, x, y)
	if err != nil {
		t.Fatalf("Error verifying original signature: %v", err)
	}
}

func TestVerifySignatureMalleable_InvalidSignature(t *testing.T) {
	privateKey, _, hash, r, s, err := prepareSignatureTest()
	if err != nil {
		t.Fatalf("Preparation failed: %v", err)
	}

	x := privateKey.PublicKey.X
	y := privateKey.PublicKey.Y

	// Get the curve order n
	nCurve := elliptic.P256().Params().N

	// make sure s is bigger than half of the curve order to simulate lack of normalization
	sPrime := new(big.Int).Sub(nCurve, s)
	if sPrime.Cmp(s) == 1 {
		s = sPrime
	}

	_, err = Verify(hash[:], r, s, x, y)
	if err == nil {
		t.Fatalf("Malleable signature should not be verified")
	}
}
