package helpers

import (
	"crypto/elliptic"
	"crypto/rsa"
	"math/big"

	"github.com/google/go-tpm/tpm2/structures/tpm2b"
	"github.com/google/go-tpm/tpm2/structures/tpms"
)

// RSAPub converts a TPM RSA public key into one recognized by the rsa package.
func RSAPub(parms *tpms.RSAParms, pub *tpm2b.PublicKeyRSA) (*rsa.PublicKey, error) {
	result := rsa.PublicKey{
		N: big.NewInt(0).SetBytes(pub.Buffer),
		E: int(parms.Exponent),
	}
	// TPM considers 65537 to be the default RSA public exponent, and 0 in
	// the parms
	// indicates so.
	if result.E == 0 {
		result.E = 65537
	}
	return &result, nil
}

// ECDHPub is a convenience wrapper around the necessary info to perform point
// multiplication with the elliptic package.
type ECDHPub struct {
	Curve elliptic.Curve
	X, Y  *big.Int
}

// ECCPub converts a TPM ECC public key into one recognized by the elliptic
// package's point-multiplication functions, for use in ECDH.
func ECCPub(parms *tpms.ECCParms, pub *tpms.ECCPoint) (*ECDHPub, error) {
	curve, err := parms.CurveID.Curve()
	if err != nil {
		return nil, err
	}
	return &ECDHPub{
		Curve: curve,
		X:     big.NewInt(0).SetBytes(pub.X.Buffer),
		Y:     big.NewInt(0).SetBytes(pub.Y.Buffer),
	}, nil
}
