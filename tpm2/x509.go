package tpm2

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
)

// EKCertToTPMTPublic returns the TPMT_PUBLIC data structure for the provided
// EK certificate.
func EKCertToTPMTPublic(cert x509.Certificate) (TPMTPublic, error) {
	switch cert.PublicKeyAlgorithm {
	case x509.RSA:
		ek, err := Copy(RSAEKTemplate)
		if err != nil {
			return TPMTPublic{}, fmt.Errorf("failed to copy rsa ek tpl: %w", err)
		}
		pk := cert.PublicKey.(*rsa.PublicKey)
		if pk.N == nil {
			return TPMTPublic{}, fmt.Errorf("rsa pub key modulus is nil")
		}
		ek.Unique = NewTPMUPublicID(
			TPMAlgRSA,
			&TPM2BPublicKeyRSA{
				Buffer: pk.N.Bytes(),
			},
		)
		return ek, nil
	case x509.ECDSA:
		ek, err := Copy(ECCEKTemplate)
		if err != nil {
			return TPMTPublic{}, fmt.Errorf("failed to copy ecc ek tpl: %w", err)
		}
		pk := cert.PublicKey.(*ecdsa.PublicKey)
		if pk.X == nil {
			return TPMTPublic{}, fmt.Errorf("ecc point.X is nil")
		}
		if pk.Y == nil {
			return TPMTPublic{}, fmt.Errorf("ecc point.Y is nil")
		}
		ek.Unique = NewTPMUPublicID(
			TPMAlgECC,
			&TPMSECCPoint{
				X: TPM2BECCParameter{
					Buffer: pk.X.Bytes(),
				},
				Y: TPM2BECCParameter{
					Buffer: pk.Y.Bytes(),
				},
			},
		)
		return ek, nil
	default:
		return TPMTPublic{}, fmt.Errorf("unsupported pub key alg: %v", cert.PublicKeyAlgorithm)
	}
}
