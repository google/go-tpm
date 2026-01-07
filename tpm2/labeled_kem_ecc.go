package tpm2

import (
	"crypto/ecdh"
	"errors"
	"io"
)

var (
	// The curve is not supported.
	ErrUnsupportedCurve = errors.New("unsupported curve")
	// There was an internal error parsing the ephemeral public key during encapsulation.
	ErrBadEphemeralKey = errors.New("bad ephemeral ECC key")
)

// An eccKey is an One-Pass-Diffie-Hellman-based Labeled Encapsulation key.
type eccKey struct {
	// The actual public key.
	eccPub *ecdh.PublicKey
	// The name algorithm of the key.
	nameAlg TPMIAlgHash
	// The symmetric parameters of the key.
	symParms *TPMTSymDefObject
}

// importECCEncapsulationKey imports an ECC key for use in labeled encapsulation.
func importECCEncapsulationKey(pub *TPMTPublic) (*eccKey, error) {
	eccParms, err := pub.Parameters.ECCDetail()
	if err != nil {
		return nil, err
	}
	eccPub, err := pub.Unique.ECC()
	if err != nil {
		return nil, err
	}
	ecdhPub, err := ECDHPub(eccParms, eccPub)
	if err != nil {
		return nil, err
	}

	return &eccKey{
		eccPub:   ecdhPub,
		nameAlg:  pub.NameAlg,
		symParms: &eccParms.Symmetric,
	}, nil
}

// Encapsulate implements LabeledEncapsulationKey.
func (pub *eccKey) Encapsulate(random io.Reader, label string) (secret []byte, ciphertext []byte, err error) {
	ephemeralPriv, err := pub.eccPub.Curve().GenerateKey(random)
	if err != nil {
		return nil, nil, err
	}
	return pub.encapsulateDerandomized(ephemeralPriv, label)
}

// encapsulateDerandomized is a derandomized internal version of Encapsulate for testing.
func (pub *eccKey) encapsulateDerandomized(ephPrivate *ecdh.PrivateKey, label string) (secret []byte, ciphertext []byte, err error) {
	nameHash, err := pub.nameAlg.Hash()
	if err != nil {
		return nil, nil, err
	}
	pubX, _, err := ECCBytes(pub.eccPub)
	if err != nil {
		return nil, nil, err
	}
	ephX, ephY, err := ECCBytes(ephPrivate.PublicKey())
	if err != nil {
		return nil, nil, err
	}
	z, err := ephPrivate.ECDH(pub.eccPub)
	if err != nil {
		return nil, nil, err
	}
	secret = KDFe(nameHash, z, label, ephX, pubX, nameHash.Size()*8)
	ciphertext = Marshal(TPMSECCPoint{
		X: TPM2BECCParameter{
			Buffer: ephX,
		},
		Y: TPM2BECCParameter{
			Buffer: ephY,
		},
	})
	return secret, ciphertext, nil
}

// NameAlg implements LabeledEncapsulationKey.
func (pub *eccKey) NameAlg() TPMAlgID {
	return pub.nameAlg
}

// SymmetricParameters implements LabeledEncapsulationkey.
func (pub *eccKey) SymmetricParameters() *TPMTSymDefObject {
	return pub.symParms
}
