package tpm2

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"math/big"
)

// RSAPub converts a TPM RSA public key into one recognized by the rsa package.
func RSAPub(parms *TPMSRSAParms, pub *TPM2BPublicKeyRSA) (*rsa.PublicKey, error) {
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
func ECCPub(parms *TPMSECCParms, pub *TPMSECCPoint) (*ECDHPub, error) {
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

const (
	duplicateLabel = "DUPLICATE"
	integrityLabel = "INTEGRITY"
	storageLabel   = "STORAGE"
)

// EKSealOptions are options for influencing the EKSeal function.
type EKSealOptions struct {
	// IgnoreMaxSymData, if true, causes EKSeal to not return an error if the
	// length of the provided plain-text data exceeds MaxSymData.
	IgnoreMaxSymData bool
}

// EKSealOption is some configuration that modifies options for an EKSeal
// operation.
type EKSealOption interface {
	// ApplyToEKSeal applies this configuration to the given options.
	ApplyToEKSeal(*EKSealOptions)
}

// EKSealIgnoreMaxSymData instructs EKSeal to skip validating whether or not
// the length of the provided plain-text data exceeds MaxSymData.
var EKSealIgnoreMaxSymData = ignoreMaxSymData{}

type ignoreMaxSymData struct{}

// ApplyToEKSeal applies this configuration to the given options.
func (ignoreMaxSymData) ApplyToEKSeal(opts *EKSealOptions) {
	opts.IgnoreMaxSymData = true
}

// EKSeal encrypts the provided plain-text data so only the TPM with the
// specified endorsement key will be able to decrypt the data.
func EKSeal(
	ek TPMTPublic,
	plainText []byte,
	options ...EKSealOption) (TPM2BPublic, TPM2BPrivate, TPM2BEncryptedSecret, error) {

	// Apply the options.
	var opts EKSealOptions
	for i := range options {
		options[i].ApplyToEKSeal(&opts)
	}

	// If the length of the plain-text data exceeds MaxSymData and the
	// IgnoreMaxSymData option was not set, return an error.
	if lpt := len(plainText); lpt > MaxSymData && !opts.IgnoreMaxSymData {
		return TPM2BPublic{}, TPM2BPrivate{}, TPM2BEncryptedSecret{},
			fmt.Errorf("len(plainText)=%d > MaxSymData=%d", lpt, MaxSymData)
	}

	public, private, err := keyedHashFromSecret(plainText, ek.NameAlg)
	if err != nil {
		return TPM2BPublic{}, TPM2BPrivate{}, TPM2BEncryptedSecret{},
			fmt.Errorf("failed to get keyed hash: %w", err)
	}

	return wrap(ek, public, private)
}

// EKCertSeal encrypts the provided plain-text data so only the TPM with the
// endorsement key matching the specified certificate will be able to decrypt
// the data.
func EKCertSeal(
	ekCert x509.Certificate,
	plainText []byte,
	options ...EKSealOption) (TPM2BPublic, TPM2BPrivate, TPM2BEncryptedSecret, error) {

	ek, err := EKCertToTPMTPublic(ekCert)
	if err != nil {
		return TPM2BPublic{}, TPM2BPrivate{}, TPM2BEncryptedSecret{},
			fmt.Errorf("failed to parse ek cert: %w", err)
	}

	return EKSeal(ek, plainText, options...)
}

// keyedHashFromSecret is based on the keyedhash_from_secret functions from
// TPM2B_SENSITIVE -- https://github.com/tpm2-software/tpm2-pytss/blob/1411ebd916467f3ad4032e4fa02b321a4c1528a1/src/tpm2_pytss/types.py#L1423-L1462
// and
// TPMT_SENSITIVE  -- https://github.com/tpm2-software/tpm2-pytss/blob/1411ebd916467f3ad4032e4fa02b321a4c1528a1/src/tpm2_pytss/types.py#L2113-L2154
func keyedHashFromSecret(
	plainText []byte,
	nameAlg TPMIAlgHash) (TPMTPublic, TPMTSensitive, error) {

	hashID, err := nameAlg.Hash()
	if err != nil {
		return TPMTPublic{}, TPMTSensitive{}, fmt.Errorf(
			"failed to get hash algorithm: %w", err)
	}

	seed, err := newSeed(hashID.Size())
	if err != nil {
		return TPMTPublic{}, TPMTSensitive{}, fmt.Errorf(
			"failed to generate seed: %w", err)
	}

	symmetricData, err := calculateSymUnique(hashID, plainText, seed)
	if err != nil {
		return TPMTPublic{}, TPMTSensitive{}, fmt.Errorf(
			"failed to calculate symmetric data: %w", err)
	}

	private := TPMTSensitive{
		SensitiveType: TPMAlgKeyedHash,
		SeedValue: TPM2BDigest{
			Buffer: seed,
		},
		Sensitive: NewTPMUSensitiveComposite(
			TPMAlgKeyedHash,
			&TPM2BSensitiveData{
				Buffer: plainText,
			},
		),
	}

	public := TPMTPublic{
		Type:    TPMAlgKeyedHash,
		NameAlg: TPMAlgSHA256,
		AuthPolicy: TPM2BDigest{
			Buffer: bytes.Repeat([]byte{'\x00'}, 32),
		},
		ObjectAttributes: TPMAObject{
			NoDA: true,
		},
		Parameters: NewTPMUPublicParms(
			TPMAlgKeyedHash,
			&TPMSKeyedHashParms{
				Scheme: TPMTKeyedHashScheme{
					Scheme: TPMAlgNull,
				},
			},
		),
		Unique: NewTPMUPublicID(
			TPMAlgKeyedHash,
			&TPM2BDigest{
				Buffer: symmetricData,
			},
		),
	}

	return public, private, nil
}

// calculateSymUnique is based on the _calculate_sym_unique function from
// https://github.com/tpm2-software/tpm2-pytss/blob/1411ebd916467f3ad4032e4fa02b321a4c1528a1/src/tpm2_pytss/internal/crypto.py#L387-L394
func calculateSymUnique(
	hashID crypto.Hash, plainText, seed []byte) ([]byte, error) {

	hash := hashID.New()

	// Write the seed to the hash.
	if n, err := hash.Write(seed); err != nil {
		return nil, fmt.Errorf("failed to write seed to hash: %w", err)
	} else if a, e := n, len(seed); a != e {
		return nil, fmt.Errorf(
			"failed to write seed to hash; act=%d, exp=%d", a, e)
	}

	// Write the plain-text to the hash.
	if n, err := hash.Write(plainText); err != nil {
		return nil, fmt.Errorf("failed to write plain-text to hash: %w", err)
	} else if a, e := n, len(plainText); a != e {
		return nil, fmt.Errorf(
			"failed to write plain-text to hash; act=%d, exp=%d", a, e)
	}

	return hash.Sum(nil), nil
}

// wrap is based on the wrap function from
// https://github.com/tpm2-software/tpm2-pytss/blob/1411ebd916467f3ad4032e4fa02b321a4c1528a1/src/tpm2_pytss/utils.py#L134-L209
func wrap(
	parent TPMTPublic,
	public TPMTPublic,
	sensitive TPMTSensitive) (

	TPM2BPublic,
	TPM2BPrivate,
	TPM2BEncryptedSecret,
	error) {

	var (
		dupePub  TPM2BPublic
		dupePriv TPM2BPrivate
		dupeSeed TPM2BEncryptedSecret
	)

	parentHashID, err := parent.NameAlg.Hash()
	if err != nil {
		return dupePub, dupePriv, dupeSeed,
			fmt.Errorf("failed to get parent hash id: %w", err)
	}

	pubName, err := ObjectName(&public)
	if err != nil {
		return dupePub, dupePriv, dupeSeed,
			fmt.Errorf("failed to get public name: %w", err)
	}

	bits, err := symmetricDefinitionToCrypto(parent)
	if err != nil {
		return dupePub, dupePriv, dupeSeed,
			fmt.Errorf("failed to symdef to crypto: %w", err)
	}

	encSalt, salt, err := getEncryptedSalt(parent, duplicateLabel)
	if err != nil {
		return dupePub, dupePriv, dupeSeed,
			fmt.Errorf("failed to get encrypted salt: %w", err)
	}

	outerKey := KDFa(
		parentHashID,
		salt,
		storageLabel,
		pubName.Buffer, nil,
		bits)
	dupeSensitive, err := encryptAESCFB(outerKey, Marshal(New2B(sensitive)))
	if err != nil {
		return dupePub, dupePriv, dupeSeed,
			fmt.Errorf("failed to enc sensitive data: %w", err)
	}

	hmacKey := KDFa(
		parentHashID,
		salt,
		integrityLabel,
		nil, nil,
		parentHashID.Size()*8)
	hmacHash := hmac.New(parentHashID.New, hmacKey)
	hmacHash.Write(dupeSensitive)
	hmacHash.Write(pubName.Buffer)
	hmacData := Marshal(TPM2BDigest{Buffer: hmacHash.Sum(nil)})

	dupePub = New2B(public)
	dupePriv.Buffer = append(hmacData, dupeSensitive...)
	dupeSeed.Buffer = encSalt.Buffer

	return dupePub, dupePriv, dupeSeed, nil
}

// symmetricDefinitionToCrypto is based on the _symdef_to_crypt function from
// https://github.com/tpm2-software/tpm2-pytss/blob/1411ebd916467f3ad4032e4fa02b321a4c1528a1/src/tpm2_pytss/internal/crypto.py#L376-L384
func symmetricDefinitionToCrypto(
	public TPMTPublic) (int, error) {

	var symDef TPMTSymDefObject

	switch public.Type {
	case TPMAlgRSA:
		asymDetail, err := public.Parameters.RSADetail()
		if err != nil {
			return 0, fmt.Errorf("failed to get asymmetric rsa detail: %w", err)
		}
		symDef = asymDetail.Symmetric
	case TPMAlgECC:
		asymDetail, err := public.Parameters.ECCDetail()
		if err != nil {
			return 0, fmt.Errorf("failed to get asymmetric ecc detail: %w", err)
		}
		symDef = asymDetail.Symmetric
	default:
		return 0, fmt.Errorf("unsupported type: %v", public.Type)
	}

	if symAlg := symDef.Algorithm; symAlg != TPMAlgAES {
		return 0, fmt.Errorf(
			"invalid sym alg id: exp=%v, act=%v", TPMAlgAES, symAlg)
	}

	// For whatever reason, symDef.Mode is set to AlgID=6, AES, even though
	// the EK's public area should set it to CFB. Thus it cannot be verified
	// here or else it will return an error.

	keyBits, err := symDef.KeyBits.AES()
	if err != nil {
		return 0, fmt.Errorf("failed to get sym key bits: %w", err)
	}
	if keyBits == nil {
		return 0, fmt.Errorf("sym key bits are nil")
	}

	return int(*keyBits), nil
}

// newSeed returns a byte slice of the specified size filled with random data
// from the crypto.Rand reader.
func newSeed(size int) ([]byte, error) {
	seed := make([]byte, size)
	if n, err := rand.Read(seed); err != nil {
		return nil, err
	} else if n != len(seed) {
		return nil, fmt.Errorf(
			"invalid seed length; exp=%d, act=%d", size, n)
	}
	return seed, nil
}

func encryptAESCFB(key, plainText []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to get aes cipher: %w", err)
	}
	iv := bytes.Repeat([]byte{'\x00'}, len(key))
	cipherText := make([]byte, len(plainText))
	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(cipherText, plainText)
	return cipherText, nil
}

// Part 1, B.10.2
func getEncryptedSaltRSA(nameAlg TPMIAlgHash, parms *TPMSRSAParms, pub *TPM2BPublicKeyRSA, label string) (*TPM2BEncryptedSecret, []byte, error) {
	rsaPub, err := RSAPub(parms, pub)
	if err != nil {
		return nil, nil, fmt.Errorf("could not encrypt salt to RSA key: %w", err)
	}
	// Odd special case: the size of the salt depends on the RSA scheme's
	// hash alg.
	var hAlg TPMIAlgHash
	switch parms.Scheme.Scheme {
	case TPMAlgRSASSA:
		rsassa, err := parms.Scheme.Details.RSASSA()
		if err != nil {
			return nil, nil, err
		}
		hAlg = rsassa.HashAlg
	case TPMAlgRSAES:
		hAlg = nameAlg
	case TPMAlgRSAPSS:
		rsapss, err := parms.Scheme.Details.RSAPSS()
		if err != nil {
			return nil, nil, err
		}
		hAlg = rsapss.HashAlg
	case TPMAlgOAEP:
		oaep, err := parms.Scheme.Details.OAEP()
		if err != nil {
			return nil, nil, err
		}
		hAlg = oaep.HashAlg
	case TPMAlgNull:
		hAlg = nameAlg
	default:
		return nil, nil, fmt.Errorf("unsupported RSA salt key scheme: %v", parms.Scheme.Scheme)
	}
	ha, err := hAlg.Hash()
	if err != nil {
		return nil, nil, err
	}
	salt, err := newSeed(ha.Size())
	if err != nil {
		return nil, nil, fmt.Errorf("generating random salt: %w", err)
	}
	// Part 1, section 4.6 specifies the trailing NULL byte for the label.
	encSalt, err := rsa.EncryptOAEP(ha.New(), rand.Reader, rsaPub, salt, []byte(label+"\x00"))
	if err != nil {
		return nil, nil, fmt.Errorf("encrypting salt: %w", err)
	}
	return &TPM2BEncryptedSecret{
		Buffer: encSalt,
	}, salt, nil
}

// Part 1, 19.6.13
func getEncryptedSaltECC(nameAlg TPMIAlgHash, parms *TPMSECCParms, pub *TPMSECCPoint, label string) (*TPM2BEncryptedSecret, []byte, error) {
	curve, err := parms.CurveID.Curve()
	if err != nil {
		return nil, nil, fmt.Errorf("could not encrypt salt to ECC key: %w", err)
	}
	eccPub, err := ECCPub(parms, pub)
	if err != nil {
		return nil, nil, fmt.Errorf("could not encrypt salt to ECC key: %w", err)
	}
	ephPriv, ephPubX, ephPubY, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("could not encrypt salt to ECC key: %w", err)
	}
	zx, _ := curve.Params().ScalarMult(eccPub.X, eccPub.Y, ephPriv)
	// ScalarMult returns a big.Int, whose Bytes() function may return the
	// compacted form. In our case, we want to left-pad zx to the size of
	// the curve.
	z := make([]byte, (curve.Params().BitSize+7)/8)
	zx.FillBytes(z)
	ha, err := nameAlg.Hash()
	if err != nil {
		return nil, nil, err
	}
	salt := KDFe(ha, z, label, ephPubX.Bytes(), pub.X.Buffer, ha.Size()*8)

	var encSalt bytes.Buffer
	binary.Write(&encSalt, binary.BigEndian, uint16(len(ephPubX.Bytes())))
	encSalt.Write(ephPubX.Bytes())
	binary.Write(&encSalt, binary.BigEndian, uint16(len(ephPubY.Bytes())))
	encSalt.Write(ephPubY.Bytes())
	return &TPM2BEncryptedSecret{
		Buffer: encSalt.Bytes(),
	}, salt, nil
}

// getEncryptedSalt creates a salt value for salted sessions.
// Returns the encrypted salt and plaintext salt, or an error value.
func getEncryptedSalt(pub TPMTPublic, label string) (*TPM2BEncryptedSecret, []byte, error) {
	switch pub.Type {
	case TPMAlgRSA:
		rsaParms, err := pub.Parameters.RSADetail()
		if err != nil {
			return nil, nil, err
		}
		rsaPub, err := pub.Unique.RSA()
		if err != nil {
			return nil, nil, err
		}
		return getEncryptedSaltRSA(pub.NameAlg, rsaParms, rsaPub, label)
	case TPMAlgECC:
		eccParms, err := pub.Parameters.ECCDetail()
		if err != nil {
			return nil, nil, err
		}
		eccPub, err := pub.Unique.ECC()
		if err != nil {
			return nil, nil, err
		}
		return getEncryptedSaltECC(pub.NameAlg, eccParms, eccPub, label)
	default:
		return nil, nil, fmt.Errorf("salt encryption alg '%v' not supported", pub.Type)
	}
}
