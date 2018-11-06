package credactivation

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

// Generate returns an idObject & wrapped secret for use in credential activation.
// This has been tested on EKs compliant with TCG 2.0 EK Credential Profile
// specification, revision 14.
// The pub parameter must be a pointer to rsa.PublicKey.
// The secret parameter must not be longer than the longest digest size implemented
// by the TPM. A 32 byte secret is a safe, recommended default.
//
// This function implements Credential Protection as defined in section 24 of the TPM
// specification revision 2 part 1, with the additional caveat of not supporting ECC EKs.
// See: https://trustedcomputinggroup.org/resource/tpm-library-specification/
func Generate(aik *tpm2.HashValue, pub crypto.PublicKey, symBlockSize int, secret []byte) ([]byte, []byte, error) {
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, nil, errors.New("only RSA public keys are supported for credential activation")
	}

	return generate(aik, rsaPub, symBlockSize, secret, rand.Reader)
}

func generate(aik *tpm2.HashValue, pub *rsa.PublicKey, symBlockSize int, secret []byte, rnd io.Reader) ([]byte, []byte, error) {
	hashNew, err := aik.Alg.Constructor()
	if err != nil {
		return nil, nil, err
	}

	// The seed length should match the keysize used by the EKs symmetric cipher.
	// For typical RSA EKs, this will be 128 bits (16 bytes).
	// Spec: TCG 2.0 EK Credential Profile revision 14, section 2.1.5.1.
	seed := make([]byte, symBlockSize)
	if _, err := rnd.Read(seed); err != nil {
		return nil, nil, fmt.Errorf("generating seed: %v", err)
	}

	// Encrypt the seed value using the provided public key.
	// See annex B, section 10.4 of the TPM specification revision 2 part 1.
	label := append([]byte(tpm2.LabelIdentity), 0)
	encSecret, err := rsa.EncryptOAEP(hashNew(), rnd, pub, seed, label)
	if err != nil {
		return nil, nil, fmt.Errorf("generating encrypted seed: %v", err)
	}

	// Generate the encrypted credential by convolving the seed with the digest of
	// the AIK, and using the result as the key to encrypt the secret.
	// See section 24.4 of TPM 2.0 specification, part 1.
	aikNameEncoded, err := aik.Encode()
	if err != nil {
		return nil, nil, fmt.Errorf("encoding aikName: %v", err)
	}
	symmetricKey, err := tpm2.KDFa(aik.Alg, seed, tpm2.LabelStorage, aikNameEncoded, nil, len(seed)*8)
	if err != nil {
		return nil, nil, fmt.Errorf("generating symmetric key: %v", err)
	}
	c, err := aes.NewCipher(symmetricKey)
	if err != nil {
		return nil, nil, fmt.Errorf("symmetric cipher setup: %v", err)
	}
	cv, err := tpmutil.Pack(secret)
	if err != nil {
		return nil, nil, fmt.Errorf("generating cv (TPM2B_Digest): %v", err)
	}

	// IV is all null bytes. encIdentity represents the encrypted credential.
	encIdentity := make([]byte, len(cv))
	cipher.NewCFBEncrypter(c, make([]byte, len(symmetricKey))).XORKeyStream(encIdentity, cv)

	// Generate the integrity HMAC, which is used to protect the integrity of the
	// encrypted structure.
	// See section 24.5 of the TPM specification revision 2 part 1.
	macKey, err := tpm2.KDFa(aik.Alg, seed, tpm2.LabelIntegrity, nil, nil, aik.Alg.DigestSize()*8)
	if err != nil {
		return nil, nil, fmt.Errorf("generating HMAC key: %v", err)
	}

	mac := hmac.New(hashNew, macKey)
	mac.Write(encIdentity)
	mac.Write(aikNameEncoded)
	integrityHMAC := mac.Sum(nil)

	idObject := &tpm2.IDObject{
		IntegrityHMAC: integrityHMAC,
		EncIdentity:   encIdentity,
	}
	id, err := idObject.Encode()
	if err != nil {
		return nil, nil, fmt.Errorf("encoding IDObject: %v", err)
	}
	packedEncSecret, err := tpmutil.Pack(encSecret)
	if err != nil {
		return nil, nil, fmt.Errorf("packing encSecret: %v", err)
	}

	return id, packedEncSecret, nil
}
