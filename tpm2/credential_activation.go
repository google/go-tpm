package tpm2

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"github.com/google/go-tpm/tpmutil"
)

// GenerateCredentialActivation creates a wrapped secret for use in credential activation.
// This function implements the minimum necessary to compute activations for RSA EKs
// compliant with TCG 2.0 EK Credential Profile specification, revision 14.
// Specifically, the constraints are:
// - aik must be computed using SHA256.
// - pub must be a 2048 bit RSA key, representing a compliant EK. That means using
//   SHA256 for digests, and a 128 bit AES symmetric cipher.
// - symBlockSize should represent the block size of the symmetric cipher. The only
//   valid value at this time is 16.
// - secret must not be longer than the longest digest size implemented by the TPM.
//   A 32 byte secret is a safe, recommended default.
//
// This function implements Credential Protection as defined in section 24 of the TPM
// specification revision 2 part 1, with the additional restrictions listed above.
// See: https://trustedcomputinggroup.org/resource/tpm-library-specification/
func GenerateCredentialActivation(aik *HashValue, pub crypto.PublicKey, symBlockSize int, secret []byte) ([]byte, error) {
	if symBlockSize != 16 {
		return nil, errors.New("only 16 byte symmetric block sizes are supported")
	}
	if aik.Alg != AlgSHA256 {
		return nil, errors.New("aik for credential activation must use SHA256 name algorithm")
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("only RSA public keys are supported for credential activation")
	}

	return generateCredentialActivation(aik, rsaPub, secret, rand.Reader)
}

// generateCredentialActivation only supports RSA 2048 public keys, with a SHA256 nameAlg,
// and using 128bit AES as the symmetric cipher.
// The provided AIK must be a digest, computed using SHA256.
func generateCredentialActivation(aik *HashValue, pub *rsa.PublicKey, secret []byte, rnd io.Reader) ([]byte, error) {
	// The seed length should match the keysize used by the EKs symmetric cipher.
	// For TCG/Windows-compliant RSA EKs, this will be 128 bits (16 bytes).
	// Spec: TCG 2.0 EK Credential Profile revision 14, section 2.1.5.1.
	seed := make([]byte, 16)
	if _, err := rnd.Read(seed); err != nil {
		return nil, fmt.Errorf("generating seed: %v", err)
	}

	// Encrypt the seed value using the provided public key.
	// See annex B, section 10.4 of the TPM specification revision 2 part 1.
	label := append([]byte(labelIdentity), 0)
	encSecret, err := rsa.EncryptOAEP(sha256.New(), rnd, pub, seed, label)
	if err != nil {
		return nil, fmt.Errorf("generating encrypted seed: %v", err)
	}

	// Generate the encrypted credential by convolving the seed with the digest of
	// the AIK, and using the result as the key to encrypt the secret.
	// See section 24.4 of TPM 2.0 specification, part 1.
	aikNameEncoded, err := aik.encode()
	if err != nil {
		return nil, fmt.Errorf("encoding aikName: %v", err)
	}
	symmetricKey, err := KDFa(aik.Alg, seed, labelStorage, aikNameEncoded, nil, len(seed)*8)
	if err != nil {
		return nil, fmt.Errorf("generating symmetric key: %v", err)
	}
	c, err := aes.NewCipher(symmetricKey)
	if err != nil {
		return nil, fmt.Errorf("symmetric cipher setup: %v", err)
	}
	cv, err := tpmutil.Pack(secret)
	if err != nil {
		return nil, fmt.Errorf("generating cv (TPM2B_Digest): %v", err)
	}

	// IV is all null bytes. encIdentity represents the encrypted credential.
	encIdentity := make([]byte, len(cv))
	cipher.NewCFBEncrypter(c, make([]byte, len(symmetricKey))).XORKeyStream(encIdentity, cv)

	// Generate the integrity HMAC, which is used to protect the integrity of the
	// encrypted structure.
	// See section 24.5 of the TPM specification revision 2 part 1.
	macKey, err := KDFa(aik.Alg, seed, labelIntegrity, nil, nil, digestSize(aik.Alg)*8)
	if err != nil {
		return nil, fmt.Errorf("generating HMAC key: %v", err)
	}

	// Algorithm sha256 is hardcoded when generating the HMAC, as we only support
	// Names using a digest of sha256 for now. In a future where we support more
	// algorithms, the HMAC algorithm should match aik.Digest.Alg.
	mac := hmac.New(sha256.New, macKey)
	mac.Write(encIdentity)
	mac.Write(aikNameEncoded)
	integrityHMAC := mac.Sum(nil)

	// Finally, we generate the activation structure, which is
	// a TPM2B_ID_OBJECT with a TPM2B_ENCRYPTED_SECRET.
	packedIntegrity, err := tpmutil.Pack(integrityHMAC)
	if err != nil {
		return nil, fmt.Errorf("packing integrity: %v", err)
	}
	// encIdentity is not packed as the size field is contained within
	// the encrypted blob.
	o, err := concat(packedIntegrity, encIdentity)
	if err != nil {
		return nil, fmt.Errorf("concat idObject: %v", err)
	}
	idObject, err := tpmutil.Pack(o)
	if err != nil {
		return nil, fmt.Errorf("packing idObject: %v", err)
	}
	packedEncSecret, err := tpmutil.Pack(encSecret)
	if err != nil {
		return nil, fmt.Errorf("packing encSecret: %v", err)
	}

	return concat(idObject, packedEncSecret)
}
