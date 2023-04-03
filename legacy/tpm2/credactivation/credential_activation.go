// Copyright (c) 2018, Google LLC All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package credactivation implements generation of data blobs to be used
// when invoking the ActivateCredential command, on a TPM.
package credactivation

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

// Labels for use in key derivation or OAEP encryption.
const (
	labelIdentity  = "IDENTITY"
	labelStorage   = "STORAGE"
	labelIntegrity = "INTEGRITY"
)

// Generate returns a TPM2B_ID_OBJECT & TPM2B_ENCRYPTED_SECRET for use in
// credential activation.
// This has been tested on EKs compliant with TCG 2.0 EK Credential Profile
// specification, revision 14.
// The pub parameter must be a pointer to rsa.PublicKey.
// The secret parameter must not be longer than the longest digest size implemented
// by the TPM. A 32 byte secret is a safe, recommended default.
//
// This function implements Credential Protection as defined in section 24 of the TPM
// specification revision 2 part 1.
// See: https://trustedcomputinggroup.org/resource/tpm-library-specification/
func Generate(aik *tpm2.HashValue, pub crypto.PublicKey, symBlockSize int, secret []byte) ([]byte, []byte, error) {
	return generate(aik, pub, symBlockSize, secret, rand.Reader)
}

func generate(aik *tpm2.HashValue, pub crypto.PublicKey, symBlockSize int, secret []byte, rnd io.Reader) ([]byte, []byte, error) {
	var seed, encSecret []byte
	var err error
	switch ekKey := pub.(type) {
	case *ecdh.PublicKey:
		seed, encSecret, err = createECSeed(aik, ekKey, rnd)
		if err != nil {
			return nil, nil, fmt.Errorf("creating seed: %v", err)
		}
	case *ecdsa.PublicKey:
		ecdhKey, err := ekKey.ECDH()
		if err != nil {
			return nil, nil, fmt.Errorf("transmuting ecdsa key to ecdh key: %v", err)
		}
		return generate(aik, ecdhKey, symBlockSize, secret, rnd)
	case *rsa.PublicKey:
		seed, encSecret, err = createRSASeed(aik, ekKey, symBlockSize, rnd)
		if err != nil {
			return nil, nil, fmt.Errorf("creating seed: %v", err)
		}
	default:
		return nil, nil, errors.New("only RSA and EC public keys are supported for credential activation")
	}

	// Generate the encrypted credential by convolving the seed with the digest of
	// the AIK, and using the result as the key to encrypt the secret.
	// See section 24.4 of TPM 2.0 specification, part 1.
	aikNameEncoded, err := aik.Encode()
	if err != nil {
		return nil, nil, fmt.Errorf("encoding aikName: %v", err)
	}
	symmetricKey, err := tpm2.KDFa(aik.Alg, seed, labelStorage, aikNameEncoded, nil, symBlockSize*8)
	if err != nil {
		return nil, nil, fmt.Errorf("generating symmetric key: %v", err)
	}
	c, err := aes.NewCipher(symmetricKey)
	if err != nil {
		return nil, nil, fmt.Errorf("symmetric cipher setup: %v", err)
	}
	cv, err := tpmutil.Pack(tpmutil.U16Bytes(secret))
	if err != nil {
		return nil, nil, fmt.Errorf("generating cv (TPM2B_Digest): %v", err)
	}

	// IV is all null bytes. encIdentity represents the encrypted credential.
	encIdentity := make([]byte, len(cv))
	cipher.NewCFBEncrypter(c, make([]byte, len(symmetricKey))).XORKeyStream(encIdentity, cv)

	// Generate the integrity HMAC, which is used to protect the integrity of the
	// encrypted structure.
	// See section 24.5 of the TPM 2.0 specification.
	cryptohash, err := aik.Alg.Hash()
	if err != nil {
		return nil, nil, err
	}
	macKey, err := tpm2.KDFa(aik.Alg, seed, labelIntegrity, nil, nil, cryptohash.Size()*8)
	if err != nil {
		return nil, nil, fmt.Errorf("generating HMAC key: %v", err)
	}

	mac := hmac.New(cryptohash.New, macKey)
	mac.Write(encIdentity)
	mac.Write(aikNameEncoded)
	integrityHMAC := mac.Sum(nil)

	idObject := &tpm2.IDObject{
		IntegrityHMAC: integrityHMAC,
		EncIdentity:   encIdentity,
	}
	id, err := tpmutil.Pack(idObject)
	if err != nil {
		return nil, nil, fmt.Errorf("encoding IDObject: %v", err)
	}

	packedID, err := tpmutil.Pack(tpmutil.U16Bytes(id))
	if err != nil {
		return nil, nil, fmt.Errorf("packing id: %v", err)
	}
	packedEncSecret, err := tpmutil.Pack(tpmutil.U16Bytes(encSecret))
	if err != nil {
		return nil, nil, fmt.Errorf("packing encSecret: %v", err)
	}

	return packedID, packedEncSecret, nil
}

func createRSASeed(aik *tpm2.HashValue, ek *rsa.PublicKey, symBlockSize int, rnd io.Reader) ([]byte, []byte, error) {
	crypothash, err := aik.Alg.Hash()
	if err != nil {
		return nil, nil, err
	}

	// The seed length should match the keysize used by the EKs symmetric cipher.
	// For typical RSA EKs, this will be 128 bits (16 bytes).
	// Spec: TCG 2.0 EK Credential Profile revision 14, section 2.1.5.1.
	seed := make([]byte, symBlockSize)
	if _, err := io.ReadFull(rnd, seed); err != nil {
		return nil, nil, fmt.Errorf("generating seed: %v", err)
	}

	// Encrypt the seed value using the provided public key.
	// See annex B, section 10.4 of the TPM specification revision 2 part 1.
	label := append([]byte(labelIdentity), 0)
	encryptedSeed, err := rsa.EncryptOAEP(crypothash.New(), rnd, ek, seed, label)
	if err != nil {
		return nil, nil, fmt.Errorf("generating encrypted seed: %v", err)
	}

	encryptedSeed, err = tpmutil.Pack(encryptedSeed)
	return seed, encryptedSeed, err
}

func createECSeed(ak *tpm2.HashValue, ek *ecdh.PublicKey, rnd io.Reader) (seed, encryptedSeed []byte, err error) {
	ephemeralPriv, err := ek.Curve().GenerateKey(rnd)
	if err != nil {
		return nil, nil, err
	}
	ephemeralX, ephemeralY := deconstructECDHPublicKey(ephemeralPriv.PublicKey())

	z, err := ephemeralPriv.ECDH(ek)
	if err != nil {
		return nil, nil, err
	}

	ekX, _ := deconstructECDHPublicKey(ek)

	crypothash, err := ak.Alg.Hash()
	if err != nil {
		return nil, nil, err
	}

	seed, err = tpm2.KDFe(
		ak.Alg,
		z,
		labelIdentity,
		ephemeralX,
		ekX,
		crypothash.Size()*8)
	if err != nil {
		return nil, nil, err
	}
	encryptedSeed, err = tpmutil.Pack(tpmutil.U16Bytes(ephemeralX), tpmutil.U16Bytes(ephemeralY))
	return seed, encryptedSeed, err
}

func deconstructECDHPublicKey(key *ecdh.PublicKey) (x []byte, y []byte) {
	b := key.Bytes()[1:]
	return b[:len(b)/2], b[len(b)/2:]
}
