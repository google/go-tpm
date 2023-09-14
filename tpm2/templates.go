package tpm2

import (
	"fmt"
)

var (
	// RSASRKTemplate contains the TCG reference RSA-2048 SRK template.
	// https://trustedcomputinggroup.org/wp-content/uploads/TCG-TPM-v2.0-Provisioning-Guidance-Published-v1r1.pdf
	RSASRKTemplate = TPMTPublic{
		Type:    TPMAlgRSA,
		NameAlg: TPMAlgSHA256,
		ObjectAttributes: TPMAObject{
			FixedTPM:             true,
			STClear:              false,
			FixedParent:          true,
			SensitiveDataOrigin:  true,
			UserWithAuth:         true,
			AdminWithPolicy:      false,
			NoDA:                 true,
			EncryptedDuplication: false,
			Restricted:           true,
			Decrypt:              true,
			SignEncrypt:          false,
		},
		Parameters: NewTPMUPublicParms(
			TPMAlgRSA,
			&TPMSRSAParms{
				Symmetric: TPMTSymDefObject{
					Algorithm: TPMAlgAES,
					KeyBits: NewTPMUSymKeyBits(
						TPMAlgAES,
						TPMKeyBits(128),
					),
					Mode: NewTPMUSymMode(
						TPMAlgAES,
						TPMAlgCFB,
					),
				},
				KeyBits: 2048,
			},
		),
		Unique: NewTPMUPublicID(
			TPMAlgRSA,
			&TPM2BPublicKeyRSA{
				Buffer: make([]byte, 256),
			},
		),
	}
	// RSAEKTemplate contains the TCG reference RSA-2048 EK template.
	RSAEKTemplate = TPMTPublic{
		Type:    TPMAlgRSA,
		NameAlg: TPMAlgSHA256,
		ObjectAttributes: TPMAObject{
			FixedTPM:             true,
			STClear:              false,
			FixedParent:          true,
			SensitiveDataOrigin:  true,
			UserWithAuth:         false,
			AdminWithPolicy:      true,
			NoDA:                 false,
			EncryptedDuplication: false,
			Restricted:           true,
			Decrypt:              true,
			SignEncrypt:          false,
		},
		AuthPolicy: TPM2BDigest{
			Buffer: []byte{
				// TPM2_PolicySecret(RH_ENDORSEMENT)
				0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xB3, 0xF8,
				0x1A, 0x90, 0xCC, 0x8D, 0x46, 0xA5, 0xD7, 0x24,
				0xFD, 0x52, 0xD7, 0x6E, 0x06, 0x52, 0x0B, 0x64,
				0xF2, 0xA1, 0xDA, 0x1B, 0x33, 0x14, 0x69, 0xAA,
			},
		},
		Parameters: NewTPMUPublicParms(
			TPMAlgRSA,
			&TPMSRSAParms{
				Symmetric: TPMTSymDefObject{
					Algorithm: TPMAlgAES,
					KeyBits: NewTPMUSymKeyBits(
						TPMAlgAES,
						TPMKeyBits(128),
					),
					Mode: NewTPMUSymMode(
						TPMAlgAES,
						TPMAlgCFB,
					),
				},
				KeyBits: 2048,
			},
		),
		Unique: NewTPMUPublicID(
			TPMAlgRSA,
			&TPM2BPublicKeyRSA{
				Buffer: make([]byte, 256),
			},
		),
	}

	// ECCSRKTemplate contains the TCG reference ECC-P256 SRK template.
	// https://trustedcomputinggroup.org/wp-content/uploads/TCG-TPM-v2.0-Provisioning-Guidance-Published-v1r1.pdf
	ECCSRKTemplate = TPMTPublic{
		Type:    TPMAlgECC,
		NameAlg: TPMAlgSHA256,
		ObjectAttributes: TPMAObject{
			FixedTPM:             true,
			STClear:              false,
			FixedParent:          true,
			SensitiveDataOrigin:  true,
			UserWithAuth:         true,
			AdminWithPolicy:      false,
			NoDA:                 true,
			EncryptedDuplication: false,
			Restricted:           true,
			Decrypt:              true,
			SignEncrypt:          false,
		},
		Parameters: NewTPMUPublicParms(
			TPMAlgECC,
			&TPMSECCParms{
				Symmetric: TPMTSymDefObject{
					Algorithm: TPMAlgAES,
					KeyBits: NewTPMUSymKeyBits(
						TPMAlgAES,
						TPMKeyBits(128),
					),
					Mode: NewTPMUSymMode(
						TPMAlgAES,
						TPMAlgCFB,
					),
				},
				CurveID: TPMECCNistP256,
			},
		),
		Unique: NewTPMUPublicID(
			TPMAlgECC,
			&TPMSECCPoint{
				X: TPM2BECCParameter{
					Buffer: make([]byte, 32),
				},
				Y: TPM2BECCParameter{
					Buffer: make([]byte, 32),
				},
			},
		),
	}

	// ECCEKTemplate contains the TCG reference ECC-P256 EK template.
	ECCEKTemplate = TPMTPublic{
		Type:    TPMAlgECC,
		NameAlg: TPMAlgSHA256,
		ObjectAttributes: TPMAObject{
			FixedTPM:             true,
			STClear:              false,
			FixedParent:          true,
			SensitiveDataOrigin:  true,
			UserWithAuth:         false,
			AdminWithPolicy:      true,
			NoDA:                 false,
			EncryptedDuplication: false,
			Restricted:           true,
			Decrypt:              true,
			SignEncrypt:          false,
		},
		AuthPolicy: TPM2BDigest{
			Buffer: []byte{
				// TPM2_PolicySecret(RH_ENDORSEMENT)
				0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xB3, 0xF8,
				0x1A, 0x90, 0xCC, 0x8D, 0x46, 0xA5, 0xD7, 0x24,
				0xFD, 0x52, 0xD7, 0x6E, 0x06, 0x52, 0x0B, 0x64,
				0xF2, 0xA1, 0xDA, 0x1B, 0x33, 0x14, 0x69, 0xAA,
			},
		},
		Parameters: NewTPMUPublicParms(
			TPMAlgECC,
			&TPMSECCParms{
				Symmetric: TPMTSymDefObject{
					Algorithm: TPMAlgAES,
					KeyBits: NewTPMUSymKeyBits(
						TPMAlgAES,
						TPMKeyBits(128),
					),
					Mode: NewTPMUSymMode(
						TPMAlgAES,
						TPMAlgCFB,
					),
				},
				CurveID: TPMECCNistP256,
			},
		),
		Unique: NewTPMUPublicID(
			TPMAlgECC,
			&TPMSECCPoint{
				X: TPM2BECCParameter{
					Buffer: make([]byte, 32),
				},
				Y: TPM2BECCParameter{
					Buffer: make([]byte, 32),
				},
			},
		),
	}
)

// RSAEKTemplateWithPublicKey returns a new TPMT_PUBLIC using the template for
// an RSA EK and the specified RSA public key.
func RSAEKTemplateWithPublicKey(pubKey TPM2BPublicKeyRSA) (TPMTPublic, error) {
	ek, err := Copy(RSAEKTemplate)
	if err != nil {
		return TPMTPublic{}, fmt.Errorf("failed to copy rsa ek tpl: %w", err)
	}
	ek.Unique = NewTPMUPublicID(TPMAlgRSA, &pubKey)
	return ek, err
}

// ECCEKTemplateWithPoint returns a new TPMT_PUBLIC using the template for an
// ECC EK and the specified ECC point.
func ECCEKTemplateWithPoint(point TPMSECCPoint) (TPMTPublic, error) {
	ek, err := Copy(ECCEKTemplate)
	if err != nil {
		return TPMTPublic{}, fmt.Errorf("failed to copy ecc ek tpl: %w", err)
	}
	ek.Unique = NewTPMUPublicID(TPMAlgECC, &point)
	return ek, err
}
