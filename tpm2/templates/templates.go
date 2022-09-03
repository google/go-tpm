package templates

import (
	"github.com/google/go-tpm/tpm2/helpers"
	"github.com/google/go-tpm/tpm2/structures/tpm"
	"github.com/google/go-tpm/tpm2/structures/tpm2b"
	"github.com/google/go-tpm/tpm2/structures/tpma"
	"github.com/google/go-tpm/tpm2/structures/tpms"
	"github.com/google/go-tpm/tpm2/structures/tpmt"
	"github.com/google/go-tpm/tpm2/structures/tpmu"
)

var (
	// RSASRKTemplate contains the TCG reference RSA-2048 SRK template.
	// https://trustedcomputinggroup.org/wp-content/uploads/TCG-tpm.-v2.0-Provisioning-Guidance-Published-v1r1.pdf
	RSASRKTemplate = tpmt.Public{
		Type:    tpm.AlgRSA,
		NameAlg: tpm.AlgSHA256,
		ObjectAttributes: tpma.Object{
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
		Parameters: tpmu.PublicParms{
			RSADetail: &tpms.RSAParms{
				Symmetric: tpmt.SymDefObject{
					Algorithm: tpm.AlgAES,
					KeyBits: tpmu.SymKeyBits{
						AES: helpers.NewKeyBits(128),
					},
					Mode: tpmu.SymMode{
						AES: helpers.NewAlgID(tpm.AlgCFB),
					},
				},
				KeyBits: 2048,
			},
		},
		Unique: tpmu.PublicID{
			RSA: &tpm2b.PublicKeyRSA{
				Buffer: make([]byte, 256),
			},
		},
	}
	// RSAEKTemplate contains the TCG reference RSA-2048 EK template.
	RSAEKTemplate = tpmt.Public{
		Type:    tpm.AlgRSA,
		NameAlg: tpm.AlgSHA256,
		ObjectAttributes: tpma.Object{
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
		AuthPolicy: tpm2b.Digest{
			Buffer: []byte{
				// tpm.2_PolicySecret(RH_ENDORSEMENT)
				0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xB3, 0xF8,
				0x1A, 0x90, 0xCC, 0x8D, 0x46, 0xA5, 0xD7, 0x24,
				0xFD, 0x52, 0xD7, 0x6E, 0x06, 0x52, 0x0B, 0x64,
				0xF2, 0xA1, 0xDA, 0x1B, 0x33, 0x14, 0x69, 0xAA,
			},
		},
		Parameters: tpmu.PublicParms{
			RSADetail: &tpms.RSAParms{
				Symmetric: tpmt.SymDefObject{
					Algorithm: tpm.AlgAES,
					KeyBits: tpmu.SymKeyBits{
						AES: helpers.NewKeyBits(128),
					},
					Mode: tpmu.SymMode{
						AES: helpers.NewAlgID(tpm.AlgCFB),
					},
				},
				KeyBits: 2048,
			},
		},
		Unique: tpmu.PublicID{
			RSA: &tpm2b.PublicKeyRSA{
				Buffer: make([]byte, 256),
			},
		},
	}

	// ECCSRKTemplate contains the TCG reference ECC-P256 SRK template.
	// https://trustedcomputinggroup.org/wp-content/uploads/TCG-tpm.-v2.0-Provisioning-Guidance-Published-v1r1.pdf
	ECCSRKTemplate = tpmt.Public{
		Type:    tpm.AlgECC,
		NameAlg: tpm.AlgSHA256,
		ObjectAttributes: tpma.Object{
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
		Parameters: tpmu.PublicParms{
			ECCDetail: &tpms.ECCParms{
				Symmetric: tpmt.SymDefObject{
					Algorithm: tpm.AlgAES,
					KeyBits: tpmu.SymKeyBits{
						AES: helpers.NewKeyBits(128),
					},
					Mode: tpmu.SymMode{
						AES: helpers.NewAlgID(tpm.AlgCFB),
					},
				},
				CurveID: tpm.ECCNistP256,
			},
		},
		Unique: tpmu.PublicID{
			ECC: &tpms.ECCPoint{
				X: tpm2b.ECCParameter{
					Buffer: make([]byte, 32),
				},
				Y: tpm2b.ECCParameter{
					Buffer: make([]byte, 32),
				},
			},
		},
	}

	// ECCEKTemplate contains the TCG reference ECC-P256 EK template.
	ECCEKTemplate = tpmt.Public{
		Type:    tpm.AlgECC,
		NameAlg: tpm.AlgSHA256,
		ObjectAttributes: tpma.Object{
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
		AuthPolicy: tpm2b.Digest{
			Buffer: []byte{
				// tpm.2_PolicySecret(RH_ENDORSEMENT)
				0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xB3, 0xF8,
				0x1A, 0x90, 0xCC, 0x8D, 0x46, 0xA5, 0xD7, 0x24,
				0xFD, 0x52, 0xD7, 0x6E, 0x06, 0x52, 0x0B, 0x64,
				0xF2, 0xA1, 0xDA, 0x1B, 0x33, 0x14, 0x69, 0xAA,
			},
		},
		Parameters: tpmu.PublicParms{
			ECCDetail: &tpms.ECCParms{
				Symmetric: tpmt.SymDefObject{
					Algorithm: tpm.AlgAES,
					KeyBits: tpmu.SymKeyBits{
						AES: helpers.NewKeyBits(128),
					},
					Mode: tpmu.SymMode{
						AES: helpers.NewAlgID(tpm.AlgCFB),
					},
				},
				CurveID: tpm.ECCNistP256,
			},
		},
		Unique: tpmu.PublicID{
			ECC: &tpms.ECCPoint{
				X: tpm2b.ECCParameter{
					Buffer: make([]byte, 32),
				},
				Y: tpm2b.ECCParameter{
					Buffer: make([]byte, 32),
				},
			},
		},
	}
)
