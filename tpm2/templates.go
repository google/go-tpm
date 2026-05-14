package tpm2

import (
	"bytes"
	"encoding/hex"
	"fmt"
)

// Template enumerates the default Endorsement Key (EK) templates.
//
// These templates are defined in the EK Credential Profile:
// https://trustedcomputinggroup.org/resource/tcgek-credential-profile-for-tpm-family-2-0/,
//
// This includes
//   - the "Low Range" templates: [TemplateL1] and [TemplateL2]
//   - the "High Range" templates: [TemplateH1] to [TemplateH7]
type Template int32

const (
	_ = Template(iota) // Skip 0 to ensure [TemplateH1] starts at 1
	// Template H-1: RSA 2048 (Storage)
	TemplateH1
	// Template H-2: ECC NIST P256 (Storage)
	TemplateH2
	// Template H-3: ECC NIST P384 (Storage)
	TemplateH3
	// Template H-4: ECC NIST P521 (Storage)
	TemplateH4
	// Template H-5: ECC SM2 P256 (Storage)
	TemplateH5
	// Template H-6: RSA 3072 (Storage)
	TemplateH6
	// Template H-7: RSA 4096 (Storage)
	TemplateH7
	highRangeLast = TemplateH7

	// Template L-1: RSA 2048 (Storage)
	TemplateL1 = Template(-1)
	// Template L-2: ECC NIST P256 (Storage)
	TemplateL2 = Template(-2)
)

// IsLowRange returns true if this template is defined in the legacy "Low Range"
// rather than the "High Range".
//
// Low Range templates have a [TPMTPublic.AuthPolicy] of [AuthPolicyA], while
// High Range templates have a [TPMTPublic.AuthPolicy] of [AuthPolicyB].
func (t Template) IsLowRange() bool {
	return t == TemplateL1 || t == TemplateL2
}

func (t Template) String() string {
	if t.IsLowRange() {
		return fmt.Sprintf("TemplateL%d", -int32(t)) // -2 -> TemplateL2
	} else if t > 0 && t <= highRangeLast {
		return fmt.Sprintf("TemplateH%d", int32(t)) // 2 -> TemplateH2
	} else {
		return fmt.Sprintf("Template(%d)", int32(t)) // -27 -> Template(-27)
	}
}

var (
	aes128 = TPMTSymDefObject{
		Algorithm: TPMAlgAES,
		KeyBits:   NewTPMUSymKeyBits(TPMAlgAES, TPMKeyBits(128)),
		Mode:      NewTPMUSymMode(TPMAlgAES, TPMAlgCFB),
	}
	aes256 = TPMTSymDefObject{
		Algorithm: TPMAlgAES,
		KeyBits:   NewTPMUSymKeyBits(TPMAlgAES, TPMKeyBits(256)),
		Mode:      NewTPMUSymMode(TPMAlgAES, TPMAlgCFB),
	}
	sm4128 = TPMTSymDefObject{
		Algorithm: TPMAlgSM4,
		KeyBits:   NewTPMUSymKeyBits(TPMAlgSM4, TPMKeyBits(128)),
		Mode:      NewTPMUSymMode(TPMAlgSM4, TPMAlgCFB),
	}
)

func newRSA(bits TPMIRSAKeyBits, hashAlg TPMIAlgHash, sym TPMTSymDefObject) TPMTPublic {
	return TPMTPublic{
		Type:    TPMAlgRSA,
		NameAlg: hashAlg,
		Parameters: NewTPMUPublicParms(TPMAlgRSA, &TPMSRSAParms{
			Symmetric: sym,
			KeyBits:   bits,
		}),
	}
}

func newECC(curve TPMIECCCurve, hashAlg TPMIAlgHash, sym TPMTSymDefObject) TPMTPublic {
	return TPMTPublic{
		Type:    TPMAlgECC,
		NameAlg: hashAlg,
		Parameters: NewTPMUPublicParms(TPMAlgECC, &TPMSECCParms{
			Symmetric: sym,
			CurveID:   curve,
		}),
	}
}

// PublicEK returns a [TPMTPublic] for an Endorsement Key (EK).
//
// This template can then be used with [TPMRHEndorsement], [CreatePrimary], and
// [New2B] to create the EK:
//
//	createEK := CreatePrimary{
//		PrimaryHandle: TPMRHEndorsement,
//		InPublic:      New2B(TemplateH3.PublicEK()),
//	}
//	rsp, err := createEK.Execute(tpm)
func (t Template) PublicEK() TPMTPublic {
	var pub TPMTPublic
	switch t {
	case TemplateL1:
		// Low Range RSA-2048 template has a non-empty Unique field.
		pub = newRSA(2048, TPMAlgSHA256, aes128)
		pub.Unique = NewTPMUPublicID(TPMAlgRSA, &TPM2BPublicKeyRSA{
			Buffer: make([]byte, 2048/8),
		})
	case TemplateL2:
		// Low Range ECC-P256 template has a non-empty Unique field.
		pub = newECC(TPMECCNistP256, TPMAlgSHA256, aes128)
		pub.Unique = NewTPMUPublicID(TPMAlgECC, &TPMSECCPoint{
			X: TPM2BECCParameter{Buffer: make([]byte, 256/8)},
			Y: TPM2BECCParameter{Buffer: make([]byte, 256/8)},
		})
	case TemplateH1:
		pub = newRSA(2048, TPMAlgSHA256, aes128) // RSA-2048
	case TemplateH2:
		pub = newECC(TPMECCNistP256, TPMAlgSHA256, aes128) // ECC-P256
	case TemplateH3:
		pub = newECC(TPMECCNistP384, TPMAlgSHA384, aes256) // ECC-P384
	case TemplateH4:
		pub = newECC(TPMECCNistP521, TPMAlgSHA512, aes256) // ECC-P521
	case TemplateH5:
		pub = newECC(TPMECCSM2P256, TPMAlgSM3256, sm4128) // SM2-P256
	case TemplateH6:
		pub = newRSA(3072, TPMAlgSHA384, aes256) // RSA-3072
	case TemplateH7:
		pub = newRSA(4096, TPMAlgSHA384, aes256) // RSA-4096
	default:
		panic(fmt.Sprintf("unhandled template: %v", t))
	}

	pub.ObjectAttributes = TPMAObject{
		FixedTPM:             true,
		STClear:              false,
		FixedParent:          true,
		SensitiveDataOrigin:  true,
		UserWithAuth:         !t.IsLowRange(), // Set for High Range templates
		AdminWithPolicy:      true,
		FirmwareLimited:      false,
		NoDA:                 false,
		EncryptedDuplication: false,
		Restricted:           true,
		Decrypt:              true,
		SignEncrypt:          false,
		X509Sign:             false,
	}

	var err error
	if t.IsLowRange() {
		pub.AuthPolicy, err = AuthPolicyA(pub.NameAlg)
	} else {
		pub.AuthPolicy, err = AuthPolicyB(pub.NameAlg)
	}
	if err != nil {
		panic(err)
	}
	return pub
}

// PublicSRK returns a modified [TPMTPublic] for a shared Storage Root Key (SRK).
//
// Specifically, this template is based on [Template.PublicEK] but with
// [TPMAObject.NoDA] set, and Enhanced Authorization disabled by:
//   - clearing [TPMTPublic.AuthPolicy]
//   - setting [TPMAObject.UserWithAuth]
//   - clearing [TPMAObject.AdminWithPolicy]
//
// This modification is described in the official TPM 2.0 Provisioning Guidance:
// https://trustedcomputinggroup.org/resource/tcg-tpm-v2-0-provisioning-guidance/.
//
// This template can then be used with [TPMRHOwner], [CreatePrimary], and
// [New2B] to create the SRK:
//
//	createSRK := CreatePrimary{
//		PrimaryHandle: TPMRHOwner,
//		InPublic:      New2B(TemplateH3.PublicSRK()),
//	}
//	rsp, err := createSRK.Execute(tpm)
func (t Template) PublicSRK() TPMTPublic {
	pub := t.PublicEK()
	pub.ObjectAttributes.UserWithAuth = true
	pub.ObjectAttributes.AdminWithPolicy = false
	pub.ObjectAttributes.NoDA = true
	pub.AuthPolicy = TPM2BDigest{Buffer: nil}
	return pub
}

// Decodes the provided hex strings into a byte array. Panics on non-hex chars.
func hexToBytes(hexStrings ...string) []byte {
	var buf []byte
	for _, s := range hexStrings {
		var err error
		buf, err = hex.AppendDecode(buf, []byte(s))
		if err != nil {
			panic(err)
		}
	}
	return buf
}

// Policy and NV Index constants from EK Credential Profile.
var (
	policyA = map[TPMIAlgHash][]byte{
		TPMAlgSHA256: hexToBytes(
			"837197674484b3f81a90cc8d46a5d724",
			"fd52d76e06520b64f2a1da1b331469aa",
		),
		TPMAlgSHA384: hexToBytes(
			"8bbf2266537c171cb56e403c4dc1d4b6",
			"4f432611dc386e6f532050c3278c930e",
			"143e8bb1133824ccb431053871c6db53",
		),
		TPMAlgSHA512: hexToBytes(
			"1e3b76502c8a1425aa0b7b3fc646a1b0",
			"fae063b03b5368f9c4cddecaff0891dd",
			"682bac1a85d4d832b781ea451915de5f",
			"c5bf0dc4a1917cd42fa041e3f998e0ee",
		),
		TPMAlgSM3256: hexToBytes(
			"c67f7d35f66f3bec13c89fe898921c65",
			"1b0cb5a38a92690a62a43c0012e4fb8b",
		),
	}
	policyB = map[TPMIAlgHash][]byte{
		TPMAlgSHA256: hexToBytes(
			"ca3d0a99a2b93906f7a3342414efcfb3",
			"a385d44cd1fd459089d19b5071c0b7a0",
		),
		TPMAlgSHA384: hexToBytes(
			"b26e7d28d11a50bc53d882bcf5fd3a1a",
			"074148bb35d3b4e4cb1c0ad9bde419ca",
			"cb47ba09699646150f9fc000f3f80e12",
		),
		TPMAlgSHA512: hexToBytes(
			"b8221ca69e8550a4914de3faa6a18c07",
			"2cc01208073a928d5d66d59ef79e49a4",
			"29c41a6b269571d57edb25fbdb183842",
			"5608b413cd616a5f6db5b6071af99bea",
		),
		TPMAlgSM3256: hexToBytes(
			"167860a35f2c5c3567f9c927ac56c032",
			"f3b3a6462f8d037998e7a10f77fa454a",
		),
	}
	policyC = map[TPMIAlgHash][]byte{
		TPMAlgSHA256: hexToBytes(
			"3767e2edd43ff45a3a7e1eaefcef7864",
			"3dca964632e7aad82c673a30d8633fde",
		),
		TPMAlgSHA384: hexToBytes(
			"d6032ce61f2fb3c240eb3cf6a33237ef",
			"2b6a16f4293c22b455e261cffd217ad5",
			"b4947c2d73e63005eed2dc2b3593d165",
		),
		TPMAlgSHA512: hexToBytes(
			"589ee1e146544716e8deafe6db247b01",
			"b81e9f9c7dd16b814aa159138749105f",
			"ba5388dd1dea702f35240c184933121e",
			"2c61b8f50d3ef91393a49a38c3f73fc8",
		),
		TPMAlgSM3256: hexToBytes(
			"2d4e81578c3531d9bd1cdd7d02ba298d",
			"5699a3e39fc3551bfeffcf132b49e11d",
		),
	}
	nvIndex = map[TPMIAlgHash]TPMIRHNVIndex{
		TPMAlgSHA256: 0x01c07f01, // Policy Index I-1
		TPMAlgSHA384: 0x01c07f02, // Policy Index I-2
		TPMAlgSHA512: 0x01c07f03, // Policy Index I-3
		TPMAlgSM3256: 0x01c07f04, // Policy Index I-4
	}
)

// AuthPolicyA is a policy satisfied by proving knowledge of the Endorsement
// Hierarchy password.
//
// This is done by executing [PolicySecret] with [TPMRHEndorsement]. See the
// "Satisfying PolicyA" section of the EK Credential Profile for more info.
//
// This is the [TPMTPublic.AuthPolicy] for all Low Range templates.
func AuthPolicyA(hashAlg TPMIAlgHash) (TPM2BDigest, error) {
	if policy, ok := policyA[hashAlg]; ok {
		return TPM2BDigest{Buffer: bytes.Clone(policy)}, nil
	}
	return TPM2BDigest{}, fmt.Errorf("no PolicyA for hash alg 0x%x", hashAlg)
}

// AuthPolicyB is a policy satisfied by satisfying [AuthPolicyA] or
// [AuthPolicyC].
//
// This is done by:
//   - First, satifying either of the two policies.
//   - Then, executing [PolicyOr] with a digest list of {PolicyA, PolicyC}.
//
// See the "Satisfying PolicyB" section of the EK Credential Profile for more info.
//
// This is the [TPMTPublic.AuthPolicy] for all High Range templates.
func AuthPolicyB(hashAlg TPMIAlgHash) (TPM2BDigest, error) {
	if policy, ok := policyB[hashAlg]; ok {
		return TPM2BDigest{Buffer: bytes.Clone(policy)}, nil
	}
	return TPM2BDigest{}, fmt.Errorf("no PolicyB for hash alg 0x%x", hashAlg)
}

// AuthPolicyC is a policy satisfied by satisfying the policy stored at
// [AuthPolicyNVPublic].
//
// This is done by executing [PolicyAuthorizeNV] with the [TPMSNVPublic.NVIndex]
// of [AuthPolicyNVPublic].
func AuthPolicyC(hashAlg TPMIAlgHash) (TPM2BDigest, error) {
	if policy, ok := policyC[hashAlg]; ok {
		return TPM2BDigest{Buffer: bytes.Clone(policy)}, nil
	}
	return TPM2BDigest{}, fmt.Errorf("no PolicyC for hash alg 0x%x", hashAlg)
}

// AuthPolicyNVPublic is a [TPMSNVPublic] for the NV Index holding the
// [TPM2BDigest] for the policy needed to satisfy [AuthPolicyC].
//
// The NV index containing the delegated policy must have this exact public
// information, or the call to [PolicyAuthorizeNV] for [AuthPolicyC] will not
// produce the correct policy digest. Note that the [TPMSNVPublic.AuthPolicy]
// is set to [AuthPolicyA], so knowledge of the Endorsement Hierarchy password
// is necessary to write or change this delegated policy.
func AuthPolicyNVPublic(hashAlg TPMIAlgHash) (TPMSNVPublic, error) {
	idx, ok := nvIndex[hashAlg]
	if !ok {
		err := fmt.Errorf("no Policy NV Index for hash alg 0x%x", hashAlg)
		return TPMSNVPublic{}, err
	}
	authPolicy, err := AuthPolicyA(hashAlg)
	if err != nil {
		return TPMSNVPublic{}, err
	}
	return TPMSNVPublic{
		NVIndex: idx,
		NameAlg: hashAlg,
		Attributes: TPMANV{
			PPWrite:        false,
			OwnerWrite:     false,
			AuthWrite:      false,
			PolicyWrite:    true,
			NT:             TPMNT(0),
			PolicyDelete:   false,
			WriteLocked:    false,
			WriteAll:       true,
			WriteDefine:    false,
			WriteSTClear:   false,
			GlobalLock:     false,
			PPRead:         true,
			OwnerRead:      true,
			AuthRead:       true,
			PolicyRead:     true,
			NoDA:           true,
			Orderly:        false,
			ClearSTClear:   false,
			ReadLocked:     false,
			Written:        true,
			PlatformCreate: false,
			ReadSTClear:    false,
		},
		AuthPolicy: authPolicy,
		DataSize:   uint16(2 + len(authPolicy.Buffer)),
	}, nil
}

// Deprecated public global variables (not safe to mutate)
var (
	// RSASRKTemplate contains the TCG reference RSA-2048 SRK template.
	//
	// Deprecated: use the [Template.PublicSRK] method of [TemplateL1] to
	// create a new copy of this template, rather than accessing this variable.
	//
	//     srkTemplate := TemplateL1.PublicSRK()
	RSASRKTemplate = TemplateL1.PublicSRK()
	// RSAEKTemplate contains the TCG reference RSA-2048 EK template.
	//
	// Deprecated: use the [Template.PublicEK] method of [TemplateL1] to
	// create a new copy of this template, rather than accessing this variable.
	//
	//     ekTemplate := TemplateL1.PublicEK()
	RSAEKTemplate = TemplateL1.PublicEK()
	// ECCSRKTemplate contains the TCG reference ECC-P256 SRK template.
	//
	// Deprecated: use the [Template.PublicSRK] method of [TemplateL2] to
	// create a new copy of this template, rather than accessing this variable.
	//
	//     srkTemplate := TemplateL2.PublicSRK()
	ECCSRKTemplate = TemplateL2.PublicSRK()
	// ECCEKTemplate contains the TCG reference ECC-P256 EK template.
	//
	// Deprecated: use the [Template.PublicEK] method of [TemplateL2] to
	// create a new copy of this template, rather than accessing this variable.
	//
	//     ekTemplate := TemplateL2.PublicEK()
	ECCEKTemplate = TemplateL2.PublicEK()
)
