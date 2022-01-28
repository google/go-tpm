// package tpmt contains TPM 2.0 structures prefixed with "TPMT_"
package tpmt

import "fmt"

// HA represents a TPMT_HA.
// See definition in Part 2: Structures, section 10.3.2.
type HA struct {
	// selector of the hash contained in the digest that implies the size of the digest
	HashAlg tpmi.AlgHash `gotpm:"nullable"`
	// the digest data
	Digest tpmu.HA `gotpm:"tag=HashAlg"`
}

// TKCreation represents a TPMT_TK_CREATION.
// See definition in Part 2: Structures, section 10.7.3.
type TKCreation struct {
	// ticket structure tag
	Tag tpm.ST
	// the hierarchy containing name
	Hierarchy tpmi.RHHierarchy
	// This shall be the HMAC produced using a proof value of hierarchy.
	Digest tpm2b.Digest
}

// TKAuth represents a TPMT_TK_AUTH.
// See definition in Part 2: Structures, section 10.7.5.
type TKAuth struct {
	// ticket structure tag
	Tag tpm.ST
	// the hierarchy of the object used to produce the ticket
	Hierarchy tpmi.RHHierarchy
	// This shall be the HMAC produced using a proof value of hierarchy.
	Digest tpm2b.Digest
}

// SymDefObject represents a TPMT_SYM_DEF_OBJECT.
// See definition in Part 2: Structures, section 11.1.7.
type SymDefObject struct {
	// selects a symmetric block cipher
	// When used in the parameter area of a parent object, this shall
	// be a supported block cipher and not TPM_ALG_NULL
	Algorithm tpmi.AlgSymObject `gotpm:"nullable"`
	// the key size
	KeyBits tpmu.SymKeyBits `gotpm:"tag=Algorithm"`
	// default mode
	// When used in the parameter area of a parent object, this shall
	// be TPM_ALG_CFB.
	Mode tpmu.SymMode `gotpm:"tag=Algorithm"`
	// contains the additional algorithm details, if any
	Details tpmu.SymDetails `gotpm:"tag=Algorithm"`
}

// KeyedHashScheme represents a TPMT_KEYEDHASH_SCHEME.
// See definition in Part 2: Structures, section 11.1.23.
type KeyedHashScheme struct {
	Scheme  tpmi.AlgKeyedHashScheme `gotpm:"nullable"`
	Details tpmu.SchemeKeyedHash    `gotpm:"tag=Scheme"`
}

// SigScheme represents a TPMT_SIG_SCHEME.
// See definition in Part 2: Structures, section 11.2.1.5.
type SigScheme struct {
	Scheme  tpmi.AlgSigScheme `gotpm:"nullable"`
	Details tpmu.SigScheme    `gotpm:"tag=Scheme"`
}

// KDFScheme represents a TPMT_KDF_SCHEME.
// See definition in Part 2: Structures, section 11.2.3.3.
type KDFScheme struct {
	// scheme selector
	Scheme tpmi.AlgKDF `gotpm:"nullable"`
	// scheme parameters
	Details tpmu.KDFScheme `gotpm:"tag=Scheme"`
}

// RSAScheme represents a TPMT_RSA_SCHEME.
// See definition in Part 2: Structures, section 11.2.4.2.
type RSAScheme struct {
	// scheme selector
	Scheme tpmi.AlgRSAScheme `gotpm:"nullable"`
	// scheme parameters
	Details tpmu.AsymScheme `gotpm:"tag=Scheme"`
}

// ECCScheme represents a TPMT_ECC_SCHEME.
// See definition in Part 2: Structures, section 11.2.5.6.
type ECCScheme struct {
	// scheme selector
	Scheme tpmi.AlgECCScheme `gotpm:"nullable"`
	// scheme parameters
	Details tpmu.AsymScheme `gotpm:"tag=Scheme"`
}

// Signature represents a TPMT_SIGNATURE.
// See definition in Part 2: Structures, section 11.3.4.
type Signature struct {
	// selector of the algorithm used to construct the signature
	SigAlg tpmi.AlgSigScheme `gotpm:"nullable"`
	// This shall be the actual signature information.
	Signature tpmuSignature `gotpm:"tag=SigAlg"`
}

// Public represents a TPMT_PUBLIC.
// See definition in Part 2: Structures, section 12.2.4.
type Public struct {
	// “algorithm” associated with this object
	Type tpmi.AlgPublic
	// algorithm used for computing the Name of the object
	NameAlg tpmi.AlgHash
	// attributes that, along with type, determine the manipulations
	// of this object
	ObjectAttributes tpma.Object
	// optional policy for using this key
	// The policy is computed using the nameAlg of the object.
	AuthPolicy tpm2b.Digest
	// the algorithm or structure details
	Parameters tpmu.PublicParms `gotpm:"tag=Type"`
	// the unique identifier of the structure
	// For an asymmetric key, this would be the public key.
	Unique tpmu.PublicID `gotpm:"tag=Type"`
}

