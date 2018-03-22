// Copyright (c) 2018, Google Inc. All rights reserved.
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

package tpm2

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"

	"github.com/google/go-tpm/tpmutil"
)

// NVPublic contains the public area of an NV index.
type NVPublic struct {
	NVIndex    tpmutil.Handle
	NameAlg    Algorithm
	Attributes KeyProp
	AuthPolicy []byte
	DataSize   uint16
}

type tpmsSensitiveCreate struct {
	UserAuth []byte
	Data     []byte
}

// PCRSelection contains a slice of PCR indexes and a hash algorithm used in
// them.
type PCRSelection struct {
	Hash Algorithm
	PCRs []int
}

type tpmsPCRSelection struct {
	Hash Algorithm
	Size byte
	PCRs tpmutil.RawBytes
}

// Public contains the public area of an object.
type Public struct {
	Type       Algorithm
	NameAlg    Algorithm
	Attributes KeyProp
	AuthPolicy []byte

	// Only one of the Parameters fields should be set. When encoding/decoding,
	// one will be picked based on Type.
	RSAParameters *RSAParams
	ECCParameters *ECCParams
}

func (p Public) encode() ([]byte, error) {
	head, err := tpmutil.Pack(p.Type, p.NameAlg, p.Attributes, p.AuthPolicy)
	if err != nil {
		return nil, err
	}
	var params []byte
	switch p.Type {
	case AlgRSA:
		params, err = p.RSAParameters.encode()
	case AlgECC:
		params, err = p.ECCParameters.encode()
	default:
		err = fmt.Errorf("unsupported type in TPMT_PUBLIC: %v", p.Type)
	}
	if err != nil {
		return nil, err
	}
	return concat(head, params)
}

func decodePublic(in *bytes.Buffer) (Public, error) {
	var pub Public
	var err error
	if err = tpmutil.UnpackBuf(in, &pub.Type, &pub.NameAlg, &pub.Attributes, &pub.AuthPolicy); err != nil {
		return pub, fmt.Errorf("decoding TPMT_PUBLIC: %v", err)
	}

	switch pub.Type {
	case AlgRSA:
		pub.RSAParameters, err = decodeRSAParams(in)
	case AlgECC:
		pub.ECCParameters, err = decodeECCParams(in)
	default:
		err = fmt.Errorf("unsupported type in TPMT_PUBLIC: %v", pub.Type)
	}
	return pub, err
}

// RSAParams represents parameters of an RSA key pair.
//
// Symmetric and Sign may be nil, depending on key Attributes in Public.
// Modulus must always be non-nil.
type RSAParams struct {
	Symmetric *SymScheme
	Sign      *SigScheme
	KeyBits   uint16
	Exponent  uint32
	Modulus   *big.Int
}

func (p *RSAParams) encode() ([]byte, error) {
	if p == nil {
		return nil, nil
	}
	sym, err := p.Symmetric.encode()
	if err != nil {
		return nil, err
	}
	sig, err := p.Sign.encode()
	if err != nil {
		return nil, err
	}
	if p.Modulus == nil {
		return nil, errors.New("RSAParams.Modulus must be set")
	}
	rest, err := tpmutil.Pack(p.KeyBits, p.Exponent, p.Modulus.Bytes())
	if err != nil {
		return nil, err
	}
	return concat(sym, sig, rest)
}

func decodeRSAParams(in *bytes.Buffer) (*RSAParams, error) {
	var params RSAParams
	var err error

	if params.Symmetric, err = decodeSymScheme(in); err != nil {
		return nil, err
	}
	if params.Sign, err = decodeSigScheme(in); err != nil {
		return nil, err
	}
	var modBytes []byte
	if err := tpmutil.UnpackBuf(in, &params.KeyBits, &params.Exponent, &modBytes); err != nil {
		return nil, err
	}
	if params.Exponent == 0 {
		params.Exponent = defaultRSAExponent
	}
	params.Modulus = new(big.Int).SetBytes(modBytes)
	return &params, nil
}

// ECCParams represents parameters of an ECC key pair.
//
// Symmetric, Sign and KDF may be nil, depending on key Attributes in Public.
type ECCParams struct {
	Symmetric *SymScheme
	Sign      *SigScheme
	CurveID   EllipticCurve
	KDF       *KDFScheme
	Point     ECPoint
}

// ECPoint represents a ECC coordinates for a point.
type ECPoint struct {
	X, Y *big.Int
}

func (p *ECCParams) encode() ([]byte, error) {
	if p == nil {
		return nil, nil
	}
	sym, err := p.Symmetric.encode()
	if err != nil {
		return nil, err
	}
	sig, err := p.Sign.encode()
	if err != nil {
		return nil, err
	}
	curve, err := tpmutil.Pack(p.CurveID)
	if err != nil {
		return nil, err
	}
	kdf, err := p.KDF.encode()
	if err != nil {
		return nil, err
	}
	point, err := tpmutil.Pack(p.Point.X.Bytes(), p.Point.Y.Bytes())
	if err != nil {
		return nil, err
	}
	return concat(sym, sig, curve, kdf, point)
}

func decodeECCParams(in *bytes.Buffer) (*ECCParams, error) {
	var params ECCParams
	var err error

	if params.Symmetric, err = decodeSymScheme(in); err != nil {
		return nil, err
	}
	if params.Sign, err = decodeSigScheme(in); err != nil {
		return nil, err
	}
	if err := tpmutil.UnpackBuf(in, &params.CurveID); err != nil {
		return nil, err
	}
	if params.KDF, err = decodeKDFScheme(in); err != nil {
		return nil, err
	}
	var x, y []byte
	if err := tpmutil.UnpackBuf(in, &x, &y); err != nil {
		return nil, err
	}
	params.Point.X = new(big.Int).SetBytes(x)
	params.Point.Y = new(big.Int).SetBytes(y)
	return &params, nil
}

// SymScheme represents a symmetric encryption scheme.
type SymScheme struct {
	Alg     Algorithm
	KeyBits uint16
	Mode    Algorithm
}

func (s *SymScheme) encode() ([]byte, error) {
	if s == nil || s.Alg.IsNull() {
		return tpmutil.Pack(AlgNull)
	}
	return tpmutil.Pack(s.Alg, s.KeyBits, s.Mode)
}

func decodeSymScheme(in *bytes.Buffer) (*SymScheme, error) {
	var scheme SymScheme
	if err := tpmutil.UnpackBuf(in, &scheme.Alg); err != nil {
		return nil, err
	}
	if scheme.Alg == AlgNull {
		return nil, nil
	}
	if err := tpmutil.UnpackBuf(in, &scheme.KeyBits, &scheme.Mode); err != nil {
		return nil, err
	}
	return &scheme, nil
}

// SigScheme represents a signing scheme.
type SigScheme struct {
	Alg  Algorithm
	Hash Algorithm
}

func (s *SigScheme) encode() ([]byte, error) {
	if s == nil || s.Alg.IsNull() {
		return tpmutil.Pack(AlgNull)
	}
	return tpmutil.Pack(s.Alg, s.Hash)
}

func decodeSigScheme(in *bytes.Buffer) (*SigScheme, error) {
	var scheme SigScheme
	if err := tpmutil.UnpackBuf(in, &scheme.Alg); err != nil {
		return nil, err
	}
	if scheme.Alg == AlgNull {
		return nil, nil
	}
	if err := tpmutil.UnpackBuf(in, &scheme.Hash); err != nil {
		return nil, err
	}
	return &scheme, nil
}

// KDFScheme represents a KDF (Key Derivation Function) scheme.
type KDFScheme struct {
	Alg  Algorithm
	Hash Algorithm
}

func (s *KDFScheme) encode() ([]byte, error) {
	if s == nil || s.Alg.IsNull() {
		return tpmutil.Pack(AlgNull)
	}
	return tpmutil.Pack(s.Alg, s.Hash)
}

func decodeKDFScheme(in *bytes.Buffer) (*KDFScheme, error) {
	var scheme KDFScheme
	if err := tpmutil.UnpackBuf(in, &scheme.Alg); err != nil {
		return nil, err
	}
	if scheme.Alg == AlgNull {
		return nil, nil
	}
	if err := tpmutil.UnpackBuf(in, &scheme.Hash); err != nil {
		return nil, err
	}
	return &scheme, nil
}

// Signature combines all possible signatures from RSA and ECC keys. Only one
// of RSA or ECC will be populated.
type Signature struct {
	Alg Algorithm
	RSA *SignatureRSA
	ECC *SignatureECC
}

func decodeSignature(in *bytes.Buffer) (*Signature, error) {
	var sig Signature
	if err := tpmutil.UnpackBuf(in, &sig.Alg); err != nil {
		return nil, err
	}
	switch sig.Alg {
	case AlgRSASSA:
		sig.RSA = new(SignatureRSA)
		if err := tpmutil.UnpackBuf(in, sig.RSA); err != nil {
			return nil, err
		}
	case AlgECDSA:
		sig.ECC = new(SignatureECC)
		var r, s []byte
		if err := tpmutil.UnpackBuf(in, &sig.ECC.HashAlg, &r, &s); err != nil {
			return nil, err
		}
		sig.ECC.R = big.NewInt(0).SetBytes(r)
		sig.ECC.S = big.NewInt(0).SetBytes(s)
	default:
		return nil, fmt.Errorf("unsupported signature algorithm 0x%x", sig.Alg)
	}
	return &sig, nil
}

// SignatureRSA is an RSA-specific signature value.
type SignatureRSA struct {
	HashAlg   Algorithm
	Signature []byte
}

// SignatureECC is an ECC-specific signature value.
type SignatureECC struct {
	HashAlg Algorithm
	R       *big.Int
	S       *big.Int
}

// Private contains private section of a TPM key.
type Private struct {
	Type      Algorithm
	AuthValue []byte
	SeedValue []byte
	Sensitive []byte
}

func (p Private) encode() ([]byte, error) {
	if p.Type.IsNull() {
		return nil, nil
	}
	return tpmutil.Pack(p)
}

type tpmtSigScheme struct {
	Scheme Algorithm
	Hash   Algorithm
}
