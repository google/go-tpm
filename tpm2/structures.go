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
	"fmt"

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
	Type          Algorithm
	NameAlg       Algorithm
	Attributes    KeyProp
	AuthPolicy    []byte
	RSAParameters *RSAParams
	ECCParameters *ECCParams
	// TODO: this is struct{x, y} for ECC
	Unique []byte
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
	tail, err := tpmutil.Pack(p.Unique)
	if err != nil {
		return nil, err
	}
	return concat(head, params, tail)
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
	if err != nil {
		return pub, err
	}

	err = tpmutil.UnpackBuf(in, &pub.Unique)
	return pub, err
}

type RSAParams struct {
	Symmetric *SymScheme
	Sign      *SigScheme
	KeyBits   uint16
	Exponent  uint32
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
	rest, err := tpmutil.Pack(p.KeyBits, p.Exponent)
	if err != nil {
		return nil, err
	}
	return concat(sym, sig, rest)
}

func decodeRSAParams(in *bytes.Buffer) (*RSAParams, error) {
	var params RSAParams
	var err error

	params.Symmetric, err = decodeSymScheme(in)
	if err != nil {
		return nil, err
	}
	params.Sign, err = decodeSigScheme(in)
	if err != nil {
		return nil, err
	}
	if err := tpmutil.UnpackBuf(in, &params.KeyBits, &params.Exponent); err != nil {
		return nil, err
	}
	if params.Exponent == 0 {
		params.Exponent = defaultRSAExponent
	}
	return &params, nil
}

type ECCParams struct {
	Symmetric *SymScheme
	Sign      *SigScheme
	CurveID   ECCCurve
	KDF       *KDFScheme
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
	return concat(sym, sig, curve, kdf)
}

func decodeECCParams(in *bytes.Buffer) (*ECCParams, error) {
	var params ECCParams
	var err error

	params.Symmetric, err = decodeSymScheme(in)
	if err != nil {
		return nil, err
	}
	params.Sign, err = decodeSigScheme(in)
	if err != nil {
		return nil, err
	}
	if err := tpmutil.UnpackBuf(in, &params.CurveID); err != nil {
		return nil, err
	}
	params.KDF, err = decodeKDFScheme(in)
	if err != nil {
		return nil, err
	}
	return &params, nil
}

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

type tpmtSignatureRSA struct {
	SigAlg    Algorithm
	HashAlg   Algorithm
	Signature []byte
}

// Private contains private section of a TPM key.
//
// TODO(awly): this is RSA-specific right now. Make it work for other Types.
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
