// Copyright (c) 2014, Google Inc. All rights reserved.
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

package tpm

import (
	"crypto/rsa"
    "crypto/sha1"
	"errors"
	"math/big"
)

// This file provides functions to extract a crypto/rsa public key from a key
// blob or a TPM_KEY of the right type. It also provides a function for
// verifying a quote value given a public key for the key it was signed with.

// UnmarshalRSAPublicKey takes in a blob containing a serialized RSA TPM_KEY and
// converts it to a crypto/rsa.PublicKey.
func UnmarshalRSAPublicKey(keyBlob []byte) (*rsa.PublicKey, error) {
	// Parse the blob as a key.
	var k key
	if err := unpack(keyBlob, []interface{}{&k}); err != nil {
		return nil, err
	}

	return k.unmarshalRSAPublicKey()
}

// UnmarshalRSAPublicKey unmarshals a TPM key into a crypto/rsa.PublicKey.
func (k *key) unmarshalRSAPublicKey() (*rsa.PublicKey, error) {
	// Currently, we only support algRSA
	if k.AlgorithmParms.AlgID != algRSA {
		return nil, errors.New("only TPM_ALG_RSA is supported")
	}

	// This means that k.AlgorithmsParms.Parms is an rsaKeyParms, which is
	// enough to create the exponent, and k.PubKey contains the key.
	var rsakp rsaKeyParms
	if err := unpack(k.AlgorithmParms.Parms, []interface{}{&rsakp}); err != nil {
		return nil, err
	}

	// TODO(tmroeder): sanity check the AlgorithmParms in PubKey to make sure
	// they match?
	var pubk pubKey
	if err := unpack(k.PubKey, []interface{}{&pubk}); err != nil {
		return nil, err
	}

	// Make sure that the exponent will fit into an int before using it blindly.
	if len(rsakp.Exponent) > 4 {
		return nil, errors.New("exponent value doesn't fit into an int")
	}
	pk := &rsa.PublicKey{
		N: new(big.Int).SetBytes(pubk.Key),
		E: int(new(big.Int).SetBytes(rsakp.Exponent).Int64()),
	}
	return pk, nil
}

// newQuoteInfo computes a quoteInfo structure for a given pair of data and PCR
// values.
func newQuoteInfo(data []byte, pcrNums []int, pcrVals [][]byte) (*quoteInfo, error) {
    // Compute the composite hash for these PCRs.
    pcrSel, err := newPCRSelection(pcrNums)
    if err != nil {
        return nil, err
    }

    pcrs := make([]byte, 0, len(pcrVals) * PCRSize)
    for _, b := range pcrVals {
        pcrs = append(pcrs, b...)
    }

    comp, err := createPCRComposite(pcrSel.Mask, pcrs)
    if err != nil {
        return nil, err
    }

    qi := &quoteInfo{
        Version: quoteVersion,
        Fixed: fixedQuote,
        Nonce: sha1.Sum(data),
    }
    copy(qi.CompositeDigest[:], comp)

    return qi, nil
}

// VerifyQuote verifies a quote against a given set of PCRs.
func VerifyQuote(data []byte, quote []byte, pcrs []int, pcrVals [][]byte) (bool, error) {
    qi, err := newQuoteInfo(data, pcrs, pcrVals)
    if err != nil {
        return false, err
    }

    p, err := pack([]interface{}{qi})
    if err != nil {
        return false, err
    }

    _ = sha1.Sum(p)

    // Since this is neither PKCS1v1.5 nor OAEP, I need to compute the
    // exponentiation directly.
    // TODO(tmroeder): finish the verification
    return false, errors.New("not implemented: VerifyQuote")
}

// TODO(tmroeder): add VerifyQuote2 instead of VerifyQuote. This means I'll
// probably have to look at the signature scheme and use that to choose how to
// verify the signature, whether PKCS1v1.5 or OAEP. And this will have to be set
// on the key before it's passed to ordQuote2
// TODO(tmroeder): handle key12
