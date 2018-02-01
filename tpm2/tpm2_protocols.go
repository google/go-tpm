// Copyright (c) 2014, Google, Inc. All rights reserved.
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
//

package tpm2

import (
	"crypto/rsa"
	"fmt"
	"io"
	"math/big"
)

const (
	RootKeyHandle     uint32 = 0x810003e8
	QuoteKeyHandle    uint32 = 0x810003e9
	RollbackKeyHandle uint32 = 0
)

// return handle, policy digest
func AssistCreateSession(rw io.ReadWriter, hashAlg uint16, pcrs []int) (Handle, []byte, error) {
	nonceCaller := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	var secret []byte
	sym := uint16(AlgTPM_ALG_NULL)

	sessionHandle, policyDigest, err := StartAuthSession(rw, Handle(OrdTPM_RH_NULL), Handle(OrdTPM_RH_NULL), nonceCaller, secret, uint8(OrdTPM_SE_POLICY), sym, hashAlg)
	if err != nil {
		return 0, nil, fmt.Errorf("StartAuthSession: %v", err)
	}

	err = PolicyPassword(rw, sessionHandle)
	if err != nil {
		return 0, nil, fmt.Errorf("PolicyPassword: %v", err)
	}
	var tpmDigest []byte
	err = PolicyPcr(rw, sessionHandle, tpmDigest, pcrs)
	if err != nil {
		return 0, nil, fmt.Errorf("PolicyPcr: %v", err)
	}

	policyDigest, err = PolicyGetDigest(rw, sessionHandle)
	if err != nil {
		return 0, nil, fmt.Errorf("PolicyGetDigest: %v", err)
	}
	return sessionHandle, policyDigest, nil
}

// Call with tpm 2.0 and the quote handle, get the key back for serialization in AttestCertRequest.
func GetRsaKeyFromHandle(rw io.ReadWriter, handle Handle) (*rsa.PublicKey, error) {
	publicBlob, _, _, err := ReadPublic(rw, handle)
	if err != nil {
		return nil, fmt.Errorf("ReadPublic: %v", err)
	}
	rsaParams, err := decodeRSABuf(publicBlob)
	publicKey := new(rsa.PublicKey)
	// TODO(jlm): read exponent from blob
	publicKey.E = 0x00010001
	M := new(big.Int)
	M.SetBytes(rsaParams.Modulus)
	publicKey.N = M
	return publicKey, nil
}

func CreateEndorsement(rw io.ReadWriter, modSize uint16, pcrs []int) (Handle, []byte, error) {
	var empty []byte
	primaryparms := RSAParams{
		uint16(AlgTPM_ALG_RSA),
		uint16(AlgTPM_ALG_SHA1),
		FlagStorageDefault,
		empty,
		uint16(AlgTPM_ALG_AES),
		uint16(128),
		uint16(AlgTPM_ALG_CFB),
		uint16(AlgTPM_ALG_NULL),
		uint16(0),
		modSize,
		uint32(0x00010001),
		empty,
	}
	return CreatePrimary(rw, uint32(OrdTPM_RH_ENDORSEMENT), pcrs, "", "", primaryparms)
}

// Loads keys from blobs.
func LoadKeyFromBlobs(rw io.ReadWriter, ownerHandle Handle, ownerPw, objectPw string, publicBlob, privateBlob []byte) (Handle, error) {
	newHandle, _, err := Load(rw, ownerHandle, ownerPw, objectPw, publicBlob, privateBlob)
	if err != nil {
		return 0, fmt.Errorf("Load: %v", err)
	}
	return newHandle, nil
}

func CreateHierarchyRoot(rw io.ReadWriter, pcrs []int, keySize uint16, hashAlg uint16) (Handle, error) {
	var empty []byte
	primaryparms := RSAParams{
		uint16(AlgTPM_ALG_RSA),
		hashAlg,
		FlagStorageDefault,
		empty,
		uint16(AlgTPM_ALG_AES),
		uint16(128),
		uint16(AlgTPM_ALG_CFB),
		uint16(AlgTPM_ALG_NULL),
		uint16(0),
		keySize,
		uint32(0x00010001),
		empty,
	}
	rootHandle, _, err := CreatePrimary(rw, uint32(OrdTPM_RH_OWNER), pcrs, "", "", primaryparms)
	return rootHandle, err
}

// Create quote and seal keys under rootHandle and return in order:
// quote public blob, quote private blob, seal public blob, seal private blob
func CreateHierarchySubKeys(rw io.ReadWriter, pcrs []int, keySize, hashAlg uint16, rootHandle Handle, quotePassword string) ([]byte, []byte, []byte, []byte, error) {

	var empty []byte
	// CreateKey (Quote Key)
	keyparms := RSAParams{
		uint16(AlgTPM_ALG_RSA),
		hashAlg,
		FlagSignerDefault,
		empty,
		uint16(AlgTPM_ALG_NULL),
		uint16(0),
		uint16(AlgTPM_ALG_ECB),
		uint16(AlgTPM_ALG_RSASSA),
		uint16(AlgTPM_ALG_SHA1),
		keySize,
		uint32(0x00010001),
		empty,
	}
	quotePrivate, quotePublic, err := CreateKey(rw, uint32(rootHandle), pcrs, "", quotePassword, keyparms)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("CreateKey: %v", err)
	}

	// CreateKey (storage key)
	storeparms := RSAParams{
		uint16(AlgTPM_ALG_RSA),
		hashAlg,
		FlagStorageDefault,
		empty,
		uint16(AlgTPM_ALG_AES),
		uint16(128),
		uint16(AlgTPM_ALG_CFB),
		uint16(AlgTPM_ALG_NULL),
		uint16(0),
		keySize,
		uint32(0x00010001),
		empty,
	}
	storePrivate, storePublic, err := CreateKey(rw, uint32(rootHandle), pcrs, "", quotePassword, storeparms)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("CreateKey: %v", err)
	}
	return quotePublic, quotePrivate, storePublic, storePrivate, nil
}

// This program creates a key hierarchy consisting of a
// primary key and quoting key for cloudproxy.
func CreateKeyHierarchy(rw io.ReadWriter, pcrs []int, keySize, hashAlg uint16, quotePassword string) (Handle, Handle, Handle, error) {

	// Create Root.
	rootHandle, err := CreateHierarchyRoot(rw, pcrs, keySize, uint16(AlgTPM_ALG_SHA1))
	if err != nil {
		return 0, 0, 0, fmt.Errorf("CreatePrimary: %v", err)
	}

	// Create sub keys.
	quotePublic, quotePrivate, sealPublic, sealPrivate, err := CreateHierarchySubKeys(rw, pcrs, keySize, uint16(AlgTPM_ALG_SHA1), rootHandle, quotePassword)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("CreateHierarchySubKeys: %v", err)
	}

	// Load
	quoteHandle, err := LoadKeyFromBlobs(rw, rootHandle, "", "", quotePublic, quotePrivate)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("LoadKeyFromBlobs: %v", err)
	}

	// Load
	sealHandle, err := LoadKeyFromBlobs(rw, rootHandle, "", "", sealPublic, sealPrivate)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("Load: %v", err)
	}

	return rootHandle, quoteHandle, sealHandle, nil
}

// Makes their handles permanent.
func PersistKeyHierarchy(rw io.ReadWriter, pcrs []int, keySize int, hashAlg uint16, rootHandle, quoteHandle uint32, quotePassword string) error {
	// Remove old permanent handles
	err := EvictControl(rw, Handle(OrdTPM_RH_OWNER), Handle(rootHandle), Handle(rootHandle))
	if err != nil {
		return fmt.Errorf("Evict existing permanant primary handle failed: %v", err)
	}
	err = EvictControl(rw, Handle(OrdTPM_RH_OWNER), Handle(quoteHandle), Handle(quoteHandle))
	if err != nil {
		return fmt.Errorf("Evict existing permanant quote handle failed: %v", err)
	}

	return nil
}
