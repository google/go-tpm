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
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"time"
)

const (
	RootKeyHandle     uint32 = 0x810003e8
	QuoteKeyHandle    uint32 = 0x810003e9
	RollbackKeyHandle uint32 = 0
)

// return handle, policy digest
func AssistCreateSession(rw io.ReadWriter, hash_alg uint16,
	pcrs []int) (Handle, []byte, error) {
	nonceCaller := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	var secret []byte
	sym := uint16(AlgTPM_ALG_NULL)

	session_handle, policy_digest, err := StartAuthSession(rw,
		Handle(OrdTPM_RH_NULL),
		Handle(OrdTPM_RH_NULL), nonceCaller, secret,
		uint8(OrdTPM_SE_POLICY), sym, hash_alg)
	if err != nil {
		return Handle(0), nil, errors.New("Can't start session")
	}

	err = PolicyPassword(rw, session_handle)
	if err != nil {
		return Handle(0), nil, errors.New("PolicyPassword fails")
	}
	var tpm_digest []byte
	err = PolicyPcr(rw, session_handle, tpm_digest, pcrs)
	if err != nil {
		return Handle(0), nil, errors.New("PolicyPcr fails")
	}

	policy_digest, err = PolicyGetDigest(rw, session_handle)
	if err != nil {
		return Handle(0), nil, errors.New("PolicyGetDigest fails")
	}
	return session_handle, policy_digest, nil
}

// out: private, public
func AssistSeal(rw io.ReadWriter, parentHandle Handle, toSeal []byte,
	parentPassword string, ownerPassword string, pcrs []int,
	policy_digest []byte) ([]byte, []byte, error) {

	var empty []byte
	keyedhashparms := KeyedHashParams{uint16(AlgTPM_ALG_KEYEDHASH),
		uint16(AlgTPM_ALG_SHA1),
		FlagSealDefault, empty, uint16(AlgTPM_ALG_AES), uint16(128),
		uint16(AlgTPM_ALG_CFB), uint16(AlgTPM_ALG_NULL), empty}
	private_blob, public_blob, err := CreateSealed(rw, parentHandle,
		policy_digest, parentPassword, ownerPassword, toSeal,
		pcrs, keyedhashparms)
	if err != nil {
		return nil, nil, errors.New("CreateSealed fails")
	}
	return private_blob, public_blob, nil
}

// out: unsealed blob, nonce
func AssistUnseal(rw io.ReadWriter, sessionHandle Handle, parentHandle Handle,
	pub []byte, priv []byte, parentPassword string, ownerPassword string,
	policy_digest []byte) ([]byte, []byte, error) {

	// Load Sealed
	sealHandle, _, err := Load(rw, parentHandle, parentPassword,
		ownerPassword, pub, priv)
	if err != nil {
		return nil, nil, errors.New("Load failed")
	}
	defer FlushContext(rw, sealHandle)

	// Unseal
	unsealed, nonce, err := Unseal(rw, sealHandle, ownerPassword,
		sessionHandle, policy_digest)
	if err != nil {
		return nil, nil, errors.New("Unseal failed")
	}
	return unsealed, nonce, err
}

// Call with tpm 2.0 and the quote handle, get the key back for serialization in AttestCertRequest.
func GetRsaKeyFromHandle(rw io.ReadWriter, handle Handle) (*rsa.PublicKey, error) {
	publicBlob, _, _, err := ReadPublic(rw, handle)
	if err != nil {
		return nil, errors.New("Can't get public key blob")
	}
	rsaParams, err := DecodeRsaBuf(publicBlob)
	publicKey := new(rsa.PublicKey)
	// TODO(jlm): read exponent from blob
	publicKey.E = 0x00010001
	M := new(big.Int)
	M.SetBytes(rsaParams.Modulus)
	publicKey.N = M
	return publicKey, nil
}

func GenerateHWCert(rw io.ReadWriter, handle Handle, hardwareName string,
	notBefore time.Time, notAfter time.Time, serialNumber *big.Int,
	derPolicyCert []byte, policyKey *rsa.PrivateKey) ([]byte, error) {
	hwPublic, err := GetRsaKeyFromHandle(rw, handle)
	if err != nil {
		return nil, errors.New("Can't get endorsement public key")
	}
	return GenerateCertFromKeys(policyKey, derPolicyCert, hwPublic,
		hardwareName, hardwareName, serialNumber, notBefore, notAfter)
}

func CreateEndorsement(rw io.ReadWriter, modSize uint16, pcrs []int) (Handle, []byte, error) {
	var empty []byte
	primaryparms := RsaParams{uint16(AlgTPM_ALG_RSA),
		uint16(AlgTPM_ALG_SHA1), FlagStorageDefault,
		empty, uint16(AlgTPM_ALG_AES), uint16(128),
		uint16(AlgTPM_ALG_CFB), uint16(AlgTPM_ALG_NULL),
		uint16(0), modSize, uint32(0x00010001), empty}
	return CreatePrimary(rw, uint32(OrdTPM_RH_ENDORSEMENT), pcrs,
		"", "", primaryparms)
}

func FormatTpm2Quote(stmt []byte, pcrs []int, pcrVals [][]byte) ([]byte, error) {
	sha256Hash := sha256.New()
	sha256Hash.Write(stmt)
	toQuote := sha256Hash.Sum(nil)
	return toQuote, nil
}

func VerifyTpm2Quote(serialized []byte, pcrs []int, expectedPcrVal []byte,
	tpm2Quote []byte, sig []byte, key *rsa.PublicKey) (bool, error) {

	// TODO: fix
	hash_alg_id := uint16(AlgTPM_ALG_SHA1)

	attest, err := UnmarshalCertifyInfo(tpm2Quote)
	if err != nil {
		return false, errors.New("Can't unmarshal quote structure\n")
	}

	// Sha256(serialized) == Data?
	sha256Hash := sha256.New()
	sha256Hash.Write(serialized)
	hashedData := sha256Hash.Sum(nil)
	if bytes.Compare(attest.Data, hashedData) != 0 {
		return false, errors.New("hashed data is not in quote structure")
	}

	// pcr digests match?
	if bytes.Compare(expectedPcrVal, attest.PcrDigest) != 0 {
		return false, errors.New("pcr digest does not match")
	}

	// quote_hash was the thing that was signed
	quote_hash, err := ComputeHashValue(hash_alg_id, tpm2Quote)
	if err != nil {
		return false, errors.New("Can't compute quote\n")
	}

	// decrypt signature
	var E *big.Int
	E = new(big.Int)
	E.SetBytes([]byte{0, 1, 0, 1})
	x := new(big.Int)
	x.SetBytes(sig)
	z := new(big.Int)
	z = z.Exp(x, E, key.N)
	decrypted_quote := z.Bytes()
	start_quote_blob := len(decrypted_quote) - SizeHash(hash_alg_id)

	// quote_hash == decrypted sig?
	if bytes.Compare(decrypted_quote[start_quote_blob:], quote_hash) != 0 {
		return false, nil
	}
	return true, nil
}

// Loads keys from blobs.
func LoadKeyFromBlobs(rw io.ReadWriter, ownerHandle Handle, ownerPw string, objectPw string,
	publicBlob []byte, privateBlob []byte) (Handle, error) {
	newHandle, _, err := Load(rw, ownerHandle, ownerPw, objectPw, publicBlob, privateBlob)
	if err != nil {
		return Handle(0), errors.New("Load failed")
	}
	return newHandle, nil
}

func CreateTpm2HierarchyRoot(rw io.ReadWriter, pcrs []int, keySize uint16, hash_alg_id uint16) (Handle, error) {
	// CreatePrimary
	var empty []byte
	primaryparms := RsaParams{uint16(AlgTPM_ALG_RSA), hash_alg_id, FlagStorageDefault,
		empty, uint16(AlgTPM_ALG_AES), uint16(128), uint16(AlgTPM_ALG_CFB), uint16(AlgTPM_ALG_NULL),
		uint16(0), keySize, uint32(0x00010001), empty}
	rootHandle, _, err := CreatePrimary(rw, uint32(OrdTPM_RH_OWNER), pcrs, "", "", primaryparms)
	return rootHandle, err
}

// Create quote and seal keys under rootHandle and return in order:
//	quote public blob, quote private blob, seal public blob, seal private blob
func CreateTpm2HierarchySubKeys(rw io.ReadWriter, pcrs []int, keySize uint16, hash_alg_id uint16,
	rootHandle Handle, quotePassword string) ([]byte, []byte, []byte, []byte, error) {

	var empty []byte
	// CreateKey (Quote Key)
	keyparms := RsaParams{uint16(AlgTPM_ALG_RSA), hash_alg_id,
		FlagSignerDefault, empty, uint16(AlgTPM_ALG_NULL), uint16(0),
		uint16(AlgTPM_ALG_ECB), uint16(AlgTPM_ALG_RSASSA),
		uint16(AlgTPM_ALG_SHA1), keySize, uint32(0x00010001), empty}
	quote_private, quote_public, err := CreateKey(rw, uint32(rootHandle), pcrs, "", quotePassword, keyparms)
	if err != nil {
		return nil, nil, nil, nil, errors.New("Can't create quote key")
	}

	// CreateKey (storage key)
	storeparms := RsaParams{uint16(AlgTPM_ALG_RSA), hash_alg_id, FlagStorageDefault,
		empty, uint16(AlgTPM_ALG_AES), uint16(128), uint16(AlgTPM_ALG_CFB),
		uint16(AlgTPM_ALG_NULL), uint16(0), keySize, uint32(0x00010001), empty}
	store_private, store_public, err := CreateKey(rw, uint32(rootHandle), pcrs, "", quotePassword, storeparms)
	if err != nil {
		return nil, nil, nil, nil, errors.New("Can't create store key")
	}
	return quote_public, quote_private, store_public, store_private, nil
}

// This program creates a key hierarchy consisting of a
// primary key and quoting key for cloudproxy.
func CreateTpm2KeyHierarchy(rw io.ReadWriter, pcrs []int, keySize uint16, hash_alg_id uint16,
	quotePassword string) (Handle, Handle, Handle, error) {

	// Create Root.
	rootHandle, err := CreateTpm2HierarchyRoot(rw, pcrs, keySize, uint16(AlgTPM_ALG_SHA1))
	if err != nil {
		return Handle(0), Handle(0), Handle(0), errors.New("CreatePrimary failed")
	}

	// Create sub keys.
	quote_public, quote_private, seal_public, seal_private, err := CreateTpm2HierarchySubKeys(rw, pcrs, keySize,
		uint16(AlgTPM_ALG_SHA1), rootHandle, quotePassword)
	if err != nil {
		return Handle(0), Handle(0), Handle(0), errors.New("Can't create quote key")
	}

	// Load
	quoteHandle, err := LoadKeyFromBlobs(rw, rootHandle, "", "", quote_public, quote_private)
	if err != nil {
		return Handle(0), Handle(0), Handle(0), errors.New("Quote load failed")
	}

	// Load
	sealHandle, err := LoadKeyFromBlobs(rw, rootHandle, "", "", seal_public, seal_private)
	if err != nil {
		return Handle(0), Handle(0), Handle(0), errors.New("Load failed")
	}

	return rootHandle, quoteHandle, sealHandle, nil
}

// Makes their handles permanent.
func PersistTpm2KeyHierarchy(rw io.ReadWriter, pcrs []int, keySize int,
	hash_alg_id uint16, rootHandle uint32, quoteHandle uint32, quotePassword string) error {

	// Remove old permanent handles
	err := EvictControl(rw, Handle(OrdTPM_RH_OWNER), Handle(rootHandle),
		Handle(rootHandle))
	if err != nil {
		fmt.Printf("Evict existing permanant primary handle failed (OK)\n")
	}
	err = EvictControl(rw, Handle(OrdTPM_RH_OWNER), Handle(quoteHandle),
		Handle(quoteHandle))
	if err != nil {
		fmt.Printf("Evict existing permanant quote handle failed (OK)\n")
	}

	/*
		err = EvictControl(rw, Handle(OrdTPM_RH_OWNER), tmpQuoteHandle,
				Handle(quoteHandle))
		if err != nil {
			FlushContext(rw, tmpQuoteHandle)
			return errors.New("Install new quote handle failed")
		}
	*/
	return nil
}

// This isnt used any more.
func InitTpm2KeysandContexts(rw io.ReadWriter, pcrs []int, keySize uint16, hash_alg_id uint16,
	quotePassword string, rootFileName string, quoteFileName string,
	storeFileName string) error {

	rootHandle, quoteHandle, storeHandle, err := CreateTpm2KeyHierarchy(rw, pcrs,
		keySize, hash_alg_id, quotePassword)
	if err != nil {
		return errors.New("InitTpm2Keys failed")
	}

	rootSaveArea, err := SaveContext(rw, rootHandle)
	if err != nil {
		return errors.New("Save root Context fails")
	}
	defer FlushContext(rw, rootHandle)

	quoteSaveArea, err := SaveContext(rw, quoteHandle)
	if err != nil {
		return errors.New("Save quote Context fails")
	}
	defer FlushContext(rw, quoteHandle)

	storeSaveArea, err := SaveContext(rw, storeHandle)
	if err != nil {
		return errors.New("Save store Context fails")
	}
	defer FlushContext(rw, storeHandle)

	ioutil.WriteFile(rootFileName, rootSaveArea, 0644)
	ioutil.WriteFile(quoteFileName, quoteSaveArea, 0644)
	ioutil.WriteFile(storeFileName, storeSaveArea, 0644)
	return nil
}

func RestoreTpm2KeysFromContext(rw io.ReadWriter, quotePassword string,
	rootFileName string, quoteFileName string,
	storeFileName string) (Handle, Handle, Handle, error) {

	rootSaveArea, err := ioutil.ReadFile(rootFileName)
	if err != nil {
		return Handle(0), Handle(0), Handle(0), errors.New("Can't read root store file")
	}
	quoteSaveArea, err := ioutil.ReadFile(quoteFileName)
	if err != nil {
		return Handle(0), Handle(0), Handle(0), errors.New("Can't read quote store file")
	}
	storeSaveArea, err := ioutil.ReadFile(storeFileName)
	if err != nil {
		return Handle(0), Handle(0), Handle(0), errors.New("Can't read store store file")
	}
	rootHandle, err := LoadContext(rw, rootSaveArea)
	if err != nil {
		return Handle(0), Handle(0), Handle(0), errors.New("Can't load root handle")
	}
	quoteHandle, err := LoadContext(rw, quoteSaveArea)
	if err != nil {
		FlushContext(rw, rootHandle)
		return Handle(0), Handle(0), Handle(0), errors.New("Can't load quote handle")
	}
	storeHandle, err := LoadContext(rw, storeSaveArea)
	if err != nil {
		FlushContext(rw, rootHandle)
		FlushContext(rw, quoteHandle)
		return Handle(0), Handle(0), Handle(0), errors.New("Can't load store handle")
	}
	return rootHandle, quoteHandle, storeHandle, nil
}
