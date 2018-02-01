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

package tpm2

import (
	"bytes"
	"crypto/rsa"
	"fmt"
	"math/big"
	"testing"
)

// Test Endian
func TestEndian(t *testing.T) {
	l := uint16(0xff12)
	v := byte(l >> 8)
	var s [2]byte
	s[0] = v
	v = byte(l & 0xff)
	s[1] = v
	if s[0] != 0xff || s[1] != 0x12 {
		t.Fatal("Endian test mismatch")
	}
}

// Test GetRandom
func TestGetRandom(t *testing.T) {
	fmt.Printf("TestGetRandom\n")

	// Open TPM
	rw, err := OpenTPM("/dev/tpm0")
	if err != nil {
		fmt.Printf("OpenTPM failed %s\n", err)
		return
	}
	defer rw.Close()
	Flushall(rw)

	rand, err := GetRandom(rw, 16)
	if err != nil {
		fmt.Printf("GetRandon Error ", err, "\n")
		t.Fatal("GetRandom failed\n")
	}
	fmt.Printf("rand: %x\n", rand[0:len(rand)])
}

// TestReadPcr tests a ReadPcr command.
func TestReadPcrs(t *testing.T) {
	fmt.Printf("TestReadPcrs\n")

	// Open TPM
	rw, err := OpenTPM("/dev/tpm0")
	if err != nil {
		fmt.Printf("OpenTPM failed %s\n", err)
		return
	}
	defer rw.Close()
	Flushall(rw)

	pcr := []byte{0x03, 0x80, 0x00, 0x00}
	counter, pcr_out, alg, digest, err := ReadPcrs(rw, byte(4), pcr)
	if err != nil {
		t.Fatal("ReadPcrs failed\n")
	}
	fmt.Printf("Counter: %x, pcr: %x, alg: %x, digest: %x\n", counter,
		pcr_out, alg, digest)
	rw.Close()
}

// TestReadClock tests a ReadClock command.
func TestReadClock(t *testing.T) {
	fmt.Printf("TestReadClock\n")

	// Open TPM
	rw, err := OpenTPM("/dev/tpm0")
	if err != nil {
		fmt.Printf("OpenTPM failed %s\n", err)
		return
	}
	Flushall(rw)

	current_time, current_clock, err := ReadClock(rw)
	if err != nil {
		t.Fatal("ReadClock failed\n")
	}
	fmt.Printf("current_time: %x , current_clock: %x\n",
		current_time, current_clock)
	rw.Close()

}

// TestGetCapabilities tests a GetCapabilities command.
// Command: 8001000000160000017a000000018000000000000014
func TestGetCapabilities(t *testing.T) {

	// Open TPM
	rw, err := OpenTPM("/dev/tpm0")
	if err != nil {
		fmt.Printf("OpenTPM failed %s\n", err)
		return
	}
	Flushall(rw)

	handles, err := GetCapabilities(rw, OrdTPM_CAP_HANDLES,
		1, 0x80000000)
	if err != nil {
		t.Fatal("GetCapabilities failed\n")
	}
	fmt.Printf("Open handles:\n")
	for _, e := range handles {
		fmt.Printf("    %x\n", e)
	}
	rw.Close()
}

// Combined Key Test
func TestCombinedKeyTest(t *testing.T) {

	// Open tpm
	rw, err := OpenTPM("/dev/tpm0")
	if err != nil {
		fmt.Printf("OpenTPM failed %s\n", err)
		return
	}

	// Flushall
	err = Flushall(rw)
	if err != nil {
		t.Fatal("Flushall failed\n")
	}

	// CreatePrimary
	var empty []byte
	primaryparms := RsaParams{uint16(AlgTPM_ALG_RSA),
		uint16(AlgTPM_ALG_SHA1), uint32(0x00030072),
		empty, uint16(AlgTPM_ALG_AES), uint16(128),
		uint16(AlgTPM_ALG_CFB), uint16(AlgTPM_ALG_NULL),
		uint16(0), uint16(1024), uint32(0x00010001), empty}
	parent_handle, public_blob, err := CreatePrimary(rw,
		uint32(OrdTPM_RH_OWNER), []int{0x7}, "",
		"01020304", primaryparms)
	if err != nil {
		t.Fatal("CreatePrimary fails")
	}
	fmt.Printf("CreatePrimary succeeded\n")

	// CreateKey
	keyparms := RsaParams{uint16(AlgTPM_ALG_RSA),
		uint16(AlgTPM_ALG_SHA1), uint32(0x00030072), empty,
		uint16(AlgTPM_ALG_AES), uint16(128),
		uint16(AlgTPM_ALG_CFB), uint16(AlgTPM_ALG_NULL),
		uint16(0), uint16(1024), uint32(0x00010001), empty}
	private_blob, public_blob, err := CreateKey(rw,
		uint32(parent_handle), []int{7}, "01020304", "01020304",
		keyparms)
	if err != nil {
		t.Fatal("CreateKey fails")
	}
	fmt.Printf("CreateKey succeeded, handle: %x\n", uint32(parent_handle))

	// Load
	key_handle, _, err := Load(rw, parent_handle, "", "01020304",
		public_blob, private_blob)
	if err != nil {
		t.Fatal("Load fails")
	}
	fmt.Printf("Load succeeded, handle: %x\n", uint32(key_handle))

	// ReadPublic
	_, name, _, err := ReadPublic(rw, key_handle)
	if err != nil {
		t.Fatal("ReadPublic fails")
	}
	fmt.Printf("ReadPublic succeeded, name: %x\n", name)

	// Flush
	err = FlushContext(rw, key_handle)
	err = FlushContext(rw, parent_handle)
	rw.Close()
}

// Combined Seal test
func TestCombinedSealTest(t *testing.T) {

	// Open tpm
	rw, err := OpenTPM("/dev/tpm0")
	if err != nil {
		fmt.Printf("OpenTPM failed %s\n", err)
		return
	}

	// Flushall
	err = Flushall(rw)
	if err != nil {
		t.Fatal("Flushall failed\n")
	}

	// CreatePrimary
	var empty []byte
	primaryparms := RsaParams{uint16(AlgTPM_ALG_RSA),
		uint16(AlgTPM_ALG_SHA1), uint32(0x00030072), empty,
		uint16(AlgTPM_ALG_AES), uint16(128),
		uint16(AlgTPM_ALG_CFB), uint16(AlgTPM_ALG_NULL),
		uint16(0), uint16(1024), uint32(0x00010001), empty}
	parent_handle, public_blob, err := CreatePrimary(rw,
		uint32(OrdTPM_RH_OWNER), []int{0x7}, "",
		"01020304", primaryparms)
	if err != nil {
		t.Fatal("CreatePrimary fails")
	}
	fmt.Printf("CreatePrimary succeeded\n")

	nonceCaller := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	var secret []byte
	sym := uint16(AlgTPM_ALG_NULL)
	to_seal := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
	hash_alg := uint16(AlgTPM_ALG_SHA1)

	session_handle, policy_digest, err := StartAuthSession(rw,
		Handle(OrdTPM_RH_NULL),
		Handle(OrdTPM_RH_NULL), nonceCaller, secret,
		uint8(OrdTPM_SE_POLICY), sym, hash_alg)
	if err != nil {
		FlushContext(rw, parent_handle)
		t.Fatal("StartAuthSession fails")
	}
	fmt.Printf("policy digest  : %x\n", policy_digest)

	err = PolicyPassword(rw, session_handle)
	if err != nil {
		FlushContext(rw, parent_handle)
		FlushContext(rw, session_handle)
		t.Fatal("PolicyPcr fails")
	}
	var tpm_digest []byte
	err = PolicyPcr(rw, session_handle, tpm_digest, []int{7})
	if err != nil {
		FlushContext(rw, parent_handle)
		FlushContext(rw, session_handle)
		t.Fatal("PolicyPcr fails")
	}

	policy_digest, err = PolicyGetDigest(rw, session_handle)
	if err != nil {
		FlushContext(rw, parent_handle)
		FlushContext(rw, session_handle)
		t.Fatal("PolicyGetDigest after PolicyPcr fails")
	}
	fmt.Printf("policy digest after PolicyPcr: %x\n", policy_digest)

	// CreateSealed
	keyedhashparms := KeyedHashParams{uint16(AlgTPM_ALG_KEYEDHASH),
		uint16(AlgTPM_ALG_SHA1), uint32(0x00000012), empty,
		uint16(AlgTPM_ALG_AES), uint16(128),
		uint16(AlgTPM_ALG_CFB), uint16(AlgTPM_ALG_NULL),
		empty}
	private_blob, public_blob, err := CreateSealed(rw, parent_handle,
		policy_digest, "01020304", "01020304", to_seal, []int{7},
		keyedhashparms)
	if err != nil {
		FlushContext(rw, parent_handle)
		FlushContext(rw, session_handle)
		t.Fatal("CreateSealed fails")
	}

	// Load
	item_handle, _, err := Load(rw, parent_handle, "", "01020304",
		public_blob, private_blob)
	if err != nil {
		FlushContext(rw, session_handle)
		FlushContext(rw, item_handle)
		FlushContext(rw, parent_handle)
		t.Fatal("Load fails")
	}
	fmt.Printf("Load succeeded\n")

	// Unseal
	unsealed, nonce, err := Unseal(rw, item_handle, "01020304",
		session_handle, policy_digest)
	if err != nil {
		FlushContext(rw, item_handle)
		FlushContext(rw, parent_handle)
		t.Fatal("Unseal fails")
	}
	fmt.Printf("Unseal succeeds\n")
	fmt.Printf("unsealed           : %x\n", unsealed)
	fmt.Printf("nonce              : %x\n\n", nonce)

	// Flush
	FlushContext(rw, item_handle)
	FlushContext(rw, parent_handle)
	FlushContext(rw, session_handle)
	rw.Close()
	if bytes.Compare(to_seal, unsealed) != 0 {
		t.Fatal("seal and unsealed bytes dont match")
	}
}

func checkQ(b1 []byte, b2 []byte) bool {
	return true;
}

// Combined Quote test
func TestCombinedQuoteTest(t *testing.T) {

	// Open tpm
	rw, err := OpenTPM("/dev/tpm0")
	if err != nil {
		fmt.Printf("OpenTPM failed %s\n", err)
		return
	}

	// Flushall
	err = Flushall(rw)
	if err != nil {
		t.Fatal("Flushall failed\n")
	}

	// CreatePrimary
	var empty []byte
	primaryparms := RsaParams{uint16(AlgTPM_ALG_RSA),
		uint16(AlgTPM_ALG_SHA1), uint32(0x00030072),
		empty, uint16(AlgTPM_ALG_AES), uint16(128),
		uint16(AlgTPM_ALG_CFB), uint16(AlgTPM_ALG_NULL),
		uint16(0), uint16(1024), uint32(0x00010001), empty}
	parent_handle, public_blob, err := CreatePrimary(rw,
		uint32(OrdTPM_RH_OWNER), []int{0x7}, "",
		"01020304", primaryparms)
	if err != nil {
		t.Fatal("CreatePrimary fails")
	}
	fmt.Printf("CreatePrimary succeeded\n")

	// Pcr event
	eventData := []byte{1, 2, 3}
	err = PcrEvent(rw, 7, eventData)
	if err != nil {
		t.Fatal("PcrEvent fails")
	}

	// CreateKey (Quote Key)
	keyparms := RsaParams{uint16(AlgTPM_ALG_RSA),
		uint16(AlgTPM_ALG_SHA1), uint32(0x00050072), empty,
		uint16(AlgTPM_ALG_NULL), uint16(0),
		uint16(AlgTPM_ALG_ECB), uint16(AlgTPM_ALG_RSASSA),
		uint16(AlgTPM_ALG_SHA1),
		uint16(1024), uint32(0x00010001), empty}

	private_blob, public_blob, err := CreateKey(rw,
		uint32(parent_handle), []int{7}, "01020304", "01020304",
		keyparms)
	if err != nil {
		t.Fatal("CreateKey fails")
	}
	fmt.Printf("CreateKey succeeded\n")

	// Load
	quote_handle, _, err := Load(rw, parent_handle, "", "01020304",
		public_blob, private_blob)
	if err != nil {
		t.Fatal("Load fails")
	}
	fmt.Printf("Load succeeded, handle: %x\n", uint32(quote_handle))

	// Quote
	to_quote := []byte{0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08,
		0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00}
	attest, sig, err := Quote(rw, quote_handle, "01020304", "01020304",
		to_quote, []int{7}, uint16(AlgTPM_ALG_NULL))
	if err != nil {
		FlushContext(rw, quote_handle)
		rw.Close()
		t.Fatal("Quote fails")
	}
	fmt.Printf("attest             : %x\n", attest)
	fmt.Printf("sig                : %x\n\n", sig)

	// get info for verify
	_, name, qualified_name, err := ReadPublic(rw, quote_handle)
	if err != nil {
		FlushContext(rw, quote_handle)
		err = FlushContext(rw, parent_handle)
		rw.Close()
		t.Fatal("Quote fails")
	}

	// Flush
	err = FlushContext(rw, quote_handle)
	err = FlushContext(rw, parent_handle)
	rw.Close()

	// Verify quote
	fmt.Printf("name(%x): %x\n", len(name), name)
	fmt.Printf("qualified_name(%x): %x\n", len(qualified_name), qualified_name)
	rsaParams, err := DecodeRsaBuf(public_blob)
	if err != nil {
		t.Fatal("DecodeRsaBuf fails %s", err)
	}

	var quote_key_info QuoteKeyInfoMessage
	att := int32(rsaParams.Attributes)
	quote_key_info.Name = name
	quote_key_info.Properties = &att
	quote_key_info.PublicKey = new(PublicKeyMessage)
	key_type := "rsa"
	quote_key_info.PublicKey.KeyType = &key_type
	quote_key_info.PublicKey.RsaKey = new(RsaPublicKeyMessage)
	key_name := "QuoteKey"
	quote_key_info.PublicKey.RsaKey.KeyName = &key_name
	sz_mod := int32(rsaParams.Mod_sz)
	quote_key_info.PublicKey.RsaKey.BitModulusSize = &sz_mod
	quote_key_info.PublicKey.RsaKey.Exponent = []byte{0, 1, 0, 1}
	quote_key_info.PublicKey.RsaKey.Modulus = rsaParams.Modulus
	if !VerifyQuote(to_quote, quote_key_info,
		uint16(AlgTPM_ALG_SHA1), attest, sig, checkQ) {
		t.Fatal("VerifyQuote fails")
	}
	fmt.Printf("VerifyQuote succeeds\n")
}

// Combined Endorsement/Activate test
func TestCombinedEndorsementTest(t *testing.T) {
	hash_alg_id := uint16(AlgTPM_ALG_SHA1)

	// Open tpm
	rw, err := OpenTPM("/dev/tpm0")
	if err != nil {
		fmt.Printf("OpenTPM failed %s\n", err)
		return
	}
	defer rw.Close()

	// Flushall
	err = Flushall(rw)
	if err != nil {
		t.Fatal("Flushall failed\n")
	}

	// CreatePrimary
	var empty []byte
	primaryparms := RsaParams{uint16(AlgTPM_ALG_RSA),
		uint16(AlgTPM_ALG_SHA1), uint32(0x00030072), empty,
		uint16(AlgTPM_ALG_AES), uint16(128),
		uint16(AlgTPM_ALG_CFB), uint16(AlgTPM_ALG_NULL),
		uint16(0), uint16(2048), uint32(0x00010001), empty}
	parent_handle, public_blob, err := CreatePrimary(rw,
		// uint32(OrdTPM_RH_ENDORSEMENT), []int{0x7}, "", "", primaryparms)
		uint32(OrdTPM_RH_OWNER), []int{0x7}, "", "", primaryparms)
	if err != nil {
		t.Fatal("CreatePrimary fails")
	}
	fmt.Printf("CreatePrimary succeeded\n")
	endorseParams, err := DecodeRsaArea(public_blob)
	if err != nil {
		t.Fatal("DecodeRsaBuf fails", err)
	}

	// CreateKey
	keyparms := RsaParams{uint16(AlgTPM_ALG_RSA),
		uint16(AlgTPM_ALG_SHA1), uint32(0x00030072), empty,
		uint16(AlgTPM_ALG_AES), uint16(128),
		uint16(AlgTPM_ALG_CFB), uint16(AlgTPM_ALG_NULL),
		uint16(0), uint16(2048), uint32(0x00010001), empty}
	private_blob, public_blob, err := CreateKey(rw,
		uint32(parent_handle),
		[]int{7}, "", "01020304", keyparms)
	if err != nil {
		t.Fatal("CreateKey fails")
	}
	fmt.Printf("CreateKey succeeded\n")

	// Load
	key_handle, _, err := Load(rw, parent_handle, "", "",
		public_blob, private_blob)
	if err != nil {
		t.Fatal("Load fails")
	}
	fmt.Printf("Load succeeded\n")

	// ReadPublic
	_, name, _, err := ReadPublic(rw, key_handle)
	if err != nil {
		t.Fatal("ReadPublic fails")
	}
	fmt.Printf("ReadPublic succeeded\n")

	// Generate Credential
	credential := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x10}
	fmt.Printf("Credential: %x\n", credential)

	// Internal MakeCredential
	credBlob, encrypted_secret0, err := InternalMakeCredential(rw,
		parent_handle, credential, name)
	if err != nil {
		FlushContext(rw, key_handle)
		FlushContext(rw, parent_handle)
		t.Fatal("Can't InternalMakeCredential\n")
	}

	// ActivateCredential
	recovered_credential1, err := ActivateCredential(rw,
		key_handle, parent_handle,
		"01020304", "", credBlob, encrypted_secret0)
	if err != nil {
		FlushContext(rw, key_handle)
		FlushContext(rw, parent_handle)
		t.Fatal("Can't ActivateCredential\n")
	}
	if bytes.Compare(credential, recovered_credential1) != 0 {
		FlushContext(rw, key_handle)
		FlushContext(rw, parent_handle)
		t.Fatal("Credential and recovered credential differ\n")
	}
	fmt.Printf("InternalMake/Activate test succeeds\n\n")

	protectorPublic := new(rsa.PublicKey)
	protectorPublic.E = 0x00010001
	M := new(big.Int)
	M.SetBytes(endorseParams.Modulus)
	protectorPublic.N = M

	// MakeCredential
	encrypted_secret, encIdentity, integrityHmac, err := MakeCredential(
		protectorPublic, hash_alg_id, credential, name)
	if err != nil {
		FlushContext(rw, key_handle)
		FlushContext(rw, parent_handle)
		t.Fatal("Can't MakeCredential\n")
	}

	// ActivateCredential
	recovered_credential2, err := ActivateCredential(rw,
		key_handle, parent_handle, "01020304", "",
		append(integrityHmac, encIdentity...), encrypted_secret)
	if err != nil {
		FlushContext(rw, key_handle)
		FlushContext(rw, parent_handle)
		t.Fatal("Can't ActivateCredential\n")
	}
	if bytes.Compare(credential, recovered_credential2) != 0 {
		FlushContext(rw, key_handle)
		FlushContext(rw, parent_handle)
		t.Fatal("Credential and recovered credential differ\n")
	}
	fmt.Printf("Make/Activate test succeeds\n")

	// Flush
	FlushContext(rw, key_handle)
}

// Combined Evict test
func TestCombinedEvictTest(t *testing.T) {
	fmt.Printf("TestCombinedEvictTest excluded\n")
	return

	// Open tpm
	rw, err := OpenTPM("/dev/tpm0")
	if err != nil {
		fmt.Printf("OpenTPM failed %s\n", err)
		return
	}

	// Flushall
	err = Flushall(rw)
	if err != nil {
		t.Fatal("Flushall failed\n")
	}

	// CreatePrimary
	var empty []byte
	primaryparms := RsaParams{uint16(AlgTPM_ALG_RSA),
		uint16(AlgTPM_ALG_SHA1), uint32(0x00030072), empty,
		uint16(AlgTPM_ALG_AES), uint16(128),
		uint16(AlgTPM_ALG_CFB), uint16(AlgTPM_ALG_NULL),
		uint16(0), uint16(1024), uint32(0x00010001), empty}
	parent_handle, public_blob, err := CreatePrimary(rw,
		uint32(OrdTPM_RH_OWNER), []int{0x7}, "",
		"01020304", primaryparms)
	if err != nil {
		t.Fatal("CreatePrimary fails")
	}
	fmt.Printf("CreatePrimary succeeded\n")

	// CreateKey
	keyparms := RsaParams{uint16(AlgTPM_ALG_RSA),
		uint16(AlgTPM_ALG_SHA1), uint32(0x00030072), empty,
		uint16(AlgTPM_ALG_AES), uint16(128),
		uint16(AlgTPM_ALG_CFB), uint16(AlgTPM_ALG_NULL),
		uint16(0), uint16(1024), uint32(0x00010001), empty}
	private_blob, public_blob, err := CreateKey(rw,
		uint32(parent_handle),
		[]int{7}, "01020304", "01020304", keyparms)
	if err != nil {
		t.Fatal("CreateKey fails")
	}
	fmt.Printf("CreateKey succeeded\n")

	// Load
	key_handle, _, err := Load(rw, parent_handle, "", "01020304",
		public_blob, private_blob)
	if err != nil {
		t.Fatal("Load fails")
	}
	fmt.Printf("Load succeeded\n")

	perm_handle := uint32(0x810003e8)

	// Evict
	err = EvictControl(rw, Handle(OrdTPM_RH_OWNER),
		key_handle, Handle(perm_handle))
	if err != nil {
		t.Fatal("EvictControl 1 fails")
	}

	// Evict
	err = EvictControl(rw, Handle(OrdTPM_RH_OWNER),
		Handle(perm_handle), Handle(perm_handle))
	if err != nil {
		t.Fatal("EvictControl 2 fails")
	}

	// Flush
	err = FlushContext(rw, key_handle)
	err = FlushContext(rw, parent_handle)
	rw.Close()
}

// Combined Context test
func TestCombinedContextTest(t *testing.T) {

	// Open tpm
	rw, err := OpenTPM("/dev/tpm0")
	if err != nil {
		fmt.Printf("OpenTPM failed %s\n", err)
		return
	}
	defer rw.Close()

	// Flushall
	err = Flushall(rw)
	if err != nil {
		t.Fatal("Flushall failed\n")
	}

	pcrs := []int{7}
	keySize := uint16(2048)
	quotePassword := ""

	// CreatePrimary
	var empty []byte
	primaryparms := RsaParams{uint16(AlgTPM_ALG_RSA),
		uint16(AlgTPM_ALG_SHA1), FlagStorageDefault,
		empty, uint16(AlgTPM_ALG_AES), uint16(128),
		uint16(AlgTPM_ALG_CFB), uint16(AlgTPM_ALG_NULL),
		uint16(0), keySize, uint32(0x00010001), empty}
	rootHandle, _, err := CreatePrimary(rw,
		uint32(OrdTPM_RH_OWNER), pcrs, "", "", primaryparms)
	if err != nil {
		t.Fatal("CreatePrimary failed")
	}
	defer FlushContext(rw, rootHandle)

	// CreateKey (Quote Key)
	keyparms := RsaParams{uint16(AlgTPM_ALG_RSA),
		uint16(AlgTPM_ALG_SHA1), FlagSignerDefault, empty,
		uint16(AlgTPM_ALG_NULL), uint16(0),
		uint16(AlgTPM_ALG_ECB), uint16(AlgTPM_ALG_RSASSA),
		uint16(AlgTPM_ALG_SHA1), keySize, uint32(0x00010001), empty}
	quote_private, quote_public, err := CreateKey(rw,
		uint32(rootHandle), pcrs, "", quotePassword, keyparms)
	if err != nil {
		t.Fatal("Can't create quote key")
	}

	// Load
	quoteHandle, _, err := Load(rw, rootHandle, "",
		quotePassword, quote_public, quote_private)
	if err != nil {
		t.Fatal("Load failed")
	}
	defer FlushContext(rw, quoteHandle)

	// SaveContext
	save_area, err := SaveContext(rw, quoteHandle)
	if err != nil {
		t.Fatal("Save Context fails")
	}
	FlushContext(rw, quoteHandle)

	// LoadContext
	quoteHandle, err = LoadContext(rw, save_area)
	if err != nil {
		t.Fatal("Load Context fails")
	}

	// FlushContext
	defer FlushContext(rw, quoteHandle)
}

// Combined Nv test
func TestCombinedNvTest(t *testing.T) {
fmt.Printf("TestCombinedNvTest\n")
	// Open tpm
	rw, err := OpenTPM("/dev/tpm0")
	if err != nil {
		fmt.Printf("OpenTPM failed %s\n", err)
		return
	}
	defer rw.Close()

	// Flushall
	err = Flushall(rw)
	if err != nil {
		t.Fatal("Flushall failed\n")
	}

	handle, err := GetNvHandle(1000)
	if err != nil {
		t.Fatal("Can't get nv handle")
	}
	fmt.Printf("nvHandle: %x\n", uint32(handle));
	owner := Handle(OrdTPM_RH_OWNER)
	err = UndefineSpace(rw, owner, handle)
	if err != nil {
		fmt.Printf("UndefineSpace failed (ok) %s\n", err)
	} else {
		fmt.Printf("UndefineSpace succeeded\n")
	}
	dataSize := uint16(8)
	offset := uint16(0)
	var policy []byte // empty
	attributes := OrdNV_COUNTER | OrdNV_AUTHWRITE | OrdNV_AUTHREAD
	authString := "01020304"
	err = DefineSpace(rw, owner, handle, authString, policy,
		attributes, dataSize)
	if err != nil {
		t.Fatal("DefineSpace fails")
	} else {
		fmt.Printf("DefineSpace succeeded\n")
	}
	// The counter must be initialized by IncrementNv before
	// ReadNv is called.  Thus the counter is advanced by 1
	// no matter what.
	err = IncrementNv(rw, handle, authString)
	if err != nil {
		t.Fatal("IncrementNv failed ", err)
	}
	c1, err := ReadNv(rw, handle, authString, offset, dataSize)
	if err != nil {
		t.Fatal("ReadNv (2) failed %s", err)
	}
	fmt.Printf("Counter before second increment: %d\n", c1)
	err = IncrementNv(rw, handle, authString)
	if err != nil {
		t.Fatal("IncrementNv failed ", err)
	}
	c2, err := ReadNv(rw, handle, authString, offset, dataSize)
	if err != nil {
		t.Fatal("ReadNv (3) failed %s", err)
	}
	fmt.Printf("Counter after increment: %d\n", c2)
	if c2 <= c1 {
		t.Fatal("Error: Counter did not advance")
	}
	// Clean up.
	err = UndefineSpace(rw, owner, handle)
	if err != nil {
		fmt.Printf("UndefineSpace failed (ok) %s\n", err)
	} else {
		fmt.Printf("UndefineSpace succeeded\n")
	}
}
