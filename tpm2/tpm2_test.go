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
	"flag"
	"os"
	"testing"
)

var runIntegration = flag.Bool("integration", false, "Run integration tests using /dev/tpm0")

func TestMain(m *testing.M) {
	flag.Parse()
	os.Exit(m.Run())
}

func TestGetRandom(t *testing.T) {
	if !*runIntegration {
		t.SkipNow()
	}
	rw, err := OpenTPM("/dev/tpm0")
	if err != nil {
		t.Fatalf("OpenTPM failed: %s", err)
	}
	defer rw.Close()
	FlushAll(rw)

	_, err = GetRandom(rw, 16)
	if err != nil {
		t.Fatalf("GetRandom failed: %v", err)
	}
}

func TestReadPCRs(t *testing.T) {
	if !*runIntegration {
		t.SkipNow()
	}
	rw, err := OpenTPM("/dev/tpm0")
	if err != nil {
		t.Fatalf("OpenTPM failed: %s", err)
	}
	defer rw.Close()
	FlushAll(rw)

	pcr := []byte{0x03, 0x80, 0x00, 0x00}
	_, _, _, _, err = ReadPCRs(rw, pcr)
	if err != nil {
		t.Fatalf("ReadPCRs failed: %s", err)
	}
}

func TestReadClock(t *testing.T) {
	if !*runIntegration {
		t.SkipNow()
	}
	rw, err := OpenTPM("/dev/tpm0")
	if err != nil {
		t.Fatalf("OpenTPM failed: %s", err)
	}
	defer rw.Close()
	FlushAll(rw)

	_, _, err = ReadClock(rw)
	if err != nil {
		t.Fatalf("ReadClock failed: %s", err)
	}

}

func TestGetCapabilities(t *testing.T) {
	if !*runIntegration {
		t.SkipNow()
	}
	rw, err := OpenTPM("/dev/tpm0")
	if err != nil {
		t.Fatalf("OpenTPM failed: %s", err)
	}
	defer rw.Close()
	FlushAll(rw)

	_, err = GetCapabilities(rw, TPM_CAP_HANDLES, 1, 0x80000000)
	if err != nil {
		t.Fatalf("GetCapabilities failed: %s", err)
	}
}

func TestCombinedKeyTest(t *testing.T) {
	if !*runIntegration {
		t.SkipNow()
	}
	rw, err := OpenTPM("/dev/tpm0")
	if err != nil {
		t.Fatalf("OpenTPM failed: %s", err)
	}
	defer rw.Close()

	err = FlushAll(rw)
	if err != nil {
		t.Fatalf("FlushAll failed: %s", err)
	}

	primaryparms := RSAParams{
		TPM_ALG_RSA,
		TPM_ALG_SHA1,
		0x00030072,
		[]byte(nil),
		TPM_ALG_AES,
		128,
		TPM_ALG_CFB,
		TPM_ALG_NULL,
		0,
		1024,
		uint32(0x00010001),
		[]byte(nil),
	}
	parentHandle, publicBlob, err := CreatePrimary(rw, TPM_RH_OWNER, []int{0x7}, "", "01020304", primaryparms)
	if err != nil {
		t.Fatalf("CreatePrimary failed: %s", err)
	}

	keyparms := RSAParams{
		TPM_ALG_RSA,
		TPM_ALG_SHA1,
		0x00030072,
		[]byte(nil),
		TPM_ALG_AES,
		128,
		TPM_ALG_CFB,
		TPM_ALG_NULL,
		0,
		1024,
		uint32(0x00010001),
		[]byte(nil),
	}
	privateBlob, publicBlob, err := CreateKey(rw, parentHandle, []int{7}, "01020304", "01020304", keyparms)
	if err != nil {
		t.Fatalf("CreateKey failed: %s", err)
	}

	keyHandle, _, err := Load(rw, parentHandle, "", "01020304", publicBlob, privateBlob)
	if err != nil {
		t.Fatalf("Load failed: %s", err)
	}

	_, _, _, err = ReadPublic(rw, keyHandle)
	if err != nil {
		t.Fatalf("ReadPublic failed: %s", err)
	}

	if err = FlushContext(rw, keyHandle); err != nil {
		t.Fatalf("FlushContext failed: %s", err)
	}
	if err = FlushContext(rw, parentHandle); err != nil {
		t.Fatalf("FlushContext failed: %s", err)
	}
}

func TestCombinedSealTest(t *testing.T) {
	if !*runIntegration {
		t.SkipNow()
	}
	rw, err := OpenTPM("/dev/tpm0")
	if err != nil {
		t.Fatalf("OpenTPM failed: %s", err)
	}
	defer rw.Close()

	err = FlushAll(rw)
	if err != nil {
		t.Fatalf("FlushAll failed: %s", err)
	}

	primaryparms := RSAParams{
		TPM_ALG_RSA,
		TPM_ALG_SHA1,
		0x00030072,
		[]byte(nil),
		TPM_ALG_AES,
		128,
		TPM_ALG_CFB,
		TPM_ALG_NULL,
		0,
		1024,
		uint32(0x00010001),
		[]byte(nil),
	}
	parentHandle, publicBlob, err := CreatePrimary(rw, TPM_RH_OWNER, []int{0x7}, "", "01020304", primaryparms)
	if err != nil {
		t.Fatalf("CreatePrimary failed: %s", err)
	}

	nonceCaller := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	var secret []byte
	sym := TPM_ALG_NULL
	toSeal := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
	hashAlg := TPM_ALG_SHA1

	sessionHandle, policyDigest, err := StartAuthSession(rw, TPM_RH_NULL, TPM_RH_NULL, nonceCaller, secret, uint8(TPM_SE_POLICY), sym, hashAlg)
	if err != nil {
		FlushContext(rw, parentHandle)
		t.Fatalf("StartAuthSession failed: %s", err)
	}

	err = PolicyPassword(rw, sessionHandle)
	if err != nil {
		FlushContext(rw, parentHandle)
		FlushContext(rw, sessionHandle)
		t.Fatalf("PolicyPCR failed: %s", err)
	}
	var tpmDigest []byte
	err = PolicyPCR(rw, sessionHandle, tpmDigest, []int{7})
	if err != nil {
		FlushContext(rw, parentHandle)
		FlushContext(rw, sessionHandle)
		t.Fatalf("PolicyPCR failed: %s", err)
	}

	policyDigest, err = PolicyGetDigest(rw, sessionHandle)
	if err != nil {
		FlushContext(rw, parentHandle)
		FlushContext(rw, sessionHandle)
		t.Fatalf("PolicyGetDigest after PolicyPCR failed: %s", err)
	}

	keyedhashparms := KeyedHashParams{
		TPM_ALG_KEYEDHASH,
		TPM_ALG_SHA1,
		uint32(0x00000012),
		[]byte(nil),
		TPM_ALG_AES,
		128,
		TPM_ALG_CFB,
		TPM_ALG_NULL,
		[]byte(nil),
	}
	privateBlob, publicBlob, err := CreateSealed(rw, parentHandle, policyDigest, "01020304", "01020304", toSeal, []int{7}, keyedhashparms)
	if err != nil {
		FlushContext(rw, parentHandle)
		FlushContext(rw, sessionHandle)
		t.Fatalf("CreateSealed failed: %s", err)
	}

	itemHandle, _, err := Load(rw, parentHandle, "", "01020304", publicBlob, privateBlob)
	if err != nil {
		FlushContext(rw, sessionHandle)
		FlushContext(rw, itemHandle)
		FlushContext(rw, parentHandle)
		t.Fatalf("Load failed: %s", err)
	}

	unsealed, _, err := Unseal(rw, itemHandle, "01020304", sessionHandle, policyDigest)
	if err != nil {
		FlushContext(rw, itemHandle)
		FlushContext(rw, parentHandle)
		t.Fatalf("Unseal failed: %s", err)
	}

	FlushContext(rw, itemHandle)
	FlushContext(rw, parentHandle)
	FlushContext(rw, sessionHandle)
	if bytes.Compare(toSeal, unsealed) != 0 {
		t.Fatalf("seal and unsealed bytes dont match: got %v, want %v", unsealed, toSeal)
	}
}

func TestCombinedEndorsementTest(t *testing.T) {
	if !*runIntegration {
		t.SkipNow()
	}

	rw, err := OpenTPM("/dev/tpm0")
	if err != nil {
		t.Fatalf("OpenTPM failed: %s", err)
	}
	defer rw.Close()

	err = FlushAll(rw)
	if err != nil {
		t.Fatalf("FlushAll failed: %s", err)
	}

	primaryparms := RSAParams{
		TPM_ALG_RSA,
		TPM_ALG_SHA1,
		0x00030072,
		[]byte(nil),
		TPM_ALG_AES,
		128,
		TPM_ALG_CFB,
		TPM_ALG_NULL,
		0,
		2048,
		uint32(0x00010001),
		[]byte(nil),
	}
	parentHandle, publicBlob, err := CreatePrimary(rw, TPM_RH_OWNER, []int{0x7}, "", "", primaryparms)
	if err != nil {
		t.Fatalf("CreatePrimary failed: %s", err)
	}

	keyparms := RSAParams{
		TPM_ALG_RSA,
		TPM_ALG_SHA1,
		0x00030072,
		[]byte(nil),
		TPM_ALG_AES,
		128,
		TPM_ALG_CFB,
		TPM_ALG_NULL,
		0,
		2048,
		uint32(0x00010001),
		[]byte(nil),
	}
	privateBlob, publicBlob, err := CreateKey(rw, parentHandle, []int{7}, "", "01020304", keyparms)
	if err != nil {
		t.Fatalf("CreateKey failed: %s", err)
	}

	keyHandle, _, err := Load(rw, parentHandle, "", "", publicBlob, privateBlob)
	if err != nil {
		t.Fatalf("Load failed: %s", err)
	}

	_, name, _, err := ReadPublic(rw, keyHandle)
	if err != nil {
		t.Fatalf("ReadPublic failed: %s", err)
	}

	// Generate Credential
	credential := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x10}
	credBlob, encryptedSecret0, err := MakeCredential(rw, parentHandle, credential, name)
	if err != nil {
		FlushContext(rw, keyHandle)
		FlushContext(rw, parentHandle)
		t.Fatalf("MakeCredential failed: %s", err)
	}

	recoveredCredential1, err := ActivateCredential(rw, keyHandle, parentHandle, "01020304", "", credBlob, encryptedSecret0)
	if err != nil {
		FlushContext(rw, keyHandle)
		FlushContext(rw, parentHandle)
		t.Fatalf("ActivateCredential failed: %s", err)
	}
	if bytes.Compare(credential, recoveredCredential1) != 0 {
		FlushContext(rw, keyHandle)
		FlushContext(rw, parentHandle)
		t.Fatalf("Credential and recovered credential differ: got %v, want %v", recoveredCredential1, credential)
	}

	FlushContext(rw, keyHandle)
}

func TestCombinedContextTest(t *testing.T) {
	if !*runIntegration {
		t.SkipNow()
	}
	rw, err := OpenTPM("/dev/tpm0")
	if err != nil {
		t.Fatalf("OpenTPM failed: %v", err)
	}
	defer rw.Close()

	err = FlushAll(rw)
	if err != nil {
		t.Fatalf("FlushAll failed: %v", err)
	}

	pcrs := []int{7}
	keySize := 2048
	quotePassword := ""

	primaryparms := RSAParams{
		TPM_ALG_RSA,
		TPM_ALG_SHA1,
		FlagStorageDefault,
		[]byte(nil),
		TPM_ALG_AES,
		128,
		TPM_ALG_CFB,
		TPM_ALG_NULL,
		0,
		uint16(keySize),
		uint32(0x00010001),
		[]byte(nil),
	}
	rootHandle, _, err := CreatePrimary(rw, TPM_RH_OWNER, pcrs, "", "", primaryparms)
	if err != nil {
		t.Fatalf("CreatePrimary failed: %v", err)
	}
	defer FlushContext(rw, rootHandle)

	// CreateKey (Quote Key)
	keyparms := RSAParams{
		TPM_ALG_RSA,
		TPM_ALG_SHA1,
		FlagSignerDefault,
		[]byte(nil),
		TPM_ALG_NULL,
		0,
		TPM_ALG_ECB,
		TPM_ALG_RSASSA,
		TPM_ALG_SHA1,
		uint16(keySize),
		uint32(0x00010001),
		[]byte(nil),
	}
	quotePrivate, quotePublic, err := CreateKey(rw, rootHandle, pcrs, "", quotePassword, keyparms)
	if err != nil {
		t.Fatalf("CreateKey failed: %v", err)
	}

	quoteHandle, _, err := Load(rw, rootHandle, "", quotePassword, quotePublic, quotePrivate)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	defer FlushContext(rw, quoteHandle)

	saveArea, err := SaveContext(rw, quoteHandle)
	if err != nil {
		t.Fatalf("SaveContext failed: %v", err)
	}
	FlushContext(rw, quoteHandle)

	quoteHandle, err = LoadContext(rw, saveArea)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	FlushContext(rw, quoteHandle)
}
