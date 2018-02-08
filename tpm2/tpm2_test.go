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

	_, _, err = ReadClock(rw)
	if err != nil {
		t.Fatalf("ReadClock failed: %s", err)
	}

}

func TestGetCapability(t *testing.T) {
	if !*runIntegration {
		t.SkipNow()
	}
	rw, err := OpenTPM("/dev/tpm0")
	if err != nil {
		t.Fatalf("OpenTPM failed: %s", err)
	}
	defer rw.Close()

	_, err = GetCapability(rw, CapabilityHandles, 1, 0x80000000)
	if err != nil {
		t.Fatalf("GetCapability failed: %s", err)
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

	primaryparms := RSAParams{
		AlgRSA,
		AlgSHA1,
		0x00030072,
		[]byte(nil),
		AlgAES,
		128,
		AlgCFB,
		AlgNull,
		0,
		1024,
		uint32(0x00010001),
		[]byte(nil),
	}
	parentHandle, publicBlob, err := CreatePrimary(rw, HandleOwner, []int{0x7}, "", "01020304", primaryparms)
	if err != nil {
		t.Fatalf("CreatePrimary failed: %s", err)
	}

	keyparms := RSAParams{
		AlgRSA,
		AlgSHA1,
		0x00030072,
		[]byte(nil),
		AlgAES,
		128,
		AlgCFB,
		AlgNull,
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

func TestCombinedEndorsementTest(t *testing.T) {
	if !*runIntegration {
		t.SkipNow()
	}

	rw, err := OpenTPM("/dev/tpm0")
	if err != nil {
		t.Fatalf("OpenTPM failed: %s", err)
	}
	defer rw.Close()

	primaryparms := RSAParams{
		AlgRSA,
		AlgSHA1,
		0x00030072,
		[]byte(nil),
		AlgAES,
		128,
		AlgCFB,
		AlgNull,
		0,
		2048,
		uint32(0x00010001),
		[]byte(nil),
	}
	parentHandle, publicBlob, err := CreatePrimary(rw, HandleOwner, []int{0x7}, "", "", primaryparms)
	if err != nil {
		t.Fatalf("CreatePrimary failed: %s", err)
	}

	keyparms := RSAParams{
		AlgRSA,
		AlgSHA1,
		0x00030072,
		[]byte(nil),
		AlgAES,
		128,
		AlgCFB,
		AlgNull,
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

	pcrs := []int{7}
	keySize := 2048
	quotePassword := ""

	primaryparms := RSAParams{
		AlgRSA,
		AlgSHA1,
		FlagStorageDefault,
		[]byte(nil),
		AlgAES,
		128,
		AlgCFB,
		AlgNull,
		0,
		uint16(keySize),
		uint32(0x00010001),
		[]byte(nil),
	}
	rootHandle, _, err := CreatePrimary(rw, HandleOwner, pcrs, "", "", primaryparms)
	if err != nil {
		t.Fatalf("CreatePrimary failed: %v", err)
	}
	defer FlushContext(rw, rootHandle)

	// CreateKey (Quote Key)
	keyparms := RSAParams{
		AlgRSA,
		AlgSHA1,
		FlagSignerDefault,
		[]byte(nil),
		AlgNull,
		0,
		AlgECB,
		AlgRSASSA,
		AlgSHA1,
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

	saveArea, err := ContextSave(rw, quoteHandle)
	if err != nil {
		t.Fatalf("ContextSave failed: %v", err)
	}
	FlushContext(rw, quoteHandle)

	quoteHandle, err = ContextLoad(rw, saveArea)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	FlushContext(rw, quoteHandle)
}
