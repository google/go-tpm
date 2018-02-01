// Copyright (c) 2016, Google Inc. All rights reserved.
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
	"testing"
)

func TestClearKeyHierarchy(t *testing.T) {
	if !*runIntegration {
		t.SkipNow()
	}
	rw, err := OpenTPM("/dev/tpm0")
	if err != nil {
		t.Fatalf("OpenTPM: %v", err)
	}
	defer rw.Close()
	err = EvictControl(rw, Handle(OrdTPM_RH_OWNER), Handle(RootKeyHandle), Handle(RootKeyHandle))
	if err != nil {
		t.Fatalf("EvictControl on permanent primary handle failed: %v", err)
	}
	err = EvictControl(rw, Handle(OrdTPM_RH_OWNER), Handle(QuoteKeyHandle), Handle(QuoteKeyHandle))
	if err != nil {
		t.Fatalf("EvictControl on permanent primary quote failed: %v", err)
	}
}

func TestCreateKeyHierarchy(t *testing.T) {
	if !*runIntegration {
		t.SkipNow()
	}
	rw, err := OpenTPM("/dev/tpm0")
	if err != nil {
		t.Fatalf("OpenTPM: %v", err)
	}
	defer rw.Close()
	pcrs := []int{7}
	rootHandle, quoteHandle, storeHandle, err := CreateKeyHierarchy(rw, pcrs, 2048, uint16(AlgTPM_ALG_SHA1), "01020304")
	if err != nil {
		t.Fatalf("CreateKeyHierarchy: %v", err)
	}
	FlushContext(rw, rootHandle)
	FlushContext(rw, quoteHandle)
	FlushContext(rw, storeHandle)
	PersistKeyHierarchy(rw, pcrs, 2048, uint16(AlgTPM_ALG_SHA1), RootKeyHandle, QuoteKeyHandle, "")
}

func TestMakeActivate(t *testing.T) {
	if !*runIntegration {
		t.SkipNow()
	}
	rw, err := OpenTPM("/dev/tpm0")
	if err != nil {
		t.Fatalf("OpenTPM: %v", err)
	}
	defer rw.Close()

	pcrs := []int{7}
	rootHandle, quoteHandle, storeHandle, err := CreateKeyHierarchy(rw, pcrs, 2048, uint16(AlgTPM_ALG_SHA1), "")
	if err != nil {
		t.Fatalf("CreateKeyHierarchy: %v", err)
	}
	defer FlushContext(rw, rootHandle)
	defer FlushContext(rw, quoteHandle)
	FlushContext(rw, storeHandle)

	credential := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x10}

	_, name, _, err := ReadPublic(rw, quoteHandle)
	if err != nil {
		t.Fatalf("ReadPublic: %v", err)
	}

	ekHandle, _, err := CreateEndorsement(rw, 2048, pcrs)
	if err != nil {
		t.Fatalf("CreateEndorsement: %v", err)
	}
	defer FlushContext(rw, ekHandle)

	secret, encIdentity, err := MakeCredential(rw, ekHandle, credential, name)
	if err != nil {
		t.Fatalf("MakeCredential: %v", err)
	}

	recovered, err := ActivateCredential(rw, quoteHandle, ekHandle, "", "", encIdentity, secret)
	if err != nil {
		t.Fatalf("ActivateCredential: %v", err)
	}
	if bytes.Compare(credential, recovered) != 0 {
		t.Fatalf("Credential and recovered credential differ\ngot: %v\nwant: %v", recovered, credential)
	}
}
