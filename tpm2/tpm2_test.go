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
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"flag"
	"io"
	"os"
	"reflect"
	"testing"

	"github.com/google/go-tpm/tpmutil"
)

var tpmPath = flag.String("tpm_path", "", "Path to TPM character device. Most Linux systems expose it under /dev/tpm0. Empty value (default) will disable all integration tests.")

func TestMain(m *testing.M) {
	flag.Parse()
	os.Exit(m.Run())
}

func openTPM(t *testing.T) io.ReadWriteCloser {
	if *tpmPath == "" {
		t.SkipNow()
	}
	rw, err := OpenTPM(*tpmPath)
	if err != nil {
		t.Fatalf("OpenTPM failed: %s", err)
	}
	return rw
}

var (
	// PCR7 is for SecureBoot.
	pcrSelection     = PCRSelection{Hash: AlgSHA1, PCRs: []int{7}}
	defaultKeyParams = RSAParams{
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
	defaultPassword = "01020304"
)

func TestGetRandom(t *testing.T) {
	rw := openTPM(t)
	defer rw.Close()

	if _, err := GetRandom(rw, 16); err != nil {
		t.Fatalf("GetRandom failed: %v", err)
	}
}

func TestReadPCRs(t *testing.T) {
	rw := openTPM(t)
	defer rw.Close()

	pcrs, err := ReadPCRs(rw, pcrSelection)
	if err != nil {
		t.Errorf("ReadPCRs failed: %s", err)
	}
	for pcr, val := range pcrs {
		if empty := make([]byte, len(val)); reflect.DeepEqual(empty, val) {
			t.Errorf("Value of PCR %d is empty", pcr)
		}
	}
}

func TestReadClock(t *testing.T) {
	rw := openTPM(t)
	defer rw.Close()

	if _, _, err := ReadClock(rw); err != nil {
		t.Fatalf("ReadClock failed: %s", err)
	}

}

func TestGetCapability(t *testing.T) {
	rw := openTPM(t)
	defer rw.Close()

	if _, err := GetCapability(rw, CapabilityHandles, 1, 0x80000000); err != nil {
		t.Fatalf("GetCapability failed: %s", err)
	}
}

func TestCombinedKeyTest(t *testing.T) {
	rw := openTPM(t)
	defer rw.Close()

	parentHandle, _, err := CreatePrimary(rw, HandleOwner, pcrSelection, "", defaultPassword, defaultKeyParams)
	if err != nil {
		t.Fatalf("CreatePrimary failed: %s", err)
	}
	defer FlushContext(rw, parentHandle)

	privateBlob, publicBlob, err := CreateKey(rw, parentHandle, pcrSelection, defaultPassword, defaultPassword, defaultKeyParams)
	if err != nil {
		t.Fatalf("CreateKey failed: %s", err)
	}

	keyHandle, _, err := Load(rw, parentHandle, defaultPassword, publicBlob, privateBlob)
	if err != nil {
		t.Fatalf("Load failed: %s", err)
	}
	defer FlushContext(rw, keyHandle)

	if _, _, _, err := ReadPublic(rw, keyHandle); err != nil {
		t.Fatalf("ReadPublic failed: %s", err)
	}
}

func TestCombinedEndorsementTest(t *testing.T) {
	rw := openTPM(t)
	defer rw.Close()

	parentHandle, _, err := CreatePrimary(rw, HandleOwner, pcrSelection, "", "", defaultKeyParams)
	if err != nil {
		t.Fatalf("CreatePrimary failed: %s", err)
	}
	defer FlushContext(rw, parentHandle)

	privateBlob, publicBlob, err := CreateKey(rw, parentHandle, pcrSelection, "", defaultPassword, defaultKeyParams)
	if err != nil {
		t.Fatalf("CreateKey failed: %s", err)
	}

	keyHandle, _, err := Load(rw, parentHandle, "", publicBlob, privateBlob)
	if err != nil {
		t.Fatalf("Load failed: %s", err)
	}
	defer FlushContext(rw, keyHandle)

	_, name, _, err := ReadPublic(rw, keyHandle)
	if err != nil {
		t.Fatalf("ReadPublic failed: %s", err)
	}

	// Generate Credential
	credential := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x10}
	credBlob, encryptedSecret0, err := MakeCredential(rw, parentHandle, credential, name)
	if err != nil {
		t.Fatalf("MakeCredential failed: %s", err)
	}

	recoveredCredential1, err := ActivateCredential(rw, keyHandle, parentHandle, defaultPassword, "", credBlob, encryptedSecret0)
	if err != nil {
		t.Fatalf("ActivateCredential failed: %s", err)
	}
	if bytes.Compare(credential, recoveredCredential1) != 0 {
		t.Fatalf("Credential and recovered credential differ: got %v, want %v", recoveredCredential1, credential)
	}
}

func TestCombinedContextTest(t *testing.T) {
	rw := openTPM(t)
	defer rw.Close()

	rootHandle, _, err := CreatePrimary(rw, HandleOwner, pcrSelection, "", "", defaultKeyParams)
	if err != nil {
		t.Fatalf("CreatePrimary failed: %v", err)
	}
	defer FlushContext(rw, rootHandle)

	// CreateKey (Quote Key)
	quotePrivate, quotePublic, err := CreateKey(rw, rootHandle, pcrSelection, "", "", defaultKeyParams)
	if err != nil {
		t.Fatalf("CreateKey failed: %v", err)
	}

	quoteHandle, _, err := Load(rw, rootHandle, "", quotePublic, quotePrivate)
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
}

func TestEvictControl(t *testing.T) {
	rw := openTPM(t)
	defer rw.Close()

	rootHandle, _, err := CreatePrimary(rw, HandleOwner, pcrSelection, "", "", defaultKeyParams)
	if err != nil {
		t.Fatalf("CreatePrimary failed: %v", err)
	}
	defer FlushContext(rw, rootHandle)

	// CreateKey (Quote Key)
	quotePrivate, quotePublic, err := CreateKey(rw, rootHandle, pcrSelection, "", "", defaultKeyParams)
	if err != nil {
		t.Fatalf("CreateKey failed: %v", err)
	}

	quoteHandle, _, err := Load(rw, rootHandle, "", quotePublic, quotePrivate)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	defer FlushContext(rw, quoteHandle)

	persistentHandle := tpmutil.Handle(0x817FFFFF)
	// Evict persistent key, if there is one already (e.g. last test run failed).
	if err := EvictControl(rw, "", HandleOwner, persistentHandle, persistentHandle); err != nil {
		t.Logf("(expected) EvictControl failed: %v", err)
	}
	// Make key persistent.
	if err := EvictControl(rw, "", HandleOwner, quoteHandle, persistentHandle); err != nil {
		t.Fatalf("EvictControl failed: %v", err)
	}
	// Evict persistent key.
	if err := EvictControl(rw, "", HandleOwner, persistentHandle, persistentHandle); err != nil {
		t.Fatalf("EvictControl failed: %v", err)
	}
}

func TestHash(t *testing.T) {
	rw := openTPM(t)
	defer rw.Close()

	val := []byte("garmonbozia")
	got, err := Hash(rw, AlgSHA256, val)
	if err != nil {
		t.Fatalf("Hash failed: %v", err)
	}
	want := sha256.Sum256(val)

	if !bytes.Equal(got, want[:]) {
		t.Errorf("Hash(%q) returned %x, want %x", val, got, want)
	}
}

func TestLoadExternalPublicKey(t *testing.T) {
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	rw := openTPM(t)
	defer rw.Close()

	rp := RSAParams{
		EncAlg:     AlgRSA,
		HashAlg:    AlgSHA1,
		Attributes: FlagSign | FlagSensitiveDataOrigin | FlagUserWithAuth,
		SymAlg:     AlgNull,
		Scheme:     AlgRSASSA,
		SchemeHash: AlgSHA1,
		ModSize:    2048,
		Exp:        uint32(pk.PublicKey.E),
		Modulus:    pk.PublicKey.N.Bytes(),
	}
	private := Private{
		Type:      AlgRSA,
		Sensitive: pk.Primes[0].Bytes(),
	}
	h, _, err := LoadExternal(rw, rp, private, HandleNull)
	if err != nil {
		t.Fatal(err)
	}
	defer FlushContext(rw, h)
}

func TestCertify(t *testing.T) {
	rw := openTPM(t)
	defer rw.Close()

	params := RSAParams{
		EncAlg:     AlgRSA,
		HashAlg:    AlgSHA256,
		Attributes: FlagSignerDefault,
		SymAlg:     AlgNull,
		Scheme:     AlgRSASSA,
		SchemeHash: AlgSHA256,
		ModSize:    1024,
	}
	signerHandle, _, err := CreatePrimary(rw, HandleOwner, pcrSelection, "", defaultPassword, params)
	if err != nil {
		t.Fatalf("CreatePrimary(signer) failed: %s", err)
	}
	defer FlushContext(rw, signerHandle)

	subjectHandle, _, err := CreatePrimary(rw, HandlePlatform, pcrSelection, "", defaultPassword, params)
	if err != nil {
		t.Fatalf("CreatePrimary(subject) failed: %s", err)
	}
	defer FlushContext(rw, subjectHandle)

	sig, err := Certify(rw, defaultPassword, defaultPassword, subjectHandle, signerHandle, nil)
	if err != nil {
		t.Errorf("Certify failed: %s", err)
		return
	}
	t.Logf("signature (hex): %x", sig)
}

func TestCertifyExternalKey(t *testing.T) {
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	rw := openTPM(t)
	defer rw.Close()

	rp := RSAParams{
		EncAlg:     AlgRSA,
		HashAlg:    AlgSHA1,
		Attributes: FlagSign | FlagSensitiveDataOrigin | FlagUserWithAuth,
		SymAlg:     AlgNull,
		Scheme:     AlgRSASSA,
		SchemeHash: AlgSHA1,
		ModSize:    2048,
		Exp:        uint32(pk.PublicKey.E),
		Modulus:    pk.PublicKey.N.Bytes(),
	}
	private := Private{
		Type:      AlgRSA,
		Sensitive: pk.Primes[0].Bytes(),
	}
	subjectHandle, _, err := LoadExternal(rw, rp, private, HandleNull)
	if err != nil {
		t.Fatalf("LoadExternal: %v", err)
	}
	defer FlushContext(rw, subjectHandle)

	params := RSAParams{
		EncAlg:     AlgRSA,
		HashAlg:    AlgSHA256,
		Attributes: FlagSignerDefault,
		SymAlg:     AlgNull,
		Scheme:     AlgRSASSA,
		SchemeHash: AlgSHA256,
		ModSize:    1024,
	}
	signerHandle, _, err := CreatePrimary(rw, HandleOwner, pcrSelection, "", defaultPassword, params)
	if err != nil {
		t.Fatalf("CreatePrimary(signer) failed: %s", err)
	}
	defer FlushContext(rw, signerHandle)

	sig, err := Certify(rw, "", defaultPassword, subjectHandle, signerHandle, nil)
	if err != nil {
		t.Errorf("Certify failed: %s", err)
		return
	}
	t.Logf("signature (hex): %x", sig)
}
