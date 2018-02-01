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
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io/ioutil"
	"testing"
	"time"

	"github.com/golang/protobuf/proto"
)

func TestClearKeyHierarchy(t *testing.T) {
	rw, err := OpenTPM("/dev/tpm0")
	if err != nil {
		t.Fatal("Can't open tpm")
	}
	defer rw.Close()
	err = EvictControl(rw, Handle(OrdTPM_RH_OWNER),
		Handle(RootKeyHandle),
		Handle(RootKeyHandle))
	if err != nil {
		fmt.Printf("Evict existing permanent primary handle failed (OK)\n")
	}
	err = EvictControl(rw, Handle(OrdTPM_RH_OWNER),
		Handle(QuoteKeyHandle),
		Handle(QuoteKeyHandle))
	if err != nil {
		fmt.Printf("Evict existing permanant primary quote failed (OK)\n")
	}
}

func TestCreateKeyHierarchy(t *testing.T) {
	rw, err := OpenTPM("/dev/tpm0")
	if err != nil {
		t.Fatal("Can't open tpm")
	}
	defer rw.Close()
	pcrs := []int{7}
	rootHandle, quoteHandle, storeHandle, err := CreateTpm2KeyHierarchy(rw, pcrs,
		2048, uint16(AlgTPM_ALG_SHA1), "01020304")
	if err != nil {
		t.Fatal("Can't create keys")
	}
	FlushContext(rw, rootHandle)
	FlushContext(rw, quoteHandle)
	FlushContext(rw, storeHandle)
	PersistTpm2KeyHierarchy(rw, pcrs, 2048, uint16(AlgTPM_ALG_SHA1),
		RootKeyHandle, QuoteKeyHandle, "")
}

func TestCreateAndStoreKeyHierarchy(t *testing.T) {
	rw, err := OpenTPM("/dev/tpm0")
	if err != nil {
		t.Fatal("Can't open tpm")
	}
	defer rw.Close()
	pcrs := []int{7}
	keySize := uint16(2048)
	hash_alg_id := AlgTPM_ALG_SHA1
	quotePassword := ""
	rootFileName := "./tmptest/rootContext"
	quoteFileName := "./tmptest/quoteContext"
	storeFileName := "./tmptest/storeContext"

	err = InitTpm2KeysandContexts(rw, pcrs, keySize, hash_alg_id,
		quotePassword, rootFileName, quoteFileName, storeFileName)
	if err != nil {
		t.Fatal("Can't InitTpm2Keys")
	}
	rootHandle, quoteHandle, storeHandle, err := RestoreTpm2KeysFromContext(
		rw, quotePassword, rootFileName, quoteFileName, storeFileName)
	if err != nil {
		t.Fatal("Can't RestoreTpm2Keys")
	}
	defer FlushContext(rw, rootHandle)
	defer FlushContext(rw, quoteHandle)
	defer FlushContext(rw, storeHandle)
}

func TestMakeEndorsementCert(t *testing.T) {
	rw, err := OpenTPM("/dev/tpm0")
	if err != nil {
		t.Fatal("Can't open tpm")
	}
	defer rw.Close()

	var notBefore time.Time
	notBefore = time.Now()
	validFor := 365 * 24 * time.Hour
	notAfter := notBefore.Add(validFor)

	policyKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal("Can't generate policy key\n")
	}
	derPolicyCert, err := GenerateSelfSignedCertFromKey(policyKey,
		"Cloudproxy Authority", "Application Policy Key",
		GetSerialNumber(), notBefore, notAfter)
	if err != nil {
		t.Fatal("Can't generate policy key\n")
	}
	fmt.Printf("policyKey: %x\n", policyKey)

	ekHandle, _, err := CreateEndorsement(rw, 2048, []int{7})
	if err != nil {
		t.Fatal("Can't CreateEndorsement")
	}
	defer FlushContext(rw, ekHandle)
	endorsementCert, err := GenerateHWCert(rw,
		ekHandle, "JohnsHw", notBefore,
		notAfter, GetSerialNumber(), derPolicyCert, policyKey)
	if err != nil {
		t.Fatal("Can't create endorsement cert")
	}
	ioutil.WriteFile("./tmptest/policy_cert.test", derPolicyCert, 0644)
	ioutil.WriteFile("./tmptest/endorsement_cert.test", endorsementCert, 0644)
}

func TestSignAttest(t *testing.T) {
	rw, err := OpenTPM("/dev/tpm0")
	if err != nil {
		t.Fatal("Can't open tpm")
	}
	defer rw.Close()
	pcrs := []int{7}
	rootHandle, quoteHandle, storeHandle, err := CreateTpm2KeyHierarchy(rw, pcrs,
		2048, uint16(AlgTPM_ALG_SHA1), "")
	if err != nil {
		t.Fatal("Can't create keys")
	}
	defer FlushContext(rw, rootHandle)
	defer FlushContext(rw, quoteHandle)
	FlushContext(rw, storeHandle)

	var notBefore time.Time
	notBefore = time.Now()
	validFor := 365 * 24 * time.Hour
	notAfter := notBefore.Add(validFor)

	policyKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal("Can't generate policy key\n")
	}
	derPolicyCert, err := GenerateSelfSignedCertFromKey(policyKey,
		"Cloudproxy Authority", "Application Policy Key",
		GetSerialNumber(), notBefore, notAfter)
	if err != nil {
		t.Fatal("Can't generate policy key\n")
	}
	fmt.Printf("policyKey: %x\n", policyKey)
	attestCert, err := GenerateHWCert(rw, quoteHandle,
		"JohnsHw", notBefore, notAfter,
		GetSerialNumber(), derPolicyCert, policyKey)
	if err != nil {
		t.Fatal("Can't create attest cert")
	}
	fmt.Printf("Attest cert: %x\n", attestCert)
	ioutil.WriteFile("./tmptest/policy_cert.test", derPolicyCert, 0644)
	ioutil.WriteFile("./tmptest/attest_cert.test", attestCert, 0644)
}

// Combined Activate test
func TestMakeActivate(t *testing.T) {
	rw, err := OpenTPM("/dev/tpm0")
	if err != nil {
		t.Fatal("Can't open tpm")
	}
	defer rw.Close()

	pcrs := []int{7}
	rootHandle, quoteHandle, storeHandle, err := CreateTpm2KeyHierarchy(rw, pcrs,
		2048, uint16(AlgTPM_ALG_SHA1), "")
	if err != nil {
		t.Fatal("Can't create keys")
	}
	defer FlushContext(rw, rootHandle)
	defer FlushContext(rw, quoteHandle)
	FlushContext(rw, storeHandle)

	// Generate Credential
	credential := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x10}
	fmt.Printf("Credential: %x\n", credential)

	// ReadPublic
	_, name, _, err := ReadPublic(rw, quoteHandle)
	if err != nil {
		t.Fatal("ReadPublic fails")
	}

	ekHandle, _, err := CreateEndorsement(rw, 2048, pcrs)
	if err != nil {
		t.Fatal("CreateEndorsement fails")
	}
	defer FlushContext(rw, ekHandle)

	protectorPublic, err := GetRsaKeyFromHandle(rw, ekHandle)
	if err != nil {
		t.Fatal("Can't get key from handle")
	}

	// MakeCredential
	secret, encIdentity, integrityHmac, err := MakeCredential(
		protectorPublic, uint16(AlgTPM_ALG_SHA1), credential, name)
	if err != nil {
		t.Fatal("Can't MakeCredential\n")
	}

	// ActivateCredential
	recovered, err := ActivateCredential(rw,
		quoteHandle, ekHandle, "", "",
		append(integrityHmac, encIdentity...), secret)
	if err != nil {
		t.Fatal("Can't ActivateCredential\n")
	}
	if bytes.Compare(credential, recovered) != 0 {
		t.Fatal("Credential and recovered credential differ\n")
	}
	fmt.Printf("Make/Activate test succeeds\n")
}

func TestInternalSignProtocol(t *testing.T) {
	rw, err := OpenTPM("/dev/tpm0")
	if err != nil {
		t.Fatal("Can't open tpm")
	}
	defer rw.Close()

	pcrs := []int{7}
	rootHandle, quoteHandle, storeHandle, err := CreateTpm2KeyHierarchy(rw, pcrs,
		2048, uint16(AlgTPM_ALG_SHA1), "")
	if err != nil {
		t.Fatal("Can't create keys")
	}
	FlushContext(rw, rootHandle)
	defer FlushContext(rw, storeHandle)

	var notBefore time.Time
	notBefore = time.Now()
	validFor := 365 * 24 * time.Hour
	notAfter := notBefore.Add(validFor)

	policyKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal("Can't generate policy key\n")
	}
	derPolicyCert, err := GenerateSelfSignedCertFromKey(policyKey,
		"Cloudproxy Authority", "Application Policy Key",
		GetSerialNumber(), notBefore, notAfter)
	if err != nil {
		t.Fatal("Can't generate policy key\n")
	}

	ekHandle, _, err := CreateEndorsement(rw, 2048, []int{7})
	if err != nil {
		t.Fatal("Can't CreateEndorsement")
	}

	derEndorsementCert, err := GenerateHWCert(rw,
		ekHandle, "JohnsHw", notBefore, notAfter,
		GetSerialNumber(), derPolicyCert, policyKey)
	if err != nil {
		t.Fatal("Can't create endorsement cert")
	}

	// signing instructions
	signing_instructions_message := new(SigningInstructionsMessage)
	issuer := "JLM CA"
	signing_instructions_message.Issuer = &issuer
	var duration int64
	duration = 86500 * 365
	signing_instructions_message.Duration = &duration
	purpose := "Signing"
	signing_instructions_message.Purpose = &purpose
	signalg := "RSA"
	hashalg := "sha1"
	signing_instructions_message.SignAlg = &signalg
	signing_instructions_message.HashAlg = &hashalg
	isCA := false
	canSign := true
	signing_instructions_message.IsCA = &isCA
	signing_instructions_message.CanSign = &canSign

	//
	// Cloudproxy protocol
	//

	programName := "TestProgram"
	fmt.Printf("Program name is %s\n", programName)
	quotePassword := ""

	// Client request.
	protoClientPrivateKey, request, err := ConstructClientRequest(rw,
		derEndorsementCert, quoteHandle, "",
		quotePassword, programName)
	if err != nil {
		t.Fatal("ConstructClientRequest failed")
	}
	fmt.Printf("ConstructClientRequest succeeded\n")

	// Create Session for seal/unseal
	sessionHandle, policy_digest, err := AssistCreateSession(rw,
		AlgTPM_ALG_SHA1, pcrs)
	if err != nil {
		t.Fatal("Can't start session for Seal")
	}
	fmt.Printf("Session handle: %x\n", sessionHandle)
	fmt.Printf("policy_digest: %x\n\n", policy_digest)
	defer FlushContext(rw, sessionHandle)

	// Serialize the client private key proto, seal it and save it.
	var unsealing_secret [32]byte
	rand.Read(unsealing_secret[0:32])
	sealed_priv, sealed_pub, err := AssistSeal(rw,
		storeHandle, unsealing_secret[0:32],
		"", "", pcrs, policy_digest)
	if err != nil {
		t.Fatal("Can't seal Program private key sealing secret")
	}
	serialized_program_key, err := proto.Marshal(protoClientPrivateKey)
	if err != nil {
		t.Fatal("Can't marshal Program private key")
	}

	// Encrypt private key.
	var inHmac []byte
	calcHmac, encrypted_program_key, err := EncryptDataWithCredential(
		true, AlgTPM_ALG_SHA1, unsealing_secret[0:32],
		serialized_program_key, inHmac)
	if err != nil {
		t.Fatal("Can't EncryptDataWithCredential program key")
	}

	// Server response.
	response, err := ConstructServerResponse(policyKey,
		derPolicyCert, *signing_instructions_message, *request)
	if err != nil {
		t.Fatal("ConstructServerResponse failed")
	}
	if response == nil {
		t.Fatal("response is nil")
	}
	fmt.Printf("Response for ProgramName %s\n", *response.ProgramName)

	// Client cert recovery.
	cert, err := ClientDecodeServerResponse(rw, ekHandle,
		quoteHandle, quotePassword, *response)
	if err != nil {
		fmt.Printf("err: %s\n", err)
		t.Fatal("ClientDecodeServerResponse failed")
	}
	fmt.Printf("Client cert: %x\n", cert)

	// if we don;t do this we run out of tpm memory
	FlushContext(rw, ekHandle)
	FlushContext(rw, quoteHandle)

	// Example: recover program private key from buffer.
	encryptedProgramKey := append(calcHmac, encrypted_program_key...)
	programPrivateBlob := sealed_priv
	programPublicBlob := sealed_pub
	recovered_hmac := encryptedProgramKey[0:20]
	recovered_cipher_text := encryptedProgramKey[20:len(encryptedProgramKey)]
	fmt.Printf("Recovered hmac, cipher_text: %x, %x\n", recovered_hmac,
		recovered_cipher_text)
	fmt.Printf("encryptedProgramKey: %x\n", encryptedProgramKey)
	fmt.Printf("Recovered priv, pub: %x, %x\n\n", programPrivateBlob,
		programPublicBlob)

	// Unseal secret and decrypt private policy key.
	unsealed, _, err := AssistUnseal(rw, sessionHandle,
		storeHandle, sealed_pub, sealed_priv, "",
		"", policy_digest)
	if err != nil {
		t.Fatal("Can't Unseal")
	}
	_, decrypted_program_key, err := EncryptDataWithCredential(false,
		AlgTPM_ALG_SHA1, unsealed, encrypted_program_key, calcHmac)
	if err != nil {
		t.Fatal("Can't EncryptDataWithCredential (decrypt) program key")
	}
	fmt.Printf("serialized_program_key: %x\n\n", serialized_program_key)
	fmt.Printf("unsealed: %x\n\n", unsealed)
	fmt.Printf("decrypted_program_key: %x\n\n", decrypted_program_key)
	fmt.Printf("Cloudproxy protocol succeeds\n")
}

func RestSignProtocolChannel(t *testing.T) {
}

func RestPCR1718(t *testing.T) {
}
