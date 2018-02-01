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
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"math/big"
	"testing"
	"time"

	"github.com/golang/protobuf/proto"
)

func TestStringUtils(t *testing.T) {
	in := "1, 3, 2"
	out, err := StringToIntList(in)
	if err != nil {
		fmt.Printf("err: %s\n", err)
		t.Fatal("Can't parse list\n")
	}
	for _, v := range out {
		fmt.Printf("%d ", v)
	}
	fmt.Printf("\n")
}

func TestSerializeDeserialize(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal("Cant generate rsa key\n")
	}
	ser, err := SerializeRsaPrivateKey(key)
	if err != nil {
		t.Fatal("Cant serialize rsa key\n")
	}
	newKey, err := DeserializeRsaKey(ser)
	if err != nil {
		t.Fatal("Can't deserialize rsa key\n")
	}
	if bytes.Compare(key.D.Bytes(), newKey.D.Bytes()) != 0 {
		t.Fatal("D is wrong\n")
	}
	if bytes.Compare(key.PublicKey.N.Bytes(), newKey.PublicKey.N.Bytes()) != 0 {
		t.Fatal("N is wrong\n")
	}
	ioutil.WriteFile("./tmptest/ser.buf", ser, 0644)
	buf, _ := ioutil.ReadFile("./tmptest/ser.buf")
	newerKey, err := DeserializeRsaKey(buf)
	if err != nil {
		t.Fatal("Can't deserialize rsa key\n")
	}
	if bytes.Compare(key.D.Bytes(), newerKey.D.Bytes()) != 0 {
		t.Fatal("D is wrong\n")
	}
	if bytes.Compare(key.PublicKey.N.Bytes(), newerKey.PublicKey.N.Bytes()) != 0 {
		t.Fatal("N is wrong\n")
	}
}

func TestDer(t *testing.T) {
	fileName := "./tmptest/endorsement_cert"
	der, err := ioutil.ReadFile(fileName)
	if der == nil || err != nil {
		t.Fatal("Can't retrieve endorsement cert\n")
	}
	key, err := GetPublicKeyFromDerCert(der)
	if der == nil {
		t.Fatal("Can't get public key from endorsement cert\n")
	}
	fmt.Printf("key: %x\n", key)
}

// Test GenerateCert from Keys
func TestGenerateCertFromKeys(t *testing.T) {
	var notBefore time.Time
	notBefore = time.Now()
	validFor := 365 * 24 * time.Hour
	notAfter := notBefore.Add(validFor)

	signingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal("Can't generate signing key\n")
	}
	derSignerCert, err := GenerateSelfSignedCertFromKey(signingKey, "Cloudproxy Authority",
		"Application Policy Key", GetSerialNumber(), notBefore, notAfter)
	if err != nil {
		t.Fatal("Can't generate signer key\n")
	}
	fmt.Printf("SigningKey: %x\n", signingKey)

	signedKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal("Can't generate privatekey\n")
	}
	newPublic := PublicKeyFromPrivate(signedKey)
	if newPublic == nil {
		t.Fatal("Can't generate privatekey\n")
	}
	cert, err := GenerateCertFromKeys(signingKey, derSignerCert, newPublic,
		"TestKey", "CommonTestKey", GetSerialNumber(),
		notBefore, notAfter)
	if err != nil {
		t.Fatal("Can't generate cert\n")
	}
	fmt.Printf("cert: %x\n", cert)
}

func TestEndorseCertificate(t *testing.T) {
	fileName := "./tmptest/endorsement_cert.ext"
	out, err := ioutil.ReadFile(fileName)
	if out == nil || err != nil {
		t.Fatal("Can't retrieve endorsement cert\n")
	}
	endorse_cert, err := x509.ParseCertificate(out)
	if err != nil {
		t.Fatal("Can't parse test endorse certificate ", err, "\n")
	}
	fmt.Printf("endorse_cert: %x\n", endorse_cert)
}

func TestSignCertificate(t *testing.T) {
	var notBefore time.Time
	notBefore = time.Now()
	validFor := 365 * 24 * time.Hour
	notAfter := notBefore.Add(validFor)

	// Generate Policy Key.
	privatePolicyKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal("Can't generate privatekey\n")
	}

	derPolicyCert, err := GenerateSelfSignedCertFromKey(privatePolicyKey, "PolicyKey",
		"PolicyKey", GetSerialNumber(), notBefore, notAfter)
	if err != nil {
		t.Fatal("Can't parse program certificate ", err, "\n")
	}

	// Generate Program Key.
	privateProgramKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal("Can't generate program privatekey\n")
	}
	derProgramCert, err := GenerateCertFromKeys(privatePolicyKey,
		derPolicyCert, &privateProgramKey.PublicKey,
		"JLM", "Test-program", GetSerialNumber(), notBefore, notAfter)
	if err != nil {
		t.Fatal("Can't generate cert\n")
	}
	ok, err := VerifyDerCert(derProgramCert, derPolicyCert)
	if !ok || err != nil {
		t.Fatal("Can't verify certificate ", err, "\n")
	}
}

func TestRsaEncryptDataWithCredential(t *testing.T) {
	unmarshaled_credential := []byte{0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8,
		0x9, 0xa, 0xb, 0xc, 0xd, 0xf, 0x10}
	var inData [64]byte
	for i := 0; i < int(64); i++ {
		inData[i] = byte(i)
	}
	fmt.Printf("Credential: %x\n", unmarshaled_credential)
	fmt.Printf("inData: %x\n", inData)

	var inHmac []byte
	calcHmac, outData, err := EncryptDataWithCredential(true,
		AlgTPM_ALG_SHA1, unmarshaled_credential,
		inData[0:64], inHmac)
	if err != nil {
		t.Fatal("Could not encrypt data\n")
	}
	fmt.Printf("calcHmac: %x\n", calcHmac)
	fmt.Printf("outData: %x\n", outData)
	_, checkData, err := EncryptDataWithCredential(false,
		AlgTPM_ALG_SHA1, unmarshaled_credential,
		outData, calcHmac)
	if err != nil {
		t.Fatal("Could not encrypt data\n")
	}
	fmt.Printf("checkData: %x\n", checkData)
	if bytes.Compare(inData[0:64], checkData) != 0 {
		t.Fatal("input data and decrypt of encrypt don't match\n")
	}
}

func TestRsaTranslate(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil || key == nil {
		t.Fatal("Can't gen private key %s\n", err)
	}
	msg, err := MarshalRsaPrivateToProto(key)
	if err != nil {
		t.Fatal("Can't marshal key to proto\n")
	}
	newKey, err := UnmarshalRsaPrivateFromProto(msg)
	if err != nil {
		t.Fatal("Can't unmarshal key to proto\n")
	}
	// values equal?
	if key.D.Cmp(newKey.D) != 0 {
		t.Fatal("Keys are unequal\n")
	}
	fmt.Printf("TestRsaTranslate succeeds\n")
}

func TestRsaPrivateKeyParse(t *testing.T) {

	// use SerializeRsaPrivateKey(key *rsa.PrivateKey) ([]byte, error)
	// and DeserializeRsaKey(in []byte) (*rsa.PrivateKey, error)
	fileName := "./tmptest/cloudproxy_key_file.proto"
	out, err := ioutil.ReadFile(fileName)
	if out == nil || err != nil {
		t.Fatal("Can't retrieve file\n")
	}
	msg := new(RsaPrivateKeyMessage)
	err = proto.Unmarshal(out, msg)
	key, err := UnmarshalRsaPrivateFromProto(msg)
	if err != nil {
		t.Fatal("Can't unmarshal key to proto\n")
	}
	fmt.Printf("key: %x\n", key)
}

func TestAttributes(t *testing.T) {
	sealedObj := uint32(FlagFixedTPM | FlagFixedParent)
	if sealedObj != 0x12 {
		t.Fatal("sealed object flags wrong\n")
	}
	storageObj := uint32(FlagRestricted | FlagDecrypt | FlagUserWithAuth |
		FlagSensitiveDataOrigin | FlagFixedTPM | FlagFixedParent)
	if storageObj != 0x30072 {
		t.Fatal("storage object flags wrong\n")
	}
	signObj := uint32(FlagRestricted | FlagSign | FlagUserWithAuth |
		FlagSensitiveDataOrigin | FlagFixedTPM | FlagFixedParent)
	if signObj != 0x50072 {
		t.Fatal("storage object flags wrong\n")
	}
}

func TestSetShortPcrs(t *testing.T) {
	pcr_nums := []int{7, 8}
	pcr, err := SetShortPcrs(pcr_nums)
	if err != nil {
		t.Fatal("Test SetShortPcrs fails\n")
	}
	test_pcr := []byte{0x03, 0x80, 0x01, 0x00}
	if !bytes.Equal(test_pcr, pcr) {
		t.Fatal("Wrong pcr value\n")
	}
}

func TestSetHandle(t *testing.T) {
	hand := SetHandle(Handle(OrdTPM_RH_OWNER))
	if hand == nil {
		t.Fatal("Test SetHandle fails\n")
	}
	test_out := []byte{0x40, 0, 0, 1}
	if !bytes.Equal(test_out, hand) {
		t.Fatal("Test SetHandle bad output\n")
	}
}

func TestSetPasswordData(t *testing.T) {
	pw1 := SetPasswordData("01020304")
	test1 := []byte{0, 4, 1, 2, 3, 4}
	if pw1 == nil || !bytes.Equal(test1, pw1) {
		t.Fatal("Test Password 1 fails\n")
	}
	pw2 := SetPasswordData("0102030405")
	test2 := []byte{0, 5, 1, 2, 3, 4, 5}
	if pw2 == nil || !bytes.Equal(test2, pw2) {
		t.Fatal("Test Password 2 fails\n")
	}
}

func TestCreatePasswordAuthArea(t *testing.T) {
	pw_auth1 := CreatePasswordAuthArea("01020304", Handle(OrdTPM_RS_PW))
	test1 := []byte{0, 0xd, 0x40, 0, 0, 9, 0, 0, 1, 0, 4, 1, 2, 3, 4}
	if test1 == nil || !bytes.Equal(test1, pw_auth1) {
		t.Fatal("Test PasswordAuthArea 1 fails\n")
	}

	pw_auth2 := CreatePasswordAuthArea("", Handle(OrdTPM_RS_PW))
	test2 := []byte{0, 0x9, 0x40, 0, 0, 9, 0, 0, 1, 0, 0}
	if test2 == nil || !bytes.Equal(test1, pw_auth1) {
		t.Fatal("Test PasswordAuthArea 2 fails\n")
	}
	fmt.Printf("TestCreatePasswordAuthArea: %x\n", pw_auth1)
	fmt.Printf("TestCreatePasswordAuthArea: %x\n", pw_auth2)
}

func TestCreateSensitiveArea(t *testing.T) {
	a1 := []byte{1, 2, 3, 4}
	var a2 []byte
	s := CreateSensitiveArea(a1, a2)
	if s == nil {
		t.Fatal("CreateSensitiveArea fails")
	}
	test := []byte{0, 8, 0, 4, 1, 2, 3, 4, 0, 0}
	if !bytes.Equal(test, s) {
		t.Fatal("CreateSensitiveArea fails")
	}
	fmt.Printf("Sensitive area: %x\n", s)
}

func TestCreateRsaParams(t *testing.T) {
	var empty []byte
	parms := RsaParams{uint16(AlgTPM_ALG_RSA), uint16(AlgTPM_ALG_SHA1),
		uint32(0x00030072), empty, uint16(AlgTPM_ALG_AES), uint16(128),
		uint16(AlgTPM_ALG_CFB), uint16(AlgTPM_ALG_NULL), uint16(0),
		uint16(1024), uint32(0x00010001), empty}

	s := CreateRsaParams(parms)
	if s == nil {
		t.Fatal("CreateRsaParams fails")
	}
	fmt.Printf("RsaParams area: %x\n", s)
	/*
		test := []byte{0,6,0,0x80,0,0x43, 0, 0x10, 4,0,0,1,0,1,0,0}
		if !bytes.Equal(test, s) {
			t.Fatal("CreateRsaParams fails")
		}
	*/
}

func TestCreateLongPcr(t *testing.T) {
	s := CreateLongPcr(uint32(1), []int{7})
	test := []byte{0, 0, 0, 1, 0, 4, 3, 0x80, 0, 0}
	if !bytes.Equal(test, s) {
		t.Fatal("CreateRsaParams fails")
	}
}

func TestKDFa(t *testing.T) {
	key := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 23, 14, 15}
	out, err := KDFA(uint16(AlgTPM_ALG_SHA1), key, "IDENTITY", nil, nil, 256)
	if err != nil {
		t.Fatal("KDFa fails")
	}
	fmt.Printf("KDFA: %x\n", out)
}

func TestReadRsaBlob(t *testing.T) {
}

func TestCertificateParse(t *testing.T) {
	out, err := ioutil.ReadFile("./tmptest/endorsement_cert")
	if out == nil || err != nil {
		t.Fatal("Can't retrieve file\n")
	}

	cert, err := x509.ParseCertificate(out)
	if cert == nil || err != nil {
		fmt.Printf("Error: %s\n", err)
		t.Fatal("Can't parse retrieved cert\n")
	}
}

func TestPad(t *testing.T) {
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil || private == nil {
		t.Fatal("Can't gen private key %s\n", err)
	}
	public := &private.PublicKey
	var a [9]byte
	copy(a[0:8], "IDENTITY")

	seed := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	encrypted_secret, err := rsa.EncryptOAEP(sha1.New(), rand.Reader,
		public, seed, a[0:9])
	if err != nil {
		t.Fatal("Can't encrypt ", err)
	}
	fmt.Printf("encrypted_secret: %x\n", encrypted_secret)
	decrypted_secret, err := rsa.DecryptOAEP(sha1.New(), rand.Reader,
		private, encrypted_secret, a[0:9])
	if err != nil {
		t.Fatal("Can't decrypt ", err)
	}
	fmt.Printf("decrypted_secret: %x\n", decrypted_secret)
	var N *big.Int
	var D *big.Int
	var x *big.Int
	var z *big.Int
	N = public.N
	D = private.D
	x = new(big.Int)
	z = new(big.Int)
	x.SetBytes(encrypted_secret)
	z = z.Exp(x, D, N)
	decrypted_pad := z.Bytes()
	fmt.Printf("decrypted_pad   : %x\n", decrypted_pad)
}
