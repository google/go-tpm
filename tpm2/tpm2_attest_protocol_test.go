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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"testing"
	"time"
)

func TestAttestProtocol(t *testing.T) {
	rw, err := OpenTPM("/dev/tpm0")
	if err != nil {
		t.Fatal("Can't open tpm")
	}
	defer rw.Close()

	policyKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("Can't generate policy key")
	}

	notBefore := time.Now()
	validFor := 365 * 24 * time.Hour
	notAfter := notBefore.Add(validFor)

	us := "US"
	issuerName := "CloudProxyPolicy"
	x509SubjectName := &pkix.Name{
		Organization:       []string{issuerName},
		OrganizationalUnit: []string{issuerName},
		CommonName:         issuerName,
		Country:            []string{us},
	}
	var sn big.Int
	sn.SetUint64(1)
	certificateTemplate := x509.Certificate{
		SerialNumber: &sn,
		Issuer:       *x509SubjectName,
		Subject:      *x509SubjectName,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage: x509.KeyUsageCertSign |
			x509.KeyUsageKeyAgreement | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA: true,
	}

	var priv interface{}
	var pub interface{}
	priv = policyKey
	pub = policyKey.Public()
	derPolicyCert, err := x509.CreateCertificate(rand.Reader, &certificateTemplate,
		&certificateTemplate, pub, priv)
	if err != nil {
		t.Fatal("Can't self sign policy key ", err)
	}
	pcrs := []int{7}

	policyCert, err := x509.ParseCertificate(derPolicyCert)
	if err != nil {
		t.Fatal("Can't parse policy cert")
	}

	rootHandle, quoteHandle, storageHandle, err := CreateTpm2KeyHierarchy(rw, pcrs,
		2048, uint16(AlgTPM_ALG_SHA1), "01020304")
	if err != nil {
		t.Fatal("Can't create keys")
	}
	FlushContext(rw, storageHandle)
	FlushContext(rw, rootHandle)
	defer FlushContext(rw, quoteHandle)

	ekHandle, _, err := CreateEndorsement(rw, 2048, []int{7})
	if err != nil {
		t.Fatal("Can't create endorsement cert")
	}
	defer FlushContext(rw, ekHandle)

	ekPublicKey, err := GetRsaKeyFromHandle(rw, ekHandle)
	if err != nil {
		t.Fatal("Can't Create endorsement public key")
	}
	ekSubjectName := &pkix.Name{
		Organization:       []string{"Endorsement"},
		OrganizationalUnit: []string{"Endorsement"},
		CommonName:         "Endorsement",
		Country:            []string{us},
	}
	sn.SetUint64(2)
	ekTemplate := x509.Certificate{
		SerialNumber: &sn,
		Issuer:       *x509SubjectName,
		Subject:      *ekSubjectName,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage: x509.KeyUsageCertSign |
			x509.KeyUsageKeyAgreement | x509.KeyUsageDigitalSignature,
	}
	derEndorsementCert, err := x509.CreateCertificate(rand.Reader,
		&ekTemplate, policyCert, ekPublicKey, policyKey)
	if err != nil {
		t.Fatal("Can't sign endorsement key")
	}

	// Todo: make taoname
	taoName := "MachineCert"

	request, err := BuildAttestCertRequest(rw, quoteHandle, ekHandle, derEndorsementCert,
		taoName, "01020304")
	if err != nil {
		t.Fatal("Can't BuildAttestCertRequest")
	}

	response, err := ProcessQuoteDomainRequest(*request, policyKey, derPolicyCert)
	if err != nil {
		t.Fatal("Can't ProcessQuoteDomainRequest")
	}

	cert, err := GetCertFromAttestResponse(rw, quoteHandle, ekHandle, "01020304", *response)
	if err != nil {
		t.Fatal("Can't GetCertFromAttestResponse")
	}
	fmt.Printf("\nCert: %x\n", cert)
}
