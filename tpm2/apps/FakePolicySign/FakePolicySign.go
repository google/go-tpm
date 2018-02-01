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

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"io/ioutil"
	"math/big"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/jlmucb/cloudproxy/go/tpm2"
)

// This program reads the quote key, generates a policy key,
// self-signs the policy cert, readsa the quote key info and
// signs a cert for the quote key with the new policy key.
func main() {
	policyKeyFile := flag.String("policyKeyFile", "policy_private.bin",
		"policy save file")
	policyKeyPassword := flag.String("policyKeyPassword", "xxx",
		"policy key password")
	policyCertFile := flag.String("policyCertFile", "policy_cert.der",
		"policy cert save file")
	quoteKeyInfoFile := flag.String("quoteKeyInfoFile", "quoteinfo.der",
		"quote info file name")
	quoteCertFile := flag.String("quoteCertFile", "quote_cert.der",
		"quote cert save file")

	flag.Parse()

	// Generate Policy key.
	policyKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Printf("Can't generate policy key")
		return
	}
	fmt.Printf("policyKey: %x\n", policyKey)

	var notBefore time.Time
	notBefore = time.Now()
	validFor := 365 * 24 * time.Hour
	notAfter := notBefore.Add(validFor)

	// Self-sign policy key and save it.
	us := "US"
	issuerName := "PolicyAuthority"
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
		fmt.Printf("Can't self sign policy key\n")
		return
	}

	ioutil.WriteFile(*policyCertFile, derPolicyCert, 0644)
	if err != nil {
		fmt.Printf("Can't write policy cert\n")
		return
	}

	policyCert, err := x509.ParseCertificate(derPolicyCert)
	if err != nil {
		fmt.Printf("Can't parse policy cert\n")
		return
	}

	// Marshal policy key and save it.
	serializedPolicyKey, err := x509.MarshalECPrivateKey(policyKey)
	if err != nil {
		fmt.Printf("Cant serialize rsa key\n")
		return
	}

	ioutil.WriteFile(*policyKeyFile, serializedPolicyKey, 0644)
	if err == nil {
		fmt.Printf("Policy Key generation succeeded, password: %s\n",
			*policyKeyPassword)
	} else {
		fmt.Printf("Policy Key generation failed\n")
	}

	// Read request buffer
	buf, err := ioutil.ReadFile(*quoteKeyInfoFile)
	if err != nil {
		fmt.Printf("Can't read quote key info\n")
		return
	}
	var request tpm2.AttestCertRequest
	err = proto.Unmarshal(buf, &request)
	if err != nil {
		fmt.Printf("Can't unmarshal quote key info\n")
		return
	}

	// Should be an rsa key.
	if *request.KeyType != "rsa" {
		fmt.Printf("Quote key is not an rsa key\n")
		return
	}

	// Parse Der subject name.
	quoteKey, err := x509.ParsePKIXPublicKey(request.SubjectPublicKey)
	if err != nil {
		fmt.Printf("Can't parse quote key\n")
		return
	}

	// Sign quote certificate and save it.
	sn.SetUint64(2)
	localhost := "localhost"
	x509QuoteKeySubjectName := &pkix.Name{
		Organization:       []string{*request.KeyName},
		OrganizationalUnit: []string{*request.KeyName},
		CommonName:         localhost,
		Country:            []string{us},
	}
	quoteCertificateTemplate := x509.Certificate{
		SerialNumber: &sn,
		Issuer:       *x509SubjectName,
		Subject:      *x509QuoteKeySubjectName,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage: x509.KeyUsageCertSign |
			x509.KeyUsageKeyAgreement | x509.KeyUsageDigitalSignature,
	}
	derQuoteCert, err := x509.CreateCertificate(rand.Reader, &quoteCertificateTemplate,
		policyCert, quoteKey, priv)
	if err != nil {
		fmt.Printf("Can't self sign policy key\n")
		return
	}

	ioutil.WriteFile(*quoteCertFile, derQuoteCert, 0644)
	if err != nil {
		fmt.Printf("Can't write quote cert\n")
		return
	}
	fmt.Printf("Quote cert: %x\n", derQuoteCert)
}
