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
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/jlmucb/cloudproxy/go/tao"
	"github.com/jlmucb/cloudproxy/go/tpm2"
)

// This program makes the endorsement certificate given the Policy key.
func main() {
	// TODO(jlm): The assumption here is that the endorsement key is always an RSA key.
	// This is OK for now since TPM 1.2 can only have RSA keys and tao_tpm2 only supports
	// RSA keys but this should be specified by a flag.
	keySize := flag.Int("modulus_size", 2048, "Modulus size for keys")
	keyName := flag.String("endorsement_key_name",
		"JohnsHw", "endorsement key name")
	endorsementCertFile := flag.String("endorsement_save_file",
		"endorsement.cert.der", "endorsement save file")
	policyCertFile := flag.String("policy_cert_file",
		"policy.cert.go.der", "cert file")
	policyKeyFile := flag.String("policy_key_file", "policy.go.bin",
		"policy save file")
	// TODO(jlm): Should default be "xxx" below?
	policyKeyPassword := flag.String("policy_key_password", "xxx",
		"policy key password")
	// TODO(jlm): This should be policy key type.  Since we have a key file, we can actually tell
	//	without this flag.
	policyKeyIsEcdsa := flag.Bool("policy_key_is_ecdsa", false, "Whether the policy key is a ECDSA key")
	// TODO(jlm): Should this be "./policy_keys/"?
	policyKeyDir := flag.String("policy_key_dir", "./keys/", "Path to policy keys")
	flag.Parse()
	fmt.Printf("Policy key password: %s\n", *policyKeyPassword)

	// TODO(jlm): Should this be the pcr's measured by the tpm (17, 18) or should it be empty?
	// In any case, {7} is wrong.
	pcrs := []int{7}

	// Open tpm
	rw, err := tpm2.OpenTPM("/dev/tpm0")
	if err != nil {
		fmt.Printf("OpenTPM failed %s\n", err)
		return
	}
	defer rw.Close()

	// Flushall
	err = tpm2.Flushall(rw)
	if err != nil {
		fmt.Printf("Flushall failed\n")
		return
	}

	// TODO(jlm): Currently a year.  This should be specified in a flag witht the
	//	default being a year.
	var notBefore time.Time
	notBefore = time.Now()
	validFor := 365 * 24 * time.Hour
	notAfter := notBefore.Add(validFor)

	ekHandle, _, err := tpm2.CreateEndorsement(rw, uint16(*keySize), pcrs)
	if err != nil {
		fmt.Printf("Can't CreateEndorsement\n")
		return
	}
	defer tpm2.FlushContext(rw, ekHandle)

	var endorsementCert []byte
	if *policyKeyIsEcdsa {
		// Load keys from policyKeyDir if keys are present there.
		policyKey, err := tao.NewOnDiskPBEKeys(tao.Signing, []byte(*policyKeyPassword), *policyKeyDir, nil)
		if err != nil {
			fmt.Println("Error in getting policy cert: ", err)
			return
		}
		if policyKey.Cert == nil {
			fmt.Println("Missing cert in policy key.")
			return
		}
		hwPublic, err := tpm2.GetRsaKeyFromHandle(rw, ekHandle)
		if err != nil {
			fmt.Println("Can't get endorsement public key: ", err)
			return
		}
		// TODO(sidtelang): move this to tpm2/support.go
		serialNumber := tpm2.GetSerialNumber()
		fmt.Printf("Serial: %x\n", serialNumber)
		fmt.Printf("notBefore: %s, notAfter: %s\n", notBefore, notAfter)
		signTemplate := x509.Certificate{
			SerialNumber: serialNumber,
			Subject: pkix.Name{
				Organization: []string{*keyName},
				CommonName:   *keyName,
			},
			NotBefore:             notBefore,
			NotAfter:              notAfter,
			KeyUsage:              x509.KeyUsageCertSign,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
			// IsCA: false,
			IsCA: true,
		}
		endorsementCert, err = x509.CreateCertificate(rand.Reader, &signTemplate, policyKey.Cert,
			hwPublic, policyKey.SigningKey)
		if err != nil {
			fmt.Println("Can't create endorsement certificate: ", err)
			return
		}
	} else {
		serializePolicyKey, err := ioutil.ReadFile(*policyKeyFile)
		if err != nil {
			fmt.Printf("Can't get serialized policy key\n")
			return
		}
		derPolicyCert, err := ioutil.ReadFile(*policyCertFile)
		if err != nil {
			fmt.Printf("Can't get policy cert %s\n", *policyCertFile)
			return
		}

		policyKey, err := tpm2.DeserializeRsaKey(serializePolicyKey)
		if err != nil {
			fmt.Printf("Can't get deserialize policy key\n")
			return
		}
		endorsementCert, err = tpm2.GenerateHWCert(rw, ekHandle,
			*keyName, notBefore, notAfter, tpm2.GetSerialNumber(),
			derPolicyCert, policyKey)
		if err != nil {
			fmt.Printf("Can't create endorsement cert\n")
		}
	}
	fmt.Printf("Endorsement cert: %x\n", endorsementCert)
	ioutil.WriteFile(*endorsementCertFile, endorsementCert, 0644)
	fmt.Printf("Endorsement cert created")
}
