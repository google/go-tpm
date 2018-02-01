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
	"flag"
	"fmt"
	"log"

	"github.com/jlmucb/cloudproxy/go/tao"
)

var (
	// TODO(jlm): The assumption here is that the endorsement key is always an RSA key.
	// This is OK for now since TPM 1.2 can only have RSA keys and tao_tpm2 only supports
	// RSA keys but this should be specified by a flag.
	keySize = flag.Int("modulus_size", 2048, "Modulus size for keys")
	keyName = flag.String("endorsement_key_name",
		"JohnsHw", "endorsement key name")
	endorsementCertFile = flag.String("endorsement_save_file",
		"endorsement.cert.der", "endorsement save file")
	policyCertFile = flag.String("policy_cert_file",
		"policy.cert.go.der", "cert file")
	policyKeyFile = flag.String("policy_key_file", "policy.go.bin",
		"policy save file")
	// TODO(jlm): Should default be "xxx" below?
	policyKeyPassword = flag.String("policy_key_password", "xxx",
		"policy key password")
	// TODO(jlm): Should this be "./policy_keys/"?
	policyKeyDir = flag.String("policy_key_dir", "./keys/", "Path to policy keys")
	// TODO(jlm): This should be policy key type.  Since we have a key file, we can actually tell
	//	without this flag.
	policyKeyIsEcdsa = flag.Bool("policy_key_is_ecdsa", false, "Whether the policy key is a ECDSA key")
)

// This program makes the endorsement certificate given the Policy key.
func main() {
	flag.Parse()
	fmt.Printf("Policy key password: %s\n", *policyKeyPassword)
	err := tao.HandleEndorsement(*keySize, *keyName, *endorsementCertFile, *policyCertFile,
		*policyKeyFile, *policyKeyPassword, *policyKeyDir, *policyKeyIsEcdsa)
	if err != nil {
		log.Fatal(err)
	}
}
