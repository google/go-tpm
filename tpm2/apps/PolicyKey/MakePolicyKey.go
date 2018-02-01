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
	"crypto/rsa"
	"flag"
	"fmt"
	"io/ioutil"
	"time"

	// "github.com/golang/protobuf/proto"
	"github.com/jlmucb/cloudproxy/go/tpm2"
)

// This program creates a key hierarchy consisting of a
// primary key, and quoting key for cloudproxy
// and makes their handles permanent.
func main() {
	// TODO(jlm): Policy key is always ECDSA for now but the key type should be
	// specified and we should support other types.
	keySize := flag.Int("modulus size",  2048, "Modulus size for keys")
	// TODO(jlm): The default value here is probably wrong.
	policyKeyFile := flag.String("Policy save file", "policy.go.bin",
		"policy save file")
	// TODO(jlm): Should this be "xxx" to be consistent with other examples?
	policyKeyPassword := flag.String("Policy key password", "xxx",
		"policy key password")
	// TODO(jlm): The default value here is probably wrong.
	policyCertFile := flag.String("Policy cert save file", "policy.cert.go.der",
		"policy cert save file")
	flag.Parse()

	// Open tpm
	rw, err := tpm2.OpenTPM("/dev/tpm0")
	if err != nil {
		fmt.Printf("OpenTPM failed %s\n", err)
		return
	}
	defer rw.Close()

	// Flushall
	err =  tpm2.Flushall(rw)
	if err != nil {
		fmt.Printf("Flushall failed\n")
		return
	}
	var notBefore time.Time
	notBefore = time.Now()
	validFor := 365*24*time.Hour
	notAfter := notBefore.Add(validFor)

	policyKey, err := rsa.GenerateKey(rand.Reader, *keySize)
	if err != nil {
		fmt.Printf("Can't generate policy key\n")
		return
	}
	fmt.Printf("policyKey: %x\n", policyKey)

	derPolicyCert, err := tpm2.GenerateSelfSignedCertFromKey(policyKey,
		"Cloudproxy Authority", "Application Policy Key",
		tpm2.GetSerialNumber(), notBefore, notAfter)
	fmt.Printf("policyKey: %x\n", policyKey)
	ioutil.WriteFile(*policyCertFile, derPolicyCert, 0644)
	if err != nil {
		fmt.Printf("Can't write policy cert\n")
		return
	}

	// Marshal policy key
	serializedPolicyKey, err := tpm2.SerializeRsaPrivateKey(policyKey)
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
}
