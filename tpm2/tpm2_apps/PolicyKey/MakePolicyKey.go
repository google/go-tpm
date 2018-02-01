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
	"log"

	"github.com/jlmucb/cloudproxy/go/tao"
)

var (
	// TODO(jlm): Policy key is always ECDSA for now but the key type should be
	// specified and we should support other types.
	keySize = flag.Int("modulus size", 2048, "Modulus size for keys")
	// TODO(jlm): The default value here is probably wrong.
	policyKeyFile = flag.String("Policy save file", "policy.go.bin",
		"policy save file")
	// TODO(jlm): Should this be "xxx" to be consistent with other examples?
	policyKeyPassword = flag.String("Policy key password", "xxx",
		"policy key password")
	// TODO(jlm): The default value here is probably wrong.
	policyCertFile = flag.String("Policy cert save file", "policy.cert.go.der",
		"policy cert save file")
)

// This program creates a key hierarchy consisting of a
// primary key, and quoting key for cloudproxy
// and makes their handles permanent.
func main() {
	flag.Parse()
	err := tao.HandlePolicyKey(*keySize, *policyKeyFile, *policyKeyPassword, *policyCertFile)
	if err != nil {
		log.Fatal(err)
	}
}
