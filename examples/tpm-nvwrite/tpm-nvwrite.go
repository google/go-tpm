// Copyright (c) 2019, Google LLC All rights reserved.
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

package main

import (
	"crypto/sha1"
	"flag"
	"fmt"
	"os"

	"github.com/google/go-tpm/tpm"
)

const ekCertIndex = 268496896

var (
	ownerAuthEnvVar = "TPM_OWNER_AUTH"

	tpmPath     = flag.String("tpm", "/dev/tpm0", "The path to the TPM device to use")
	index       = flag.Uint("index", ekCertIndex, "NV index to write to")
	defineSpace = flag.Bool("define_space", false, "Whether to define the region in NVRAM")
)

func main() {
	flag.Parse()

	rwc, err := tpm.OpenTPM(*tpmPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Couldn't open the TPM file %s: %s\n", *tpmPath, err)
		return
	}

	var ownerAuth [20]byte
	ownerInput := os.Getenv(ownerAuthEnvVar)
	if ownerInput != "" {
		oa := sha1.Sum([]byte(ownerInput))
		copy(ownerAuth[:], oa[:])
	}

	if *defineSpace {
		if err := tpm.NVDefineSpace(rwc, &tpm.NVPublicDescription{Index: uint32(*index)}, ownerAuth); err != nil {
			fmt.Fprintf(os.Stderr, "NVDefineSpace failed: %v\n", err)
			return
		}
	}
}
