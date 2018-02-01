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

	"github.com/jlmucb/cloudproxy/go/tpm2"
)

// This program creates a key hierarchy consisting of a
// primary key, and quoting key for cloudproxy and saves the context.
func main() {
	keySize := flag.Int("modulusSize",  2048, "Modulus size for keys")
	rootContextFileName := flag.String("rootContextFile",  "rootContext.bin",
		"Root context file")
	quoteContextFileName := flag.String("quoteContextFile",
		"quoteContext.bin", "Quote context file")
	storeContextFileName := flag.String("storeContextFile",
		"storeContext.bin", "Store context file")
	pcrList := flag.String("pcrList",  "7", "Pcr list")
	flag.Parse()

	fmt.Printf("Pcr list: %s\n", *pcrList)

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

	pcrs, err := tpm2.StringToIntList(*pcrList)
	if err != nil {
		fmt.Printf("Can't format pcr list\n")
		return
	}

	err = tpm2.InitTpm2KeysandContexts(rw, pcrs, uint16(*keySize),
		uint16(tpm2.AlgTPM_ALG_SHA1), "", *rootContextFileName,
                *quoteContextFileName, *storeContextFileName)
	if err == nil {
		fmt.Printf("Key creation succeeded\n")
	} else {
		fmt.Printf("Key creation failed\n")
	}
	return
}
