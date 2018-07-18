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

// Command tpm2-readpcr outputs the value of a PCR in hex.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/google/go-tpm/tpm2"
)

var (
	tpmPath = flag.String("tpm-path", "/dev/tpm0", "Path to the TPM device (character device or a Unix socket).")
	pcr     = flag.Int("pcr", 0, "PCR to read. Must be within [0, 23].")
)

func main() {
	flag.Parse()
	var errors []error
	readpcr(&errors)
	for _, err := range errors {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
	}
	if len(errors) > 0 {
		os.Exit(1)
	}
}

func readpcr(errors *[]error) {
	if *pcr < 0 || *pcr > 23 {
		*errors = append(
			*errors, fmt.Errorf("invalid flag 'pcr': %d is out of range", *pcr))
		return
	}

	rwc, err := tpm2.OpenTPM(*tpmPath)
	if err != nil {
		*errors = append(*errors, fmt.Errorf("can't open TPM %q: %v", *tpmPath, err))
		return
	}
	defer func() {
		if err := rwc.Close(); err != nil {
			*errors = append(
				*errors, fmt.Errorf("unable to close connection to TPM: %v", err))
		}
	}()

	pcrValues, err := tpm2.ReadPCRs(
		rwc,
		tpm2.PCRSelection{
			Hash: tpm2.AlgSHA256,
			PCRs: []int{*pcr},
		})
	if err != nil {
		*errors = append(*errors, fmt.Errorf("unable to read PCRs from TPM: %v\n", err))
		return
	}

	val, present := pcrValues[*pcr]
	if !present {
		*errors = append(*errors, fmt.Errorf("PCR value missing from response.\n"))
		return
	}
	fmt.Printf("%x\n", val)
}
