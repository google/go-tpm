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

// Command tpm2-extendpcr extends a pcr with some data.
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

var (
	tpmPath = flag.String("tpm-path", "/dev/tpm0", "Path to the TPM device (character device or a Unix socket).")
	pcr     = flag.Int("pcr", -1, "PCR to read. Must be within [0, 23].")
	data    = flag.String("data", "", "The hex encoded bytes with which to extend the PCR. Must not exceed 1024 bytes.")
)

func main() {
	flag.Parse()
	var errors []error
	seal(&errors)
	for _, err := range errors {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
	}
	if len(errors) > 0 {
		os.Exit(1)
	}
}

func seal(errors *[]error) {
	if *pcr < 0 || *pcr > 23 {
		*errors = append(
			*errors, fmt.Errorf("invalid flag 'pcr': %d is out of range", *pcr))
		return
	}

	dataBytes, err := hex.DecodeString(*data)
	if err != nil {
		*errors = append(*errors, fmt.Errorf("invalid flag 'data': %v", err))
		return
	}
	if len(dataBytes) > 1024 {
		*errors = append(
			*errors, fmt.Errorf("the data flag value must not exceed 1024 bytes."))
		return
	}

	rwc, err := tpm2.OpenTPM(*tpmPath)
	if err != nil {
		*errors = append(*errors, fmt.Errorf("can't open TPM at %q: %v", *tpmPath, err))
		return
	}
	defer func() {
		if err := rwc.Close(); err != nil {
			*errors = append(
				*errors, fmt.Errorf("unable to close connection to TPM: %v", err))
		}
	}()

	if err = tpm2.PCREvent(rwc, tpmutil.Handle(uint32(*pcr)), dataBytes); err != nil {
		*errors = append(*errors, fmt.Errorf("unable to extend PCR: %v", err))
		return
	}
}
