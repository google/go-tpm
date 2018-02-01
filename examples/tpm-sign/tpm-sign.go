// Copyright (c) 2018, Ian Haken. All rights reserved.
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
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"flag"
	"fmt"
	"os"

	"github.com/google/go-tpm/tpm"
)

var (
	ownerAuthEnvVar     = "TPM_OWNER_AUTH"
	srkAuthEnvVar       = "TPM_SRK_AUTH"
	usageAuthEnvVar     = "TPM_USAGE_AUTH"
	migrationAuthEnvVar = "TPM_MIGRATION_AUTH"
)

func main() {
	var tpmname = flag.String("tpm", "/dev/tpm0", "The path to the TPM device to use")
	flag.Parse()

	rwc, err := tpm.OpenTPM(*tpmname)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Couldn't open the TPM file %s: %s\n", *tpmname, err)
		return
	}
	defer rwc.Close()

	// Compute the auth values as needed.
	var ownerAuth [20]byte
	ownerInput := os.Getenv(ownerAuthEnvVar)
	if ownerInput != "" {
		oa := sha1.Sum([]byte(ownerInput))
		copy(ownerAuth[:], oa[:])
	}

	var srkAuth [20]byte
	srkInput := os.Getenv(srkAuthEnvVar)
	if srkInput != "" {
		sa := sha1.Sum([]byte(srkInput))
		copy(srkAuth[:], sa[:])
	}

	var usageAuth [20]byte
	usageInput := os.Getenv(usageAuthEnvVar)
	if usageInput != "" {
		ua := sha1.Sum([]byte(usageInput))
		copy(usageAuth[:], ua[:])
	}

	var migrationAuth [20]byte
	migrationInput := os.Getenv(migrationAuthEnvVar)
	if migrationInput != "" {
		ma := sha1.Sum([]byte(migrationInput))
		copy(migrationAuth[:], ma[:])
	}

	keyblob, err := tpm.CreateWrapKey(rwc, srkAuth[:], usageAuth, migrationAuth, []int{0, 1, 2, 3, 4, 16})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Couldn't make a new signing key: %s\n", err)
		return
	}
	fmt.Printf("Keyblob: %s\n", base64.StdEncoding.EncodeToString(keyblob))

	pubKey, err := tpm.UnmarshalRSAPublicKey(keyblob)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not get public key: %s\n", err)
		return
	}

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not marshal public key: %s\n", err)
		return
	}
	fmt.Printf("Public Key: %s\n", base64.StdEncoding.EncodeToString(pubKeyBytes))

	keyHandle, err := tpm.LoadKey2(rwc, keyblob, srkAuth[:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not load keyblob: %s\n", err)
		return
	}
	defer keyHandle.CloseKey(rwc)

	hashed := sha256.Sum256([]byte("Hello, World!"))
	signature, err := tpm.Sign(rwc, usageAuth[:], keyHandle, crypto.SHA256, hashed[:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not perform sign operation: %s\n", err)
		return
	}

	fmt.Printf("Signature: %s\n", base64.StdEncoding.EncodeToString(signature))

	if err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hashed[:], signature); err != nil {
		fmt.Fprintf(os.Stderr, "Error from verification: %s\n", err)
		return
	}
	fmt.Printf("Signature valid.\n")

	// Extend PCR 16.
	if _, err = tpm.PcrExtend(rwc, 16, sha1.Sum([]byte("xyz"))); err != nil {
		fmt.Fprintf(os.Stderr, "Error extending PCR: %s\n", err)
		return
	}
	if _, err = tpm.Sign(rwc, usageAuth[:], keyHandle, crypto.SHA256, hashed[:]); err == nil {
		fmt.Fprintf(os.Stderr, "Should have failed to sign with extended PCR.")
		return
	}
	if err = tpm.PcrReset(rwc, []int{16}); err != nil {
		fmt.Fprintf(os.Stderr, "Unable to reset PCR: %s\n", err)
		return
	}

	if _, err = tpm.Sign(rwc, usageAuth[:], keyHandle, crypto.SHA256, hashed[:]); err != nil {
		fmt.Fprintf(os.Stderr, "Unable to sign with PCR reset: %s\n", err)
		return
	}

	return
}
