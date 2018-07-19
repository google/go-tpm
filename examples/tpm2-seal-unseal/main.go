// Copyright (c) 2018, Google Inc. All rights reserved.
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

// Command tpm2-seal-unseal illustrates utilizing the TPM2 API to seal and unseal data.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

var (
	// Default EK template defined in:
	// https://trustedcomputinggroup.org/wp-content/uploads/Credential_Profile_EK_V2.0_R14_published.pdf
	// Shared SRK template based off of EK template and specified in:
	// https://trustedcomputinggroup.org/wp-content/uploads/TCG-TPM-v2.0-Provisioning-Guidance-Published-v1r1.pdf
	srkTemplate = tpm2.Public{
		Type:       tpm2.AlgRSA,
		NameAlg:    tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin | tpm2.FlagUserWithAuth | tpm2.FlagRestricted | tpm2.FlagDecrypt | tpm2.FlagNoDA,
		AuthPolicy: nil,
		RSAParameters: &tpm2.RSAParams{
			Symmetric: &tpm2.SymScheme{
				Alg:     tpm2.AlgAES,
				KeyBits: 128,
				Mode:    tpm2.AlgCFB,
			},
			KeyBits:    2048,
			Exponent:   0,
			ModulusRaw: make([]byte, 256),
		},
	}
)

func main() {
	tpmPathFlag := flag.String("tpm-path", "/dev/tpm0", "Path to the TPM device (character device or a Unix socket).")
	pcrFlag := flag.Int("pcr", -1, "PCR to seal data to. Must be within [0, 23].")
	flag.Parse()

	if *pcrFlag < 0 || *pcrFlag > 23 {
		fmt.Fprintf(os.Stderr, "Invalid flag 'pcr': value %d is out of range", *pcrFlag)
		os.Exit(1)
	}

	errs := run(*pcrFlag, *tpmPathFlag)
	for _, err := range errs {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
	}
	if len(errs) > 0 {
		os.Exit(1)
	}
}

func run(pcr int, tpmPath string) (errs []error) {
	// Open the TPM
	rwc, err := tpm2.OpenTPM(tpmPath)
	if err != nil {
		return append(errs, fmt.Errorf("can't open TPM %q: %v", tpmPath, err))
	}
	defer func() {
		if err := rwc.Close(); err != nil {
			errs = append(errs, fmt.Errorf("can't close TPM %q: %v", tpmPath, err))
		}
	}()

	// Create the parent key against which to seal the data
	srkPassword := ""
	srkHandle, _, err := tpm2.CreatePrimary(rwc, tpm2.HandleOwner, tpm2.PCRSelection{}, "", srkPassword, srkTemplate)
	if err != nil {
		return append(errs, fmt.Errorf("can't create primary key: %v", err))
	}
	defer func() {
		if err := tpm2.FlushContext(rwc, srkHandle); err != nil {
			errs = append(errs, fmt.Errorf("unable to flush SRK handle %q: %v", srkHandle, err))
		}
	}()
	fmt.Printf("Created parent key with handle: 0x%x\n", srkHandle)

	// Note the value of the pcr against which we will seal the data
	pcrVal, err := readPCR(rwc, pcr)
	if err != nil {
		return append(errs, fmt.Errorf("unable to read PCR: %v", err))
	}
	fmt.Printf("PCR %v value: 0x%x\n", pcr, pcrVal)

	// Get the authorization policy that will protect the data to be sealed
	objectPassword := "objectPassword"
	sessHandle, policy, err := policyPCRPasswordSession(rwc, pcr, objectPassword)
	if sessHandle != tpm2.HandleNull {
		if flushErr := tpm2.FlushContext(rwc, sessHandle); flushErr != nil {
			errs = append(errs, fmt.Errorf("unable to flush session: %v", flushErr))
		} else {
			sessHandle = tpm2.HandleNull
		}
	}
	if err != nil {
		errs = append(errs, fmt.Errorf("unable to get policy: %v", err))
	}
	if len(errs) > 0 {
		return
	}
	fmt.Printf("Created authorization policy: 0x%x\n", policy)

	// Seal the data to the parent key and the policy
	dataToSeal := []byte("secret")
	fmt.Printf("Data to be sealed: 0x%x\n", dataToSeal)
	privateArea, publicArea, err := tpm2.Seal(rwc, srkHandle, srkPassword, objectPassword, policy, dataToSeal)
	if err != nil {
		return append(errs, fmt.Errorf("unable to seal data: %v", err))
	}
	fmt.Printf("Sealed data: 0x%x\n", privateArea)

	// Load the sealed data into the TPM.
	objectHandle, _, err := tpm2.Load(rwc, srkHandle, srkPassword, publicArea, privateArea)
	if err != nil {
		return append(errs, fmt.Errorf("unable to load data: %v", err))
	}
	defer func() {
		if err := tpm2.FlushContext(rwc, objectHandle); err != nil {
			errs = append(errs, fmt.Errorf("unable to flush object handle %q: %v", objectHandle, err))
		}
	}()
	fmt.Printf("Loaded sealed data with handle: 0x%x\n", objectHandle)

	// Unseal the data
	unsealedData, unsealErr, otherErrs := unseal(rwc, pcr, objectPassword, objectHandle)
	if unsealErr != nil {
		errs = append(errs, fmt.Errorf("unable to unseal data: %v", unsealErr))
	}
	for otherErr := range otherErrs {
		errs = append(errs, fmt.Errorf("error while unsealing data: %v", otherErr))
	}
	if len(errs) > 0 {
		return
	}
	fmt.Printf("Unsealed data: 0x%x\n", unsealedData)

	// Try to unseal the data with the wrong password
	_, unsealErr, otherErrs = unseal(rwc, pcr, "wrong-password", objectHandle)
	if unsealErr == nil && len(otherErrs) == 0 {
		errs = append(errs, fmt.Errorf("expected unsealing with wrong password to fail but it succeeded"))
	}
	for otherErr := range otherErrs {
		errs = append(errs, fmt.Errorf("error while unsealing data: %v", otherErr))
	}
	if len(errs) > 0 {
		return
	}
	// Note that this can be easily fooled since we don't verify that the error was
	// due specifically to policy.
	fmt.Printf("As expected, unsealing with the wrong password failed with an error. Error was: %v\n", unsealErr)

	// Extend the PCR
	if err = tpm2.PCREvent(rwc, tpmutil.Handle(pcr), []byte{1}); err != nil {
		return append(errs, fmt.Errorf("unable to extend PCR: %v", err))
	}
	fmt.Printf("Extended PCR %d\n", pcr)

	// Note the new value of the pcr
	pcrVal, err = readPCR(rwc, pcr)
	if err != nil {
		return append(errs, fmt.Errorf("unable to read PCR: %v", err))
	}
	fmt.Printf("PCR %d value: 0x%x\n", pcr, pcrVal)

	// Try to unseal the data with the PCR in the wrong state
	_, unsealErr, otherErrs = unseal(rwc, pcr, objectPassword, objectHandle)
	if unsealErr == nil && len(otherErrs) == 0 {
		errs = append(errs, fmt.Errorf("expected unsealing with wrong PCR state to fail but it succeeded"))
	}
	for otherErr := range otherErrs {
		errs = append(errs, fmt.Errorf("error while unsealing data: %v", otherErr))
	}
	if len(errs) > 0 {
		return
	}
	// Note that this can be easily fooled since we don't verify that the error was
	// due specifically to policy.
	fmt.Printf("As expected, unsealing after extending the PCR failed with an error. Error was: %v\n", unsealErr)

	return
}

// Returns the unsealed data, any error due to the Unseal command, and any other errors
func unseal(rwc io.ReadWriteCloser, pcr int, objectPassword string, objectHandle tpmutil.Handle) (data []byte, unsealErr error, otherErrs []error) {
	// Create the authorization session
	sessHandle, _, err := policyPCRPasswordSession(rwc, pcr, objectPassword)
	defer func() {
		if sessHandle != tpm2.HandleNull {
			if flushErr := tpm2.FlushContext(rwc, sessHandle); flushErr != nil {
				otherErrs = append(otherErrs, fmt.Errorf("unable to flush session: %v", flushErr))
			}
		}
	}()
	if err != nil {
		otherErrs = append(otherErrs, fmt.Errorf("unable to get auth session: %v", err))
		return
	}

	// Unseal the data
	unsealedData, err := tpm2.UnsealWithSession(rwc, sessHandle, objectHandle, objectPassword)
	if err != nil {
		unsealErr = fmt.Errorf("unable to unseal data: %v", err)
		return
	}
	data = unsealedData
	return
}

// Note that the handle may be returned even if an error is returned as well, in which
// case it still needs to be flushed.
// Returns session handle and policy digest.
func policyPCRPasswordSession(rwc io.ReadWriteCloser, pcr int, password string) (tpmutil.Handle, []byte, error) {
	// FYI, this is not a very secure session.
	sessHandle, _, err := tpm2.StartAuthSession(
		rwc,
		tpm2.HandleNull,                                        /*tpmKey*/
		tpm2.HandleNull,                                        /*bindKey*/
		[]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, /*nonceCaller*/
		nil, /*secret*/
		tpm2.SessionPolicy,
		tpm2.AlgNull,
		tpm2.AlgSHA256)
	if err != nil {
		return tpm2.HandleNull, nil, fmt.Errorf("unable to start session: %v", err)
	}

	pcrSelection := tpm2.PCRSelection{
		Hash: tpm2.AlgSHA256,
		PCRs: []int{pcr},
	}

	// An empty expected digest means that digest verification is skipped.
	err = tpm2.PolicyPCR(rwc, sessHandle, nil /*expectedDigest*/, pcrSelection)
	if err != nil {
		return sessHandle, nil, fmt.Errorf("unable to bind PCRs to auth policy: %v", err)
	}

	err = tpm2.PolicyPassword(rwc, sessHandle)
	if err != nil {
		return sessHandle, nil, fmt.Errorf("unable to require password for auth policy: %v", err)
	}

	policy, err := tpm2.PolicyGetDigest(rwc, sessHandle)
	if err != nil {
		return sessHandle, nil, fmt.Errorf("unable to get policy digest: %v", err)
	}
	return sessHandle, policy, nil
}

func readPCR(rwc io.ReadWriteCloser, pcr int) ([]byte, error) {
	pcrSelection := tpm2.PCRSelection{
		Hash: tpm2.AlgSHA256,
		PCRs: []int{pcr},
	}
	pcrVals, err := tpm2.ReadPCRs(rwc, pcrSelection)
	if err != nil {
		return nil, fmt.Errorf("unable to read PCRs from TPM: %v", err)
	}
	pcrVal, present := pcrVals[pcr]
	if !present {
		return nil, fmt.Errorf("PCR %d value missing from response", pcr)
	}
	return pcrVal, nil
}
