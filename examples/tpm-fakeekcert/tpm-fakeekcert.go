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
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"time"

	"github.com/google/go-tpm/tpm"
)

var (
	ownerAuthEnvVar = "TPM_OWNER_AUTH"

	tpmPath  = flag.String("tpm", "/dev/tpm0", "The path to the TPM device to use")
	certPath = flag.String("cert", "ek.der", "The path to write the EK out to")
	certOrg  = flag.String("cert_org", "Acme Co", "The organization string to use in the EKCert")
)

func generateCertificate(pub *rsa.PublicKey) ([]byte, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{*certOrg},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	return x509.CreateCertificate(rand.Reader, &template, &template, pub, priv)
}

func writePCCert(f io.Writer, der []byte) error {
	// Write the header as documented in: TCG PC Specific Implementation
	// Specification, section 7.3.2.
	if _, err := f.Write([]byte{0x10, 0x01, 0x00}); err != nil {
		return err
	}
	certLength := make([]byte, 2)
	binary.BigEndian.PutUint16(certLength, uint16(len(der)))
	if _, err := f.Write(certLength); err != nil {
		return err
	}

	_, err := f.Write(der)
	return err
}

func main() {
	flag.Parse()

	var ownerAuth [20]byte
	ownerInput := os.Getenv(ownerAuthEnvVar)
	if ownerInput != "" {
		oa := sha1.Sum([]byte(ownerInput))
		copy(ownerAuth[:], oa[:])
	}

	rwc, err := tpm.OpenTPM(*tpmPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Couldn't open the TPM at %q: %v\n", *tpmPath, err)
		return
	}

	pubEK, err := tpm.OwnerReadPubEK(rwc, ownerAuth)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Couldn't read the endorsement key: %v\n", err)
		return
	}
	pub, err := tpm.DecodePublic(pubEK)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Couldn't decode the endorsement key: %v\n", err)
		return
	}

	der, err := generateCertificate(pub.(*rsa.PublicKey))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Couldn't generate a certificate: %v\n", err)
		return
	}

	f, err := os.OpenFile(*certPath, os.O_RDWR|os.O_TRUNC|os.O_CREATE, 0744)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could open certificate path %q: %v\n", *certPath, err)
		return
	}
	defer func() {
		if err := f.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to close %q: %v\n", *certPath, err)
		}
	}()

	if err := writePCCert(f, der); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write certificate: %v\n", err)
		return
	}
}
