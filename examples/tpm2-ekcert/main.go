// Binary tpm2-ekcert reads an x509 certificate from a specific NVRAM index.
package main

import (
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"reflect"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

var (
	tpmPath = flag.String("tpm-path", "/dev/tpm0", "Path to the TPM device (character device or a Unix socket)")
	// Default value is defined in section 7.8, "NV Memory" of the latest version pdf on:
	// https://trustedcomputinggroup.org/resource/tcg-tpm-v2-0-provisioning-guidance/
	certIndex = flag.Uint("cert-index", 0x01C00002, "NVRAM index of the certificate file")
	tmplIndex = flag.Uint("template-index", 0x81010001, "NVRAM index of the EK template")
	outPath   = flag.String("output", "", "File path for output; leave blank to write to stdout")
)

func main() {
	flag.Parse()

	cert, err := readEKCert(*tpmPath, uint32(*certIndex), uint32(*tmplIndex))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if *outPath == "" {
		fmt.Println(string(cert))
		return
	}
	if err := ioutil.WriteFile(*outPath, cert, os.ModePerm); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func readEKCert(path string, certIdx, tmplIdx uint32) ([]byte, error) {
	rwc, err := tpm2.OpenTPM(path)
	if err != nil {
		return nil, fmt.Errorf("can't open TPM at %q: %v", path, err)
	}
	defer rwc.Close()
	ekCert, err := tpm2.NVRead(rwc, tpmutil.Handle(certIdx))
	if err != nil {
		return nil, fmt.Errorf("reading EK cert: %v", err)
	}
	// Sanity-check that this is a valid certificate.
	cert, err := x509.ParseCertificate(ekCert)
	if err != nil {
		return nil, fmt.Errorf("parsing EK cert: %v", err)
	}

	// Initialize EK and compare public key to ekCert.PublicKey.
	ekTemplate, err := tpm2.NVRead(rwc, tpmutil.Handle(tmplIdx))
	if err != nil {
		return nil, fmt.Errorf("reading EK template: %v", err)
	}
	ekh, ekPub, err := tpm2.CreatePrimaryRawTemplate(rwc, tpm2.HandleEndorsement, tpm2.PCRSelection{}, "", "", ekTemplate)
	if err != nil {
		return nil, fmt.Errorf("creating EK: %v", err)
	}
	defer tpm2.FlushContext(rwc, ekh)

	if !reflect.DeepEqual(ekPub, cert.PublicKey) {
		return nil, errors.New("public key in EK certificate differs from public key created via EK template")
	}

	return ekCert, nil
}
