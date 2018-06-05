// Binary tpm2-ekcert reads an x509 certificate from a specific NVRAM index.
package main

import (
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

var (
	tpmPath   = flag.String("tpm-path", "/dev/tpm0", "Path to the TPM device (character device or a Unix socket)")
	certIndex = flag.Uint("cert-index", 0, "NVRAM index of the certificate file")
	outPath   = flag.String("output", "", "File path for output. Leave blank to write to stdout.")
)

func main() {
	flag.Parse()

	if *certIndex == 0 {
		fmt.Fprintln(os.Stderr, "--cert-index must be set")
		os.Exit(2)
	}

	cert, err := readEKCert(*tpmPath, uint32(*certIndex))
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

func readEKCert(path string, idx uint32) ([]byte, error) {
	rwc, err := tpm2.OpenTPM(path)
	if err != nil {
		return nil, fmt.Errorf("can't open TPM at %q: %v", path, err)
	}
	defer rwc.Close()
	ekCert, err := tpm2.NVRead(rwc, tpmutil.Handle(idx))
	if err != nil {
		return nil, fmt.Errorf("reading EK cert: %v", err)
	}
	// Sanity-check that this is a valid certificate.
	if _, err := x509.ParseCertificate(ekCert); err != nil {
		return nil, fmt.Errorf("parsing EK cert: %v", err)
	}
	return ekCert, nil
}
