package tpm2_test

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/google/go-tpm/tpm2"
)

func TestEKSeal(t *testing.T) {
	testCases := []struct {
		name      string
		ekFile    string
		plainText string
		expErr    error
		options   []tpm2.EKSealOption
	}{
		{
			name:      "RSA",
			ekFile:    "./testdata/ek-rsa.bin",
			plainText: "Hello, world.",
		},
		{
			name:      "ECC",
			ekFile:    "./testdata/ek-ecc.bin",
			plainText: "Hello, world.",
		},
		{
			name:      "Exceeds MaxSymData",
			ekFile:    "./testdata/ek-rsa.bin",
			plainText: "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.Is129.",
			expErr:    fmt.Errorf("len(plainText)=129 > MaxSymData=128"),
		},
		{
			name:      "Exceeds MaxSymData and IgnoreMaxSymData",
			ekFile:    "./testdata/ek-rsa.bin",
			plainText: "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.Is129.",
			options:   []tpm2.EKSealOption{tpm2.EKSealIgnoreMaxSymData},
		},
	}

	for i := range testCases {
		tc := testCases[i]
		t.Run(tc.name, func(t *testing.T) {
			ekData, err := os.ReadFile(tc.ekFile)
			if err != nil {
				t.Fatalf("failed to read ek binary data")
			}
			ekTPM2BPublic, err := tpm2.Unmarshal[tpm2.TPM2BPublic](ekData)
			if err != nil {
				t.Fatalf("failed to load ek: %s", err)
			}
			ek, err := ekTPM2BPublic.Contents()
			if err != nil {
				t.Fatalf("failed to unbox ek: %s", err)
			}

			pub, priv, seed, err := tpm2.EKSeal(*ek, []byte(tc.plainText), tc.options...)
			if !assertExpectedError(t, true, err, tc.expErr) {
				return
			}
			ekSealTestPrintTrailingCommands(t, tc.name, pub, priv, seed)
		})
	}
}

func TestEKCertSeal(t *testing.T) {
	testCases := []struct {
		name      string
		pemFile   string
		plainText string
		expErr    error
		options   []tpm2.EKSealOption
	}{
		{
			name:      "RSA",
			pemFile:   "./testdata/ek-rsa-crt.pem",
			plainText: "Hello, world.",
		},
		{
			name:      "ECC",
			pemFile:   "./testdata/ek-ecc-crt.pem",
			plainText: "Hello, world.",
		},
		{
			name:      "Exceeds MaxSymData",
			pemFile:   "./testdata/ek-rsa-crt.pem",
			plainText: "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.Is129.",
			expErr:    fmt.Errorf("len(plainText)=129 > MaxSymData=128"),
		},
		{
			name:      "Exceeds MaxSymData and IgnoreMaxSymData",
			pemFile:   "./testdata/ek-rsa-crt.pem",
			plainText: "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.Is129.",
			options:   []tpm2.EKSealOption{tpm2.EKSealIgnoreMaxSymData},
		},
	}

	for i := range testCases {
		tc := testCases[i]
		t.Run(tc.name, func(t *testing.T) {
			pemData, err := os.ReadFile(tc.pemFile)
			if err != nil {
				t.Fatalf("failed to read ek pem data")
			}
			pemBlock, _ := pem.Decode([]byte(pemData))
			if pemBlock == nil {
				t.Fatalf("failed to decode ek pem data")
			}
			cert, err := x509.ParseCertificate(pemBlock.Bytes)
			if err != nil {
				t.Fatalf("failed to load ek cert: %s", err)
			}

			pub, priv, seed, err := tpm2.EKCertSeal(
				*cert,
				[]byte(tc.plainText),
				tc.options...,
			)
			if !assertExpectedError(t, true, err, tc.expErr) {
				return
			}
			ekSealTestPrintTrailingCommands(t, tc.name, pub, priv, seed)
		})
	}
}

func ekSealTestPrintTrailingCommands(
	t *testing.T,
	testCaseName string,
	pub tpm2.TPM2BPublic,
	priv tpm2.TPM2BPrivate,
	seed tpm2.TPM2BEncryptedSecret) {

	t.Logf("\n\n"+
		"# Copy the following line onto the system with the EK\n"+
		"# and use ../examples/tpm2-ekseal/tpm2-ekunseal.sh along with\n"+
		"# tpm2-tools to unseal the data.\n\n"+
		"  echo '%s@@NULL@@%s@@NULL@@%s' | unseal.sh -0 -G %s\n\n",
		base64.StdEncoding.EncodeToString(tpm2.Marshal(pub)),
		base64.StdEncoding.EncodeToString(tpm2.Marshal(priv)),
		base64.StdEncoding.EncodeToString(tpm2.Marshal(seed)),
		strings.ToLower(testCaseName))
}
