// Binary tpm2-ekseal seals plain-text using a provided EK public area or
// certificate and emits a duplicated object that can only be unsealed on the
// system that has the provided EK.
package main

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/google/go-tpm/tpm2"
)

var (
	flagEKPub = flag.String(
		"ek-pub", "",
		"Path to the endorsement key's public area saved as a binary file.\n"+
			"May not be used with -ek-pem")

	flagEKPem = flag.String(
		"ek-pem", "",
		"Path to the endorsement key's public certificate.\n"+
			"May not be used with -ek-pub")

	flagPlainText = flag.String(
		"plain-text", "-",
		`Plain-text data. Defaults to STDIN via "-".`)

	flagOutFormat = flag.String(
		"f", "json",
		"Output format. Options are 'json', 'cmds', and '0'.\n"+
			"The format 'json' emits the encrypted data as a JSON object.\n"+
			"The format 'cmds' emits three shell commands that can be copied \n"+
			"and pasted into another system to easily create the encrypted\n"+
			"data's three parts as files.\n"+
			"The format '0' emits the encrypted data as base64-encoded\n"+
			"data structures delimited by @@NULL@@.\n"+
			"Both the 'cmds' and '0' formats may be used with unseal.sh on a\n"+
			"Linux system with tpm2-tools to unseal the data.",
	)
)

func main() {
	flag.Parse()

	var ek tpm2.TPMTPublic

	switch {
	case *flagEKPem != "" && *flagEKPub != "":
		fmt.Fprintln(os.Stderr, "-ek-pem and -ek-pub are mutually exclusive")
		os.Exit(1)
	case *flagEKPem != "":
		pemData, err := os.ReadFile(*flagEKPem)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to read ek pem data: %s", err)
			os.Exit(1)
		}
		pemBlock, _ := pem.Decode([]byte(pemData))
		if pemBlock == nil {
			fmt.Fprintln(os.Stderr, "failed to decode ek pem data")
			os.Exit(1)
		}
		cert, err := x509.ParseCertificate(pemBlock.Bytes)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to load ek cert %s", err)
			os.Exit(1)
		}
		if ek, err = tpm2.EKCertToTPMTPublic(*cert); err != nil {
			fmt.Fprintf(os.Stderr, "failed to load ek from cert %s", err)
			os.Exit(1)
		}
	case *flagEKPub != "":
		ekData, err := os.ReadFile(*flagEKPub)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to read ek binary data: %s", err)
			os.Exit(1)
		}
		ekTPM2BPublic, err := tpm2.Unmarshal[tpm2.TPM2BPublic](ekData)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to load ek: %s", err)
			os.Exit(1)
		}
		ekPtr, err := ekTPM2BPublic.Contents()
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to unbox ek: %s", err)
			os.Exit(1)
		}
		ek = *ekPtr
	}

	// Read the plain-text.
	var plainTextFile *os.File
	if *flagPlainText == "-" {
		plainTextFile = os.Stdin
	} else {
		f, err := os.Open(*flagPlainText)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to open input file: %s", err)
			os.Exit(1)
		}
		plainTextFile = f
		defer f.Close()
	}
	plainText, err := io.ReadAll(plainTextFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read input data: %s", err)
		os.Exit(1)
	}

	pub, priv, seed, err := tpm2.EKSeal(ek, plainText)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to seal plain-text: %s", err)
		os.Exit(1)
	}

	pubData, privData, seedData :=
		tpm2.Marshal(pub),
		tpm2.Marshal(priv),
		tpm2.Marshal(seed)

	switch *flagOutFormat {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(struct {
			Public  []byte `json:"public"`
			Private []byte `json:"private"`
			Seed    []byte `json:"seed"`
		}{
			Public:  pubData,
			Private: privData,
			Seed:    seedData,
		}); err != nil {
			fmt.Fprintf(os.Stderr, "failed to encode duped object: %s", err)
			os.Exit(1)
		}
	case "cmds":
		fmt.Printf("echo '%s' | base64 -d >enc.bin.pub;",
			base64.StdEncoding.EncodeToString(pubData))
		fmt.Printf("echo '%s' | base64 -d >enc.bin.priv;",
			base64.StdEncoding.EncodeToString(privData))
		fmt.Printf("echo '%s' | base64 -d >enc.bin.seed\n",
			base64.StdEncoding.EncodeToString(seedData))
	case "0":
		fmt.Printf("%s@@NULL@@%s@@NULL@@%s",
			base64.StdEncoding.EncodeToString(pubData),
			base64.StdEncoding.EncodeToString(privData),
			base64.StdEncoding.EncodeToString(seedData))
	}

}
