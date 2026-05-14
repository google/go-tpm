// Package templates contains binary-encoded TPMTPublic templates.
package templates

import (
	_ "embed"

	"github.com/google/go-tpm/tpm2"
)

//go:embed L1_EK.bin
var l1ek []byte

//go:embed L1_SRK.bin
var l1srk []byte

//go:embed L2_EK.bin
var l2ek []byte

//go:embed L2_SRK.bin
var l2srk []byte

var EKBytes = map[tpm2.Template][]byte{
	tpm2.TemplateL1: l1ek,
	tpm2.TemplateL2: l2ek,
}

var SRKBytes = map[tpm2.Template][]byte{
	tpm2.TemplateL1: l1srk,
	tpm2.TemplateL2: l2srk,
}
