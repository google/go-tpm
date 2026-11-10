//go:build !windows

// Package googlemtd provides functions for connecting to and initializing a
// Titan TPM MTD device.
package googlemtd

import (
	"context"
	"fmt"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/googleec"
)

const (
	ecTitanSendSendTPMCommand uint16 = 0x3e33
)

// titanTPM implements go-tpm's transport.TPM interface, for transmitting TPM
// commands to a Titan TPM using EC-over-MTD.
type titanTPM struct {
	cd googleec.CommandDispatcher
}

// Send implements the transport.TPM interface.
func (t *titanTPM) Send(input []byte) ([]byte, error) {
	ctx := context.Background()
	rsp, err := googleec.SendCommand(ctx, t.cd, googleec.Command{Code: ecTitanSendSendTPMCommand, Version: 0}, input)
	if err != nil {
		return nil, err
	}
	return rsp, nil
}

// Close closes the connection to the TPM.
func (t *titanTPM) Close() error {
	return t.cd.Close()
}

// Open creates a TPM connection to a Titan device via MTD.
func Open(opts Options) (transport.TPMCloser, error) {
	titan, err := NewDispatcher(opts)
	if err != nil {
		return nil, fmt.Errorf("[MTD TPM] err: %v", err)
	}
	return &titanTPM{
		cd: titan,
	}, nil
}
