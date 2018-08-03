# go-tpm usage examples

This directory contains binaries demonstrating usage of go-tpm.

## Versions

All directories that start with `tpm-` are for TPM 1.x devices.

All directories that start with `tpm2-` are for TPM 2.x devices.

They are not compatible. For example, running `tpm-sign` against a TPM 2.x
device will fail.
