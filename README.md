Go-TPM
======

Go-TPM is a Go library that communicates directly with a TPM on Linux. It
marshals and unmarshals buffers directly into and from formats specified in the
TPM spec. This code is under active development; the current version only
supports Seal and Unseal operations over PCR 17 with a well-known secret.

To get the code, run

  go get github.com/google/go-tpm
