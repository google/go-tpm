module github.com/google/go-tpm/tpm2/transport/googlemtd

go 1.24.0

require (
	github.com/google/go-tpm v0.9.8
	github.com/google/go-tpm/tpm2/transport/googleec v0.0.0
)

require golang.org/x/sys v0.8.0 // indirect

replace (
	github.com/google/go-tpm => ../../../
	github.com/google/go-tpm/tpm2/transport/googleec => ../googleec
)
