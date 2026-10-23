module github.com/google/go-tpm/tpm2/transport/googleipmi

go 1.24.0

require (
	github.com/google/go-tpm v0.9.8
	github.com/google/go-tpm/tpm2/transport/googleec v0.0.0
	github.com/u-root/u-root v0.16.0
)

require (
	github.com/vtolstov/go-ioctl v0.0.0-20151206205506-6be9cced4810 // indirect
	golang.org/x/sys v0.41.0 // indirect
)

replace (
	github.com/google/go-tpm => ../../../
	github.com/google/go-tpm/tpm2/transport/googleec => ../googleec
)
