package tpmutil

import (
	"os"

	"golang.org/x/sys/unix"
)

// Poll blocks until the file descriptior is ready for reading or an error occurs.
func poll(f *os.File) error {
	const (
		events  = 0x001 // POLLIN
		timeout = -1    // TSS2_TCTI_TIMEOUT_BLOCK
	)
	pollfds := []unix.PollFd{
		{Fd: int32(f.Fd()), Events: events},
	}
	_, err := unix.Poll(pollfds, timeout)
	return err
}
