// +build linux darwin

package tpmutil

import (
	"fmt"
	"os"
	"syscall"
	"time"
	"unsafe"
)

type pollFD struct {
	fd      int32
	events  int16
	revents int16
}

const pollNoTimeout = -1

// poll blocks until the file descriptior is ready for reading or an error occurs.
func poll(f *os.File, timeout time.Duration) error {
	var (
		fd = &pollFD{
			fd:     int32(f.Fd()),
			events: 0x1, // POLLIN
		}
		numFD     = 1
		timeoutMS int
	)
	// Convert timeout into milliseconds int (or keep -1 for no timeout).
	if timeout == pollNoTimeout {
		timeoutMS = pollNoTimeout
	} else {
		timeoutMS = int(timeout / time.Millisecond)
	}
	_, _, errno := syscall.Syscall(syscall.SYS_POLL, uintptr(unsafe.Pointer(fd)), uintptr(numFD), uintptr(timeoutMS))
	// Convert errno into an error, otherwise err != nil checks up the stack
	// will hit unexpectedly on 0 errno.
	var err error
	if errno != 0 {
		err = errno
		return err
	}
	// revents is filled in by the kernel.
	// If nothing happened and we had a timeout set, the there's no data
	// available to read still.
	if fd.revents == 0 && timeout > 0 {
		return fmt.Errorf("poll timed out")
	}
	// If the expected event happened, revents should match events.
	if fd.revents != fd.events {
		return fmt.Errorf("unexpected poll revents 0x%x", fd.revents)
	}
	return nil
}
