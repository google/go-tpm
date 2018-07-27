package tbs

import (
	"os"
	"testing"
)

func getContext(t *testing.T) Context {
	ctx, err := CreateContext(TPMVersion20, IncludeTPM12|IncludeTPM20)
	if err != nil {
		t.Fatalf("Could not get tbs.Context: %v", err)
	}
	return ctx
}

// Get the log by passing in progressivly larger buffers
func TestGetLogLargeBuffer(t *testing.T) {
	ctx := getContext(t)
	defer ctx.Close()

	log := make([]byte, os.Getpagesize())
	for {
		logLen, err := ctx.GetTCGLog(log)
		if err == nil {
			if logLen == 0 {
				t.Fatalf("Expected positive TCGLog length")
			}
			return
		}
		if err != ErrInsufficientBuffer {
			t.Fatalf("GetTCGLog failed: err = %v", err)
		}
		log = append(log, make([]byte, len(log))...)
	}
}

// Get the log by passing in nil, checking the size, and then getting the log.
func TestGetLogWithNilSlice(t *testing.T) {
	ctx := getContext(t)
	defer ctx.Close()

	logLen, err := ctx.GetTCGLog(nil)
	if err != ErrInsufficientBuffer {
		t.Fatalf("First GetTCGLog failed: err = %v", err)
	}
	if logLen == 0 {
		t.Fatalf("Expected positive TCGLog length")
	}

	log := make([]byte, logLen)
	if _, err := ctx.GetTCGLog(log); err != nil {
		t.Fatalf("Second GetTCGLog failed: err = %v", err)
	}
}
