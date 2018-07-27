package tbs

import (
	"bytes"
	"os"
	"testing"
)


var (
	// Encodes a call to Getrandom with a length of 0
	encodedCommand = []byte{128, 1, 0, 0, 0, 12, 0, 0, 1, 123, 0, 0}
	// Expected response buffer for the above command
	expectedResponse = []byte{128, 1, 0, 0, 0, 12, 0, 0, 0, 0, 0, 0}
)

func getContext(t *testing.T) Context {
	ctx, err := CreateContext(TPMVersion20, IncludeTPM12|IncludeTPM20)
	if err != nil {
		t.Skipf("Skipping test as we couldn't access the TPM: %v", err)
	}
	return ctx
}

// Get the log by passing in progressively larger buffers
func TestGetLogLargeBuffer(t *testing.T) {
	ctx := getContext(t)
	defer ctx.Close()

	log := make([]byte, os.Getpagesize())
	for {
		logLen, err := ctx.GetTCGLog(log)
		if err == nil {
			if logLen == 0 {
				t.Fatal("Expected positive TCGLog length")
			}
			return
		}
		if err != ErrInsufficientBuffer {
			t.Fatalf("GetTCGLog failed: err = %v", err)
		}
		log = make([]byte, 2*len(log))
	}
}

// Get the log by passing in nil, checking the size, and then getting the log.
func TestGetLogWithNilSlice(t *testing.T) {
	ctx := getContext(t)
	defer ctx.Close()

	logLen, err := ctx.GetTCGLog(nil)
	if err != nil {
		t.Fatalf("First GetTCGLog failed: err = %v", err)
	}
	if logLen == 0 {
		t.Fatal("Expected positive TCGLog length")
	}

	log := make([]byte, logLen)
	if _, err := ctx.GetTCGLog(log); err != nil {
		t.Fatalf("Second GetTCGLog failed: err = %v", err)
	}
}

// Make sure SubmitCommand can handle a nil command buffer.
func TestSubmitCommandNilCommand(t *testing.T) {
	ctx := getContext(t)
	defer ctx.Close()

	response := make([]byte, os.Getpagesize())
	_, err := ctx.SubmitCommand(NormalPriority, nil, response)
	if err != ErrBadParameter {
		t.Fatalf("Expected ErrBadParameter from Submit Command: got %v", err)
	}
}

// Make sure SubmitCommand can handle a nil response buffer.
func TestSubmitCommandNilResponse(t *testing.T) {
	ctx := getContext(t)
	defer ctx.Close()

	_, err := ctx.SubmitCommand(NormalPriority, encodedCommand, nil)
	if err != ErrInvalidOutputPointer {
		t.Fatalf("Expected ErrInvalidOutputPointer from Submit Command: got %v", err)
	}
}

// Make sure SubmitCommand can handle a short response buffer.
func TestSubmitCommandShortResponse(t *testing.T) {
	ctx := getContext(t)
	defer ctx.Close()

	response := make([]byte, 1)
	_, err := ctx.SubmitCommand(NormalPriority, encodedCommand, response)
	if err != ErrInsufficientBuffer {
		t.Fatalf("Expected ErrInsufficientBuffer from Submit Command: got %v", err)
	}
}

// Make sure SubmitCommand can handle a long response buffer.
func TestSubmitCommandLongResponse(t *testing.T) {
	ctx := getContext(t)
	defer ctx.Close()

	response := make([]byte, 100)
	responseLen, err := ctx.SubmitCommand(NormalPriority, encodedCommand, response)
	if err != nil {
		t.Fatalf("SubmitCommand failed: err = %v", err)
	}
	response = response[:responseLen]
	if !bytes.Equal(response, expectedResponse) {
		t.Fatalf("Got response of %v, expected %v", response, expectedResponse)
	}
}
