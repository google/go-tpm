package tbs

import (
	"bytes"
	"os"
	"testing"
)

// Encodes a call to Getrandom() with a buffer of length zero, making this
// command an effective no-op.
var getRandomRawCommand = []byte{128, 1, 0, 0, 0, 12, 0, 0, 1, 123, 0, 0}

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
			t.Fatalf("GetTCGLog failed: %v", err)
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
		t.Fatalf("First GetTCGLog failed: %v", err)
	}
	if logLen == 0 {
		t.Fatal("Expected positive TCGLog length")
	}

	log := make([]byte, logLen)
	if _, err := ctx.GetTCGLog(log); err != nil {
		t.Fatalf("Second GetTCGLog failed: %v", err)
	}
}

// SubmitCommand can handle a nil command buffer.
func TestSubmitCommandNilCommand(t *testing.T) {
	ctx := getContext(t)
	defer ctx.Close()

	rawResponse := make([]byte, os.Getpagesize())
	_, err := ctx.SubmitCommand(NormalPriority, nil, rawResponse)
	if err != ErrBadParameter {
		t.Fatalf("SubmitCommand failed with %v: expected ErrBadParameter", err)
	}
}

// SubmitCommand can handle a nil response buffer.
func TestSubmitCommandNilResponse(t *testing.T) {
	ctx := getContext(t)
	defer ctx.Close()

	_, err := ctx.SubmitCommand(NormalPriority, getRandomRawCommand, nil)
	if err != ErrInvalidOutputPointer {
		t.Fatalf("SubmitCommand failed with %v: expected ErrInvalidOutputPointer", err)
	}
}

// SubmitCommand can handle a response buffer that is shorter than necessary.
func TestSubmitCommandShortResponse(t *testing.T) {
	ctx := getContext(t)
	defer ctx.Close()

	rawResponse := make([]byte, 1)
	_, err := ctx.SubmitCommand(NormalPriority, getRandomRawCommand, rawResponse)
	if err != ErrInsufficientBuffer {
		t.Fatalf("SubmitCommand failed with %v: expected ErrInsufficientBuffer", err)
	}
}

// SubmitCommand can handle a response buffer that is longer than necessary.
func TestSubmitCommandLongResponse(t *testing.T) {
	ctx := getContext(t)
	defer ctx.Close()

	rawResponse := make([]byte, os.Getpagesize())
	responseLen, err := ctx.SubmitCommand(NormalPriority, getRandomRawCommand, rawResponse)
	if err != nil {
		t.Fatalf("SubmitCommand failed: %v", err)
	}
	rawResponse = rawResponse[:responseLen]

	// Expected response buffer for getRandomRawCommand
	expectedGetRandomRawResponse := []byte{128, 1, 0, 0, 0, 12, 0, 0, 0, 0, 0, 0}
	if !bytes.Equal(rawResponse, expectedGetRandomRawResponse) {
		t.Fatalf("Got response of %v, expected %v", rawResponse, expectedGetRandomRawResponse)
	}
}

// Get Storage owner authorization delegation blob
func TestGetStorageOwnerAuth(t *testing.T) {
	ctx := getContext(t)
	defer ctx.Close()

	authBufferLength, err := ctx.GetOwnerAuth(Storage20Authorization, nil)
	if err != nil && err != ErrOwnerauthNotFound {
		t.Fatalf("Failed to get Storage authorization delegation blob size: %v", err)
	} else if err == ErrOwnerauthNotFound {
		t.Log("Skipping retrieval of Storage authorization; Delegation blob not available in the registry.")
		t.SkipNow()
	}

	storageOwnerAuth := make([]byte, authBufferLength)
	if _, err := ctx.GetOwnerAuth(Storage20Authorization, storageOwnerAuth); err != nil && err != ErrOwnerauthNotFound {
		t.Fatalf("Failed to retrieve Storage Authorization delegation blob from the registry: %v", err)
	} else if err == ErrOwnerauthNotFound {
		t.Log("Skipping retrieval of Storage authorization; Delegation blob not available in the registry.")
		t.SkipNow()
	}
}

// Get Endorsement owner authorization delegation blob
func TestGetEndorsementOwnerAuth(t *testing.T) {
	ctx := getContext(t)
	defer ctx.Close()

	authBufferLength, err := ctx.GetOwnerAuth(Endorsement20Authorization, nil)
	if err != nil && err != ErrOwnerauthNotFound {
		t.Fatalf("Failed to get Endorsement authorization delegation blob size: %v", err)
	} else if err == ErrOwnerauthNotFound {
		t.Log("Skipping retrieval of Endorsement authorization; Delegation blob not available in the registry.")
		t.SkipNow()
	}
	if authBufferLength <= 0 {
		t.Fatal("Expected positive Endorsement authorization delegation blob size")
	}

	endorsementOwnerAuth := make([]byte, authBufferLength)
	if _, err := ctx.GetOwnerAuth(Endorsement20Authorization, endorsementOwnerAuth); err != nil && err != ErrOwnerauthNotFound {
		t.Fatalf("Failed to retrieve Endorsement Authorization delegation blob from the registry: %v", err)
	} else if err == ErrOwnerauthNotFound {
		t.Log("Skipping retrieval of Endorsement authorization; Delegation blob not available in the registry.")
		t.SkipNow()
	}
}

// Get Full owner authorization delegation blob
func TestGetFullOwnerAuth(t *testing.T) {
	ctx := getContext(t)
	defer ctx.Close()

	authBufferLength, err := ctx.GetOwnerAuth(FullAuthorization, nil)
	if err != nil && err != ErrOwnerauthNotFound {
		t.Fatalf("Failed to get Full authorization delegation blob size: %v", err)
	} else if err == ErrOwnerauthNotFound {
		t.Log("Skipping retrieval of Full authorization; Delegation blob not available in the registry.")
		t.SkipNow()
	}

	fullOwnerAuth := make([]byte, authBufferLength)
	if _, err := ctx.GetOwnerAuth(FullAuthorization, fullOwnerAuth); err != nil && err != ErrOwnerauthNotFound {
		t.Fatalf("Failed to retrieve Full Authorization delegation blob from the registry: %v", err)
	} else if err == ErrOwnerauthNotFound {
		t.Log("Skipping retrieval of Full authorization; Delegation blob not available in the registry.")
		t.SkipNow()
	}
}
