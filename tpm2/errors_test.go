package tpm2

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"testing"
)

func TestTPMRCAsAndIs(t *testing.T) {
	rawFmt1 := TPMRC(rcFmt1 | rcP | 0x100 | TPMRCValue)

	// Direct TPMRC.Canonical()
	if got := rawFmt1.Canonical(); got != TPMRCValue {
		t.Errorf("rawFmt1.Canonical() got 0x%x, want 0x%x (TPMRCValue)", got, TPMRCValue)
	}
	if got := TPMRCInitialize.Canonical(); got != TPMRCInitialize {
		t.Errorf("TPMRCInitialize.Canonical() got 0x%x, want 0x%x", got, TPMRCInitialize)
	}

	// TPMFmt1Error from isFmt1Error
	isFmt1, fmt1 := rawFmt1.isFmt1Error()
	if !isFmt1 {
		t.Fatalf("isFmt1Error() got false, want true")
	}
	if got := fmt1.Raw(); got != rawFmt1 {
		t.Errorf("fmt1.Raw() got 0x%x, want 0x%x", got, rawFmt1)
	}
	if got := fmt1.Canonical(); got != TPMRCValue {
		t.Errorf("fmt1.Canonical() got 0x%x, want 0x%x", got, TPMRCValue)
	}

	// errors.Is on TPMFmt1Error matches both canonical and raw
	if !errors.Is(fmt1, TPMRCValue) {
		t.Errorf("errors.Is(fmt1, TPMRCValue) got false, want true")
	}
	if !errors.Is(fmt1, rawFmt1) {
		t.Errorf("errors.Is(fmt1, rawFmt1) got false, want true")
	}
	if errors.Is(fmt1, TPMRCSize) {
		t.Errorf("errors.Is(fmt1, TPMRCSize) got true, want false")
	}

	// errors.As on TPMFmt1Error yields canonical TPMRC
	var rcFromFmt1 TPMRC
	if !errors.As(fmt1, &rcFromFmt1) {
		t.Fatalf("errors.As(fmt1, &rcFromFmt1) failed")
	}
	if rcFromFmt1 != TPMRCValue {
		t.Errorf("errors.As(fmt1, &rcFromFmt1) got 0x%x, want canonical 0x%x (TPMRCValue)", rcFromFmt1, TPMRCValue)
	}

	// errors.As(*TPMFmt1Error) on TPMFmt1Error
	var extractedFmt1 TPMFmt1Error
	if !errors.As(fmt1, &extractedFmt1) {
		t.Fatalf("errors.As(fmt1, &extractedFmt1) failed")
	}
	if extractedFmt1.Canonical() != TPMRCValue {
		t.Errorf("extractedFmt1.Canonical() got 0x%x, want 0x%x", extractedFmt1.Canonical(), TPMRCValue)
	}
	if isParam, idx := extractedFmt1.Parameter(); !isParam || idx != 1 {
		t.Errorf("extractedFmt1.Parameter() got (%v, %d), want (true, 1)", isParam, idx)
	}

	// Direct As method on TPMRC
	var directRC TPMRC
	if !rawFmt1.As(&directRC) {
		t.Fatalf("rawFmt1.As(&directRC) failed")
	}
	if directRC != TPMRCValue {
		t.Errorf("rawFmt1.As(&directRC) got 0x%x, want canonical 0x%x", directRC, TPMRCValue)
	}
}

func TestRspHeaderFmt1Error(t *testing.T) {
	// Simulate TPM response buffer with format-1 error (e.g. parameter 1, TPMRCValue)
	rawFmt1 := TPMRC(rcFmt1 | rcP | 0x100 | TPMRCValue)
	hdr := TPMRspHeader{
		Tag:          TPMSTNoSessions,
		Length:       10,
		ResponseCode: rawFmt1,
	}

	var buf bytes.Buffer
	if err := marshal(&buf, reflect.ValueOf(&hdr).Elem()); err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	err := rspHeader(&buf)
	if err == nil {
		t.Fatalf("rspHeader got nil, want error")
	}

	// 1. Verify errors.As(err, &rc) yields canonical code (fixes #340)
	var rc TPMRC
	if !errors.As(err, &rc) {
		t.Fatalf("errors.As(err, &rc) failed")
	}
	if rc != TPMRCValue {
		t.Errorf("errors.As(err, &rc) got 0x%x, want canonical 0x%x (TPMRCValue)", rc, TPMRCValue)
	}

	// 2. Verify errors.Is(err, TPMRCValue) works
	if !errors.Is(err, TPMRCValue) {
		t.Errorf("errors.Is(err, TPMRCValue) got false, want true")
	}

	// 3. Verify errors.Is(err, rawFmt1) works
	if !errors.Is(err, rawFmt1) {
		t.Errorf("errors.Is(err, rawFmt1) got false, want true")
	}

	// 4. Verify errors.As(err, &fmt1) extracts TPMFmt1Error
	var fmt1 TPMFmt1Error
	if !errors.As(err, &fmt1) {
		t.Fatalf("errors.As(err, &fmt1) failed")
	}
	if isParam, idx := fmt1.Parameter(); !isParam || idx != 1 {
		t.Errorf("fmt1.Parameter() got (%v, %d), want (true, 1)", isParam, idx)
	}

	// 5. Verify wrapped error propagates As and Is
	wrapped := fmt.Errorf("command execution failed: %w", err)
	var wrappedRC TPMRC
	if !errors.As(wrapped, &wrappedRC) {
		t.Fatalf("errors.As(wrapped, &wrappedRC) failed")
	}
	if wrappedRC != TPMRCValue {
		t.Errorf("errors.As(wrapped, &wrappedRC) got 0x%x, want canonical 0x%x", wrappedRC, TPMRCValue)
	}
	if !errors.Is(wrapped, TPMRCValue) {
		t.Errorf("errors.Is(wrapped, TPMRCValue) got false, want true")
	}
}
