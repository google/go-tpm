package tpm2

import (
	"reflect"
	"testing"
)

func TestError(t *testing.T) {
	var err error

	// Vendor
	err = decodeResponse(0x501)
	ve, ok := err.(VendorError)
	if !ok {
		t.Fatalf("unexpected error type %v, want VendorError", reflect.TypeOf(err))
	}
	if ve.Code != 0x501 {
		t.Fatalf("unexpected error code %v, want 1", ve.Code)
	}

	// Warning
	err = decodeResponse(0x922)
	w, ok := err.(Warning)
	if !ok {
		t.Fatalf("unexpected error type %v, want Warning", reflect.TypeOf(err))
	}
	if w.Code != RcRetry {
		t.Fatalf("unexpected error code %v", w.Code)
	}

	// Error
	err = decodeResponse(0x100)
	e, ok := err.(Error)
	if !ok {
		t.Fatalf("unexpected error type %v, want Error", reflect.TypeOf(err))
	}
	if e.Code != RcInitialize {
		t.Fatalf("unexpected error code %v", e.Code)
	}

	// ParameterError
	err = decodeResponse(0xfc1)
	pe, ok := err.(ParameterError)
	if !ok {
		t.Fatalf("unexpected error type %v, want ParameterError", reflect.TypeOf(err))
	}
	if pe.Code != RcAsymmetric {
		t.Fatalf("unexpected error code %v", pe.Code)
	}
	if pe.Parameter != RcF {
		t.Fatalf("unexpected parameter %v", pe.Parameter)
	}

	// HandleError
	err = decodeResponse(0x7a3)
	he, ok := err.(HandleError)
	if !ok {
		t.Fatalf("unexpected error type %v, want HandleError", reflect.TypeOf(err))
	}
	if he.Code != RcExpired {
		t.Fatalf("unexpected error code %v", he.Code)
	}
	if he.Handle != Rc7 {
		t.Fatalf("unexpected handle %v", he.Handle)
	}

	// SessionError
	err = decodeResponse(0xfa2)
	se, ok := err.(SessionError)
	if !ok {
		t.Fatalf("unexpected error type %v, want SessionError", reflect.TypeOf(err))
	}
	if se.Code != RcBadAuth {
		t.Fatalf("unexpected error code %v", he.Code)
	}
	if se.Session != Rc7 {
		t.Fatalf("unexpected session %v", se.Session)
	}
}
