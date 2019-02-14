package tpm2

import (
	"reflect"
	"testing"

	"github.com/google/go-tpm/tpmutil"
)

func TestError(t *testing.T) {
	tests := []struct {
		Response tpmutil.ResponseCode
		Expected error
	}{
		{0x501, VendorError{Code: 0x501}},                           // Vendor
		{0x922, Warning{Code: RCRetry}},                             // Warning
		{0x100, Error{Code: RCInitialize}},                          // Error
		{0xfc1, ParameterError{Code: RCAsymmetric, Parameter: RCF}}, // ParameterError
		{0x7a3, HandleError{Code: RCExpired, Handle: RC7}},          // HandleError
		{0xfa2, SessionError{Code: RCBadAuth, Session: RC7}},        // SessionError
	}

	for _, test := range tests {
		err := decodeResponse(test.Response)
		if !reflect.DeepEqual(err, test.Expected) {
			t.Fatalf("expected error %#v for response 0x%x, got %#v", test.Expected, test.Response, err)
		}
	}
}
