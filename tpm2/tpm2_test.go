package tpm2_test

import "testing"

// assertExpectedError asserts an expected error either occurred or not.
// If fatal is true, then errors are indicated with t.Fatalf, otherwise
// t.Errorf is used.
func assertExpectedError(t *testing.T, fatal bool, a, e error) bool {
	failFn := t.Errorf
	if fatal {
		failFn = t.Fatalf
	}
	switch {
	case a != nil && e != nil && a.Error() != e.Error():
		failFn("unexpected error occurred: act=%q, exp=%q", a, e)
	case a != nil && e != nil && a.Error() == e.Error():
		t.Logf("expected error occurred: exp=%s", e)
		return false
	case a != nil && e == nil:
		failFn("unexpected error occurred:  act=%s", a)
	case a == nil && e != nil:
		failFn("expected error did not occur: exp=%s", e)
	}
	return true
}
