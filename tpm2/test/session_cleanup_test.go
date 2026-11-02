package tpm2test

import (
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	. "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/testhelper"
)

var errPolicy = errors.New("the policy failed")

func failingPolicy(transport.TPM, TPMISHPolicy, TPM2BNonce) error { return errPolicy }

func emptyPolicy(transport.TPM, TPMISHPolicy, TPM2BNonce) error { return nil }

// loadedSessions returns how many sessions are loaded in the TPM.
func loadedSessions(t *testing.T, thetpm transport.TPM) int {
	t.Helper()
	rsp, err := GetCapability{
		Capability:    TPMCapHandles,
		Property:      uint32(TPMHTLoadedSession) << 24,
		PropertyCount: 16,
	}.Execute(thetpm)
	if err != nil {
		t.Fatalf("GetCapability: %v", err)
	}
	handles, err := rsp.CapabilityData.Data.Handles()
	if err != nil {
		t.Fatalf("Handles: %v", err)
	}
	return len(handles.Handle)
}

// flushWatcher records whether a FlushContext of TPM_RH_NULL was sent.
type flushWatcher struct {
	transport.TPM
	flushedNull bool
}

func (w *flushWatcher) Send(input []byte) ([]byte, error) {
	if len(input) >= 14 &&
		TPMCC(binary.BigEndian.Uint32(input[6:10])) == TPMCCFlushContext &&
		TPMHandle(binary.BigEndian.Uint32(input[10:14])) == TPMRHNull {
		w.flushedNull = true
	}
	return w.TPM.Send(input)
}

// A failing policy callback leaves no session behind, however often it fails.
// The simulator holds three sessions.
func TestPolicyCallbackFailureFlushesSession(t *testing.T) {
	thetpm := testhelper.Open(t)
	defer thetpm.Close()

	for i := 0; i < 8; i++ {
		_, err := CreatePrimary{
			PrimaryHandle: AuthHandle{Handle: TPMRHOwner, Auth: Policy(TPMAlgSHA256, 16, failingPolicy)},
			InPublic:      New2B(ECCSRKTemplate),
		}.Execute(thetpm)
		if !errors.Is(err, errPolicy) {
			t.Fatalf("failure %d: %v, want the policy's error", i, err)
		}
		if n := loadedSessions(t, thetpm); n != 0 {
			t.Fatalf("after failure %d: %d sessions loaded", i, n)
		}
	}
}

// When a later session's Init fails, the ones started before it in the same
// call are flushed too.
func TestLaterSessionFailureFlushesEarlierSessions(t *testing.T) {
	thetpm := testhelper.Open(t)
	defer thetpm.Close()

	for i := 0; i < 8; i++ {
		_, err := CreatePrimary{
			PrimaryHandle: TPMRHOwner,
			InPublic:      New2B(ECCSRKTemplate),
		}.Execute(thetpm,
			HMAC(TPMAlgSHA256, 16, AESEncryption(128, EncryptOut)),
			Policy(TPMAlgSHA256, 16, failingPolicy))
		if !errors.Is(err, errPolicy) {
			t.Fatalf("failure %d: %v, want the policy's error", i, err)
		}
		if n := loadedSessions(t, thetpm); n != 0 {
			t.Fatalf("after failure %d: %d sessions loaded", i, n)
		}
	}
}

// A session whose StartAuthSession failed has nothing to flush: no FlushContext
// of a null handle, and the error is StartAuthSession's alone. A session started
// before it in the same call is flushed.
func TestStartAuthSessionFailureFlushesNoNullHandle(t *testing.T) {
	thetpm := testhelper.Open(t)
	defer thetpm.Close()
	watcher := &flushWatcher{TPM: thetpm}

	// A salt key that is gone: StartAuthSession refuses its handle.
	primary, err := CreatePrimary{
		PrimaryHandle: TPMRHOwner,
		InPublic:      New2B(ECCSRKTemplate),
	}.Execute(thetpm)
	if err != nil {
		t.Fatalf("CreatePrimary: %v", err)
	}
	public, err := primary.OutPublic.Contents()
	if err != nil {
		t.Fatalf("Contents: %v", err)
	}
	if _, err := (FlushContext{FlushHandle: primary.ObjectHandle}).Execute(thetpm); err != nil {
		t.Fatalf("FlushContext: %v", err)
	}
	gone := Salted(primary.ObjectHandle, *public)

	for name, sessions := range map[string][]Session{
		"policy":          {Policy(TPMAlgSHA256, 16, emptyPolicy, gone)},
		"hmac":            {HMAC(TPMAlgSHA256, 16, gone)},
		"after a session": {HMAC(TPMAlgSHA256, 16, AESEncryption(128, EncryptOut)), HMAC(TPMAlgSHA256, 16, gone)},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := CreatePrimary{
				PrimaryHandle: TPMRHOwner,
				InPublic:      New2B(ECCSRKTemplate),
			}.Execute(watcher, sessions...)
			if !errors.Is(err, TPMRCReferenceH0) {
				t.Fatalf("%v, want TPM_RC_REFERENCE_H0", err)
			}
			if strings.Contains(err.Error(), "during cleanup") {
				t.Errorf("the cleanup failed: %v", err)
			}
			if watcher.flushedNull {
				t.Error("FlushContext of a null handle")
			}
			if n := loadedSessions(t, thetpm); n != 0 {
				t.Errorf("%d sessions loaded", n)
			}
		})
	}
}

// A command that fails on this side after its sessions started leaves none.
func TestLocalFailureAfterInitFlushesSessions(t *testing.T) {
	thetpm := testhelper.Open(t)
	defer thetpm.Close()

	for i := 0; i < 8; i++ {
		_, err := NVRead{
			// No Name for an NV index: the command cannot be built.
			AuthHandle: AuthHandle{Handle: TPMHandle(0x01000001), Auth: Policy(TPMAlgSHA256, 16, emptyPolicy)},
			NVIndex:    NamedHandle{Handle: TPMHandle(0x01000001), Name: TPM2BName{Buffer: []byte{0}}},
			Size:       1,
		}.Execute(thetpm)
		if err == nil || !strings.Contains(err.Error(), "missing Name") {
			t.Fatalf("failure %d: %v, want the missing Name", i, err)
		}
		if n := loadedSessions(t, thetpm); n != 0 {
			t.Fatalf("after failure %d: %d sessions loaded", i, n)
		}
	}
}

// The same one-off session can be used again after its callback failed: it
// starts afresh.
func TestPolicySessionRetriedAfterCallbackFailure(t *testing.T) {
	thetpm := testhelper.Open(t)
	defer thetpm.Close()

	// A parent any policy session with an empty digest may use.
	template := ECCSRKTemplate
	template.AuthPolicy = TPM2BDigest{Buffer: make([]byte, 32)}
	parent, err := CreatePrimary{
		PrimaryHandle: TPMRHOwner,
		InPublic:      New2B(template),
	}.Execute(thetpm)
	if err != nil {
		t.Fatalf("CreatePrimary: %v", err)
	}
	defer FlushContext{FlushHandle: parent.ObjectHandle}.Execute(thetpm)

	fail := true
	session := Policy(TPMAlgSHA256, 16, func(transport.TPM, TPMISHPolicy, TPM2BNonce) error {
		if fail {
			return errPolicy
		}
		return nil
	})
	create := Create{
		ParentHandle: AuthHandle{Handle: parent.ObjectHandle, Name: parent.Name, Auth: session},
		InSensitive: TPM2BSensitiveCreate{Sensitive: &TPMSSensitiveCreate{
			Data: NewTPMUSensitiveCreate(&TPM2BSensitiveData{Buffer: []byte("sealed")}),
		}},
		InPublic: New2B(TPMTPublic{
			Type:    TPMAlgKeyedHash,
			NameAlg: TPMAlgSHA256,
			ObjectAttributes: TPMAObject{
				FixedTPM:     true,
				FixedParent:  true,
				UserWithAuth: true,
				NoDA:         true,
			},
		}),
	}
	if _, err := create.Execute(thetpm); !errors.Is(err, errPolicy) {
		t.Fatalf("%v, want the policy's error", err)
	}
	fail = false
	if _, err := create.Execute(thetpm); err != nil {
		t.Fatalf("the retry: %v", err)
	}
	if n := loadedSessions(t, thetpm); n != 0 {
		t.Errorf("%d sessions loaded", n)
	}
}
