package tcp

import (
	"bytes"
	"errors"
	"flag"
	"testing"

	"github.com/google/go-tpm/tpm2"
)

var (
	cmdAddr  = flag.String("cmd_addr", "", "command port (e.g., 'localhost:2321')")
	platAddr = flag.String("plat_addr", "", "platform port (e.g., 'localhost:2322')")
)

// The tests in this file are skipped unless the flags above are provided.
// To run the tests:
// Fetch the TPM reference code at https://github.com/trustedcomputinggroup/tpm
// Build the simulator per the instructions for your platform
// In one shell, run the simulator, e.g., TPMCmd/Simulator/src/tpm2-simulator
// In the other, run the tests, e.g.:
//   go test --cmd_addr localhost:2321 --plat_addr localhost:2322

// Helper to open the TPM based on command-line flags passed to the test, or skip.
func getTPM(t *testing.T, powerOnStartUp bool) *TPM {
	t.Helper()
	flag.Parse()

	if *cmdAddr == "" || *platAddr == "" {
		t.Skipf("TPM simulator not provided, skipping test")
	}

	tpm, err := Open(Config{
		CommandAddress:  *cmdAddr,
		PlatformAddress: *platAddr,
	})
	if err != nil {
		t.Fatalf("Open() = %v", err)
	}

	if err := tpm.PowerOff(); err != nil {
		t.Fatalf("PowerOff() = %v", err)
	}

	if powerOnStartUp {
		if err := tpm.PowerOn(); err != nil {
			t.Fatalf("PowerOn() = %v", err)
		}
		_, err := tpm2.Startup{
			StartupType: tpm2.TPMSUClear,
		}.Execute(tpm)
		if err != nil {
			t.Fatalf("Startup() = %v", err)
		}
	}

	return tpm
}

// Helper to let us easily test that closing the TPM doesn't return any errors.
func closeTPM(t *testing.T, tpm *TPM) {
	t.Helper()
	if err := tpm.Close(); err != nil {
		t.Fatalf("Close() = %v", err)
	}
}

func TestPowerOnOff(t *testing.T) {
	tpm := getTPM(t, false)
	defer closeTPM(t, tpm)

	// The simulator starts out powered off, but maybe the simulator was
	// running before we started this test.
	// Ensure it is off at the start of the test.
	if err := tpm.PowerOff(); err != nil {
		t.Fatalf("PowerOff() = %v", err)
	}

	// Check that we return the expected error for a powered-off TPM.
	_, err := tpm2.Startup{
		StartupType: tpm2.TPMSUClear,
	}.Execute(tpm)
	if !errors.Is(err, ErrEmptyResponse) {
		t.Fatalf("Startup() before PowerOn() = %v, want %v", err, ErrEmptyResponse)
	}

	// Power on the TPM.
	if err := tpm.PowerOn(); err != nil {
		t.Fatalf("PowerOn() = %v", err)
	}

	// Check that the TPM now reports it needs to be started up.
	_, err = tpm2.GetRandom{
		BytesRequested: 16,
	}.Execute(tpm)
	if !errors.Is(err, tpm2.TPMRCInitialize) {
		t.Errorf("GetRandom() = %v, want %v", err, tpm2.TPMRCInitialize)
	}

	_, err = tpm2.Startup{
		StartupType: tpm2.TPMSUClear,
	}.Execute(tpm)
	if err != nil {
		t.Errorf("Startup() = %v", err)
	}

	rnd, err := tpm2.GetRandom{
		BytesRequested: 16,
	}.Execute(tpm)
	if err != nil {
		t.Errorf("GetRandom() = %v", err)
	}
	if bytes.Equal(rnd.RandomBytes.Buffer, make([]byte, 16)) {
		t.Errorf("GetRandom() = %x, expected random bytes", rnd.RandomBytes.Buffer)
	}
}

// Helper to perform a restart ("warm reboot") or reset ("cold reboot") of the TPM.
func rebootTPM(t *testing.T, tpm *TPM, shutdownType tpm2.TPMSU) {
	t.Helper()

	_, err := tpm2.Shutdown{
		ShutdownType: shutdownType,
	}.Execute(tpm)
	if err != nil {
		t.Fatalf("Shutdown() = %v", err)
	}
	if err := tpm.Reset(); err != nil {
		t.Fatalf("Reset() = %v", err)
	}
	_, err = tpm2.Startup{
		StartupType: shutdownType,
	}.Execute(tpm)
	if err != nil {
		t.Fatalf("Startup() = %v", err)
	}
}

func TestResetRestart(t *testing.T) {
	tpm := getTPM(t, true)
	defer closeTPM(t, tpm)

	clock1, err := tpm2.ReadClock{}.Execute(tpm)
	if err != nil {
		t.Fatalf("ReadClock() = %v", err)
	}

	// Perform a TPM Restart (SU_STATE)
	rebootTPM(t, tpm, tpm2.TPMSUState)

	clock2, err := tpm2.ReadClock{}.Execute(tpm)
	if err != nil {
		t.Fatalf("ReadClock() = %v", err)
	}

	// Perform a TPM Reset (SU_CLEAR)
	rebootTPM(t, tpm, tpm2.TPMSUClear)

	clock3, err := tpm2.ReadClock{}.Execute(tpm)
	if err != nil {
		t.Fatalf("ReadClock() = %v", err)
	}

	// Restart should increment restartCount and leave resetCount alone.
	if clock2.CurrentTime.ClockInfo.RestartCount != clock1.CurrentTime.ClockInfo.RestartCount+1 {
		t.Errorf("restartCount after Restart was %v, want %v",
			clock2.CurrentTime.ClockInfo.RestartCount,
			clock1.CurrentTime.ClockInfo.RestartCount+1)
	}
	if clock2.CurrentTime.ClockInfo.ResetCount != clock1.CurrentTime.ClockInfo.ResetCount {
		t.Errorf("resetCount after Restart was %v, want %v",
			clock2.CurrentTime.ClockInfo.ResetCount,
			clock1.CurrentTime.ClockInfo.ResetCount)
	}

	// Reset should reset restartCount to 0 and increment resetCount.
	if clock3.CurrentTime.ClockInfo.RestartCount != 0 {
		t.Errorf("restartCount after Reset was %v, want 0",
			clock3.CurrentTime.ClockInfo.RestartCount)
	}
	if clock3.CurrentTime.ClockInfo.ResetCount != clock2.CurrentTime.ClockInfo.ResetCount+1 {
		t.Errorf("resetCount after Reset was %v, want %v",
			clock3.CurrentTime.ClockInfo.ResetCount,
			clock2.CurrentTime.ClockInfo.ResetCount+1)
	}
}
