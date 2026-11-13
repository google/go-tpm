package tpm2test

import (
	"math/bits"
	"testing"

	"github.com/google/go-tpm-tools/simulator"
	. "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/testhelper"
)

// currentAllocation returns the PCR banks the TPM currently has allocated.
func currentAllocation(t *testing.T, thetpm transport.TPM) TPMLPCRSelection {
	t.Helper()

	capRsp, err := GetCapability{
		Capability:    TPMCapPCRs,
		PropertyCount: 1,
	}.Execute(thetpm)
	if err != nil {
		t.Fatalf("GetCapability failed: %v", err)
	}

	assigned, err := capRsp.CapabilityData.Data.AssignedPCR()
	if err != nil {
		t.Fatalf("AssignedPCR failed: %v", err)
	}
	return *assigned
}

// TestPCRAllocate re-requests the allocation the TPM already has. That is a
// no-op as far as the next TPM2_Startup(CLEAR) is concerned, but it still
// exercises the full command round trip.
func TestPCRAllocate(t *testing.T) {
	thetpm := testhelper.Open(t)
	defer thetpm.Close()

	allocate := PCRAllocate{
		AuthHandle: AuthHandle{
			Handle: TPMRHPlatform,
			Auth:   PasswordAuth(nil),
		},
		PCRAllocation: currentAllocation(t, thetpm),
	}

	rsp, err := allocate.Execute(thetpm)
	if err != nil {
		t.Fatalf("PCRAllocate failed: %v", err)
	}
	if !rsp.AllocationSuccess {
		t.Errorf("PCRAllocate did not accept the current allocation: "+
			"maxPCR = %v, sizeNeeded = %v, sizeAvailable = %v",
			rsp.MaxPCR, rsp.SizeNeeded, rsp.SizeAvailable)
	}
	if rsp.MaxPCR == 0 {
		t.Errorf("PCRAllocate returned maxPCR = 0, want nonzero")
	}
}

// TestPCRAllocateSingleBank selects a single bank with no PCR in it. Only banks
// listed in pcrAllocation are changed, so this leaves every other bank alone and
// the request should need less space than the current allocation has available.
func TestPCRAllocateSingleBank(t *testing.T) {
	thetpm := testhelper.Open(t)
	defer thetpm.Close()

	allocate := PCRAllocate{
		AuthHandle: AuthHandle{
			Handle: TPMRHPlatform,
			Auth:   PasswordAuth(nil),
		},
		PCRAllocation: TPMLPCRSelection{
			PCRSelections: []TPMSPCRSelection{
				{
					Hash:      TPMAlgSHA1,
					PCRSelect: PCClientCompatible.PCRs(),
				},
			},
		},
	}

	rsp, err := allocate.Execute(thetpm)
	if err != nil {
		t.Fatalf("PCRAllocate failed: %v", err)
	}
	// Emptying a bank only frees space, so the request has to fit.
	if rsp.SizeNeeded > rsp.SizeAvailable {
		t.Fatalf("emptying a bank needs %v octets with only %v available",
			rsp.SizeNeeded, rsp.SizeAvailable)
	}
	// Part 3 section 22.5.1 states one direction only: sizeNeeded less than or
	// equal to sizeAvailable implies allocationSuccess is YES. It says nothing
	// about the converse, so do not assert it.
	if !rsp.AllocationSuccess {
		t.Errorf("allocationSuccess = false with sizeNeeded = %v <= sizeAvailable = %v, want true",
			rsp.SizeNeeded, rsp.SizeAvailable)
	}
}

// pcrCounts returns the number of PCR allocated in each bank.
func pcrCounts(t *testing.T, thetpm transport.TPM) map[TPMAlgID]int {
	t.Helper()

	counts := make(map[TPMAlgID]int)
	for _, sel := range currentAllocation(t, thetpm).PCRSelections {
		n := 0
		for _, b := range sel.PCRSelect {
			n += bits.OnesCount8(b)
		}
		counts[sel.Hash] = n
	}
	return counts
}

// TestPCRAllocateTakesEffect checks that the request is applied at the next
// _TPM_Init and not before, and that banks left out of the request are
// untouched.
//
// This drives the in-process simulator directly rather than going through
// testhelper.Open, because triggering _TPM_Init needs simulator.Reset and
// transport.TPM has no equivalent.
func TestPCRAllocateTakesEffect(t *testing.T) {
	sim, err := simulator.Get()
	if err != nil {
		t.Skipf("could not open simulator: %v", err)
	}
	defer sim.Close()
	thetpm := transport.FromReadWriter(sim)

	before := pcrCounts(t, thetpm)
	if before[TPMAlgSHA1] == 0 {
		t.Skipf("SHA-1 bank is already empty, nothing to observe")
	}

	allocate := PCRAllocate{
		AuthHandle: AuthHandle{
			Handle: TPMRHPlatform,
			Auth:   PasswordAuth(nil),
		},
		PCRAllocation: TPMLPCRSelection{
			PCRSelections: []TPMSPCRSelection{
				{
					Hash:      TPMAlgSHA1,
					PCRSelect: PCClientCompatible.PCRs(),
				},
			},
		},
	}
	rsp, err := allocate.Execute(thetpm)
	if err != nil {
		t.Fatalf("PCRAllocate failed: %v", err)
	}
	if !rsp.AllocationSuccess {
		t.Fatalf("PCRAllocate rejected emptying the SHA-1 bank")
	}

	// The allocation in place is retained until the next _TPM_Init.
	if got := pcrCounts(t, thetpm)[TPMAlgSHA1]; got != before[TPMAlgSHA1] {
		t.Errorf("SHA-1 bank has %v PCR before _TPM_Init, want %v unchanged",
			got, before[TPMAlgSHA1])
	}

	if err := sim.Reset(); err != nil {
		t.Fatalf("could not reset simulator: %v", err)
	}

	after := pcrCounts(t, thetpm)
	if after[TPMAlgSHA1] != 0 {
		t.Errorf("SHA-1 bank has %v PCR after _TPM_Init, want 0", after[TPMAlgSHA1])
	}
	for alg, want := range before {
		if alg == TPMAlgSHA1 {
			continue
		}
		if after[alg] != want {
			t.Errorf("unrequested bank %v has %v PCR after _TPM_Init, want %v unchanged",
				alg, after[alg], want)
		}
	}
}

// TestPCRAllocateBadAuth checks that the command is rejected without platform
// authorization.
func TestPCRAllocateBadAuth(t *testing.T) {
	thetpm := testhelper.Open(t)
	defer thetpm.Close()

	allocate := PCRAllocate{
		AuthHandle: AuthHandle{
			Handle: TPMRHPlatform,
			Auth:   PasswordAuth([]byte("not the platform auth")),
		},
		PCRAllocation: currentAllocation(t, thetpm),
	}

	if _, err := allocate.Execute(thetpm); err == nil {
		t.Errorf("PCRAllocate succeeded with the wrong auth, want failure")
	}
}
