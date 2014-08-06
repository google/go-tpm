// Copyright (c) 2014, Google Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tpm

import (
	"bytes"
	"crypto/rand"
	"os"
	"testing"
)

func TestEncoding(t *testing.T) {
	ch := commandHeader{tagRQUCommand, 0, ordOIAP}
	var c uint32 = 137
	in := []interface{}{c}

	b, err := packWithHeader(ch, in)
	if err != nil {
		t.Fatal("Couldn't pack the bytes:", err)
	}

	var hdr commandHeader
	var size uint32
	out := []interface{}{&hdr, &size}
	if err := unpack(b, out); err != nil {
		t.Fatal("Couldn't unpack the packed bytes")
	}

	if size != 137 {
		t.Fatal("Got the wrong size back")
	}
}

func TestReadPCR(t *testing.T) {
	// Try to read PCR 18. For this to work, you have to have access to
	// /dev/tpm0, and there has to be a TPM driver to answer requests.
	f, err := os.OpenFile("/dev/tpm0", os.O_RDWR, 0600)
	defer f.Close()
	if err != nil {
		t.Fatal("Can't open /dev/tpm0 for read/write:", err)
	}

	res, err := ReadPCR(f, 18)
	if err != nil {
		t.Fatal("Couldn't read PCR 18 from the TPM:", err)
	}

	t.Logf("Got PCR 18 value % x\n", res)
}

func TestPCRMask(t *testing.T) {
	var mask PCRMask
	if err := mask.SetPCR(-1); err == nil {
		t.Fatal("Incorrectly allowed non-existent PCR -1 to be set")
	}

	if err := mask.SetPCR(24); err == nil {
		t.Fatal("Incorrectly allowed non-existent PCR 24 to be set")
	}

	if err := mask.SetPCR(0); err != nil {
		t.Fatal("Couldn't set PCR 0 in the mask:", err)
	}

	set, err := mask.IsPCRSet(0)
	if err != nil {
		t.Fatal("Couldn't check to see if PCR 0 was set:", err)
	}

	if !set {
		t.Fatal("Incorrectly said PCR wasn't set when it should have been")
	}

	if err := mask.SetPCR(18); err != nil {
		t.Fatal("Couldn't set PCR 18 in the mask:", err)
	}

	set, err = mask.IsPCRSet(18)
	if err != nil {
		t.Fatal("Couldn't check to see if PCR 18 was set:", err)
	}

	if !set {
		t.Fatal("Incorrectly said PCR wasn't set when it should have been")
	}
}

func TestFetchPCRValues(t *testing.T) {
	f, err := os.OpenFile("/dev/tpm0", os.O_RDWR, 0600)
	defer f.Close()
	if err != nil {
		t.Fatal("Can't open /dev/tpm0 for read/write:", err)
	}

	var mask PCRMask
	if err := mask.SetPCR(17); err != nil {
		t.Fatal("Couldn't set PCR 17:", err)
	}

	pcrs, err := FetchPCRValues(f, mask)
	if err != nil {
		t.Fatal("Couldn't get PCRs 17 and 18:", err)
	}

	comp, err := createPCRComposite(mask, pcrs)
	if err != nil {
		t.Fatal("Couldn't create PCR composite")
	}

	if len(comp) != int(digestSize) {
		t.Fatal("Invalid PCR composite")
	}

	// Locality is apparently always set to 0 in vTCIDirect.
	var locality byte
	_, err = createPCRInfo(locality, mask, pcrs)
	if err != nil {
		t.Fatal("Couldn't create a pcrInfoLong structure for these PCRs")
	}
}

func TestGetRandom(t *testing.T) {
	// Try to get 16 bytes of randomness from the TPM.
	f, err := os.OpenFile("/dev/tpm0", os.O_RDWR, 0600)
	defer f.Close()
	if err != nil {
		t.Fatal("Can't open /dev/tpm0 for read/write:", err)
	}

	b, err := GetRandom(f, 16)
	if err != nil {
		t.Fatal("Couldn't get 16 bytes of randomness from the TPM:", err)
	}

	t.Logf("Got random bytes % x\n", b)
}

func TestOIAP(t *testing.T) {
	f, err := os.OpenFile("/dev/tpm0", os.O_RDWR, 0600)
	defer f.Close()
	if err != nil {
		t.Fatal("Can't open /dev/tpm0 for read/write:", err)
	}

	// Get auth info from OIAP.
	resp, err := oiap(f)
	if err != nil {
		t.Fatal("Couldn't run OIAP:", err)
	}

	t.Logf("From OIAP, got AuthHandle %d and NonceEven % x\n", resp.AuthHandle, resp.NonceEven)
}

func TestOSAP(t *testing.T) {
	f, err := os.OpenFile("/dev/tpm0", os.O_RDWR, 0600)
	defer f.Close()
	if err != nil {
		t.Fatal("Can't open /dev/tpm0 for read/write:", err)
	}

	// Try to run OSAP for the SRK.
	osapc := osapCommand{
		EntityType:  etSRK,
		EntityValue: khSRK,
	}

	if _, err := rand.Read(osapc.OddOSAP[:]); err != nil {
		t.Fatal("Couldn't get a random odd OSAP nonce")
	}

	resp, err := osap(f, osapc)
	if err != nil {
		t.Fatal("Couldn't run OSAP:", err)
	}

	t.Logf("From OSAP, go AuthHandle %d and NonceEven % x and EvenOSAP % x\n", resp.AuthHandle, resp.NonceEven, resp.EvenOSAP)
}

func TestResizeableSlice(t *testing.T) {
	// Set up an encoded slice with a byte array.
	sr := &sealResponse{
		NonceEven:   [20]byte{},
		ContSession: 1,
		PubAuth:     [20]byte{},
	}

	b := make([]byte, 322)
	if _, err := rand.Read(b); err != nil {
		t.Fatal("Couldn't read random bytes into the byte array")
	}

	rh := &responseHeader{
		Tag:  tagRSPAuth1Command,
		Size: 0,
		Res:  0,
	}

	in := []interface{}{rh, sr, b}
	rh.Size = uint32(packedSize(in))
	bb, err := pack(in)
	if err != nil {
		t.Fatal("Couldn't pack the bytes:", err)
	}

	var rh2 responseHeader
	var sr2 sealResponse
	var b2 []byte
	out := []interface{}{&rh2, &sr2, &b2}
	if err := unpack(bb, out); err != nil {
		t.Fatal("Couldn't unpack the resizeable values:", err)
	}

	if !bytes.Equal(b2, b) {
		t.Fatal("ResizeableSlice was not resized or copied correctly")
	}
}

func TestSeal(t *testing.T) {
	f, err := os.OpenFile("/dev/tpm0", os.O_RDWR, 0600)
	defer f.Close()
	if err != nil {
		t.Fatal("Can't open /dev/tpm0 for read/write:", err)
	}

	// Seal the same data as vTCIDirect so we can check the output as exactly as
	// possible.
	data := make([]byte, 64)
	data[0] = 1
	data[1] = 27
	data[2] = 52

	sealed, err := Seal(f, data)
	if err != nil {
		t.Fatal("Couldn't seal the data:", err)
	}

	data2, err := Unseal(f, sealed)
	if err != nil {
		t.Fatal("Couldn't unseal the data:", err)
	}

	if !bytes.Equal(data2, data) {
		t.Fatal("Unsealed data doesn't match original data")
	}
}
