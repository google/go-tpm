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
	"crypto/sha1"
	"errors"
	"fmt"
	"io"
	"strconv"
)

// setPCR sets a PCR value as selected in a given mask.
func (pm *pcrMask) setPCR(i int) error {
	if i >= 24 || i < 0 {
		return errors.New("can't set PCR " + strconv.Itoa(i))
	}

	(*pm)[i/8] |= 1 << uint(i%8)
	return nil
}

// isPCRSet checks to see if a given PCR is included in this mask.
func (pm pcrMask) isPCRSet(i int) (bool, error) {
	if i >= 24 || i < 0 {
		return false, errors.New("can't check PCR " + strconv.Itoa(i))
	}

	n := byte(1 << uint(i%8))
	return pm[i/8]&n == n, nil
}

// String returns a string representation of a pcrSelection
func (p pcrSelection) String() string {
	return fmt.Sprintf("pcrSelection{Size: %x, Mask: % x}", p.Size, p.Mask)
}

// newPCRSelection creates a new pcrSelection for the given set of PCRs.
func newPCRSelection(pcrVals []int) (*pcrSelection, error) {
	pcrs := &pcrSelection{Size: 3}
	for _, v := range pcrVals {
		if err := pcrs.Mask.setPCR(v); err != nil {
			return nil, err
		}
	}

	return pcrs, nil
}

// createPCRComposite composes a set of PCRs by prepending a pcrSelection and a
// length, then computing the SHA1 hash and returning its output.
func createPCRComposite(mask pcrMask, pcrs []byte) ([]byte, error) {
	if len(pcrs)%PCRSize != 0 {
		return nil, errors.New("pcrs must be a multiple of " + strconv.Itoa(PCRSize))
	}

	pcrc := pcrComposite{
		Selection: pcrSelection{3, mask},
		Values:    pcrs,
	}
	b, err := pack([]interface{}{pcrc})
	if err != nil {
		return nil, err
	}

	h := sha1.Sum(b)
	return h[:], nil
}

// String returns a string representation of a pcrInfoLong.
func (pcri pcrInfoLong) String() string {
	return fmt.Sprintf("pcrInfoLong{Tag: %x, LocAtCreation: %x, LocAtRelease: %x, PCRsAtCreation: %s, PCRsAtRelease: %s, DigestAtCreation: % x, DigestAtRelease: % x}", pcri.Tag, pcri.LocAtCreation, pcri.LocAtRelease, pcri.PCRsAtCreation, pcri.PCRsAtRelease, pcri.DigestAtCreation, pcri.DigestAtRelease)
}

// String returns a string representation of a pcrInfoShort.
func (pcri pcrInfoShort) String() string {
	return fmt.Sprintf("pcrInfoShort{LocAtRelease: %x, PCRsAtRelease: %s, DigestAtRelease: % x}", pcri.LocAtRelease, pcri.PCRsAtRelease, pcri.DigestAtRelease)
}

// createPCRInfoLong creates a pcrInfoLong structure from a mask and some PCR
// values that match this mask, along with a TPM locality.
func createPCRInfoLong(loc byte, mask pcrMask, pcrVals []byte) (*pcrInfoLong, error) {
	d, err := createPCRComposite(mask, pcrVals)
	if err != nil {
		return nil, err
	}

	locVal := byte(1 << loc)
	pcri := &pcrInfoLong{
		Tag:            tagPCRInfoLong,
		LocAtCreation:  locVal,
		LocAtRelease:   locVal,
		PCRsAtCreation: pcrSelection{3, mask},
		PCRsAtRelease:  pcrSelection{3, mask},
	}

	copy(pcri.DigestAtRelease[:], d)
	copy(pcri.DigestAtCreation[:], d)

	return pcri, nil
}

// newPCRInfoLong creates and returns a pcrInfoLong structure for the given PCR
// values.
func newPCRInfoLong(rw io.ReadWriter, loc byte, pcrNums []int) (*pcrInfoLong, error) {
	var mask pcrMask
	for _, pcr := range pcrNums {
		if err := mask.setPCR(pcr); err != nil {
			return nil, err
		}
	}

	pcrVals, err := FetchPCRValues(rw, pcrNums)
	if err != nil {
		return nil, err
	}

	return createPCRInfoLong(loc, mask, pcrVals)
}

func newPCRInfo(rw io.ReadWriter, pcrNums []int) (*pcrInfo, error) {
	var mask pcrMask
	for _, pcr := range pcrNums {
		if err := mask.setPCR(pcr); err != nil {
			return nil, err
		}
	}

	pcrVals, err := FetchPCRValues(rw, pcrNums)
	if err != nil {
		return nil, err
	}
	d, err := createPCRComposite(mask, pcrVals)
	if err != nil {
		return nil, err
	}
	pcri := &pcrInfo{
		PcrSelection: pcrSelection{3, mask},
	}
	copy(pcri.DigestAtRelease[:], d)
	copy(pcri.DigestAtCreation[:], d)

	return pcri, nil
}
