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
	"testing"
)

func TestPCRMask(t *testing.T) {
	var mask pcrMask
	if err := mask.setPCR(-1); err == nil {
		t.Fatal("Incorrectly allowed non-existent PCR -1 to be set")
	}

	if err := mask.setPCR(24); err == nil {
		t.Fatal("Incorrectly allowed non-existent PCR 24 to be set")
	}

	if err := mask.setPCR(0); err != nil {
		t.Fatal("Couldn't set PCR 0 in the mask:", err)
	}

	set, err := mask.isPCRSet(0)
	if err != nil {
		t.Fatal("Couldn't check to see if PCR 0 was set:", err)
	}

	if !set {
		t.Fatal("Incorrectly said PCR wasn't set when it should have been")
	}

	if err := mask.setPCR(18); err != nil {
		t.Fatal("Couldn't set PCR 18 in the mask:", err)
	}

	set, err = mask.isPCRSet(18)
	if err != nil {
		t.Fatal("Couldn't check to see if PCR 18 was set:", err)
	}

	if !set {
		t.Fatal("Incorrectly said PCR wasn't set when it should have been")
	}
}
