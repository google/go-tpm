// Copyright (c) 2018, Google Inc. All rights reserved.
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

package tpm2

import (
	"flag"
	"io"
	"testing"
)

var runTPMTests = flag.Bool("run_tpm_tests", false, "Run the Windows TPM integration tests. Defaults to false.")

func openTPM(t *testing.T) io.ReadWriteCloser {
	if *runTPMTests == false {
		t.SkipNow()
	}
	rw, err := OpenTPM()
	if err != nil {
		t.Fatalf("Open TPM failed: %s\n", err)
	}
	return rw
}
