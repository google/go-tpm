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

package tpm2integrationtest

import (
	"bytes"
	"flag"
	"os"
	"os/exec"
	"testing"
)

var (
	tpmPath = flag.String("tpm-path", "", "Path to TPM character device. Most Linux systems expose it under /dev/tpm0. Empty value (default) will disable all integration tests.")
	binPath = flag.String("bin-path", "./", "The path to the directory where the binaries for the examples live.")
)

func TestMain(m *testing.M) {
	flag.Parse()
	if *tpmPath == "" {
		os.Exit(0)
	} else {
		os.Exit(m.Run())
	}
}

// TODO(nlehrer): TestReadPCR

func TestExtendPCR(t *testing.T) {
	pcr1ValBefore := runTPM2Cmd(t, "readpcr", "-pcr", "1")
	runTPM2Cmd(t, "extendpcr", "-pcr", "1", "-data", "FF")
	pcr1ValAfter := runTPM2Cmd(t, "readpcr", "-pcr", "1")
	if pcr1ValBefore == pcr1ValAfter {
		// TODO(nlehrer): Add message.
		t.Fail()
	}
}

func runTPM2Cmd(t *testing.T, cmdName string, args ...string) string {
	progName := *binPath + "tpm2-" + cmdName
	progArgs := make([]string, 0, len(args)+2)
	progArgs = append(append(progArgs, "-tpm-path", *tpmPath), args...)
	cmd := exec.Command(progName, progArgs...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		t.Fatalf("Command %v failed with error %q and error stream: %s\n",
			cmd.Args, err, stderr.String())
	}
	t.Logf("%v succeeded with output: %s\n", cmd.Args, stdout.String())
	return stdout.String()
}
