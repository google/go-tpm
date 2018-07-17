package tpm2_integration_test

import (
	"bytes"
	"flag"
	"os"
	"os/exec"
	"testing"
)

var (
	tpmPath = flag.String(
		"tpm-path",
		"",
		"Path to TPM character device. Most Linux systems expose it under /dev/tpm0. "+
			"Empty value (default) will disable all integration tests.")

	binPath = flag.String(
		"bin-path",
		"./",
		"The path to the directory where the binaries for the examples live.")
)

func TestMain(m *testing.M) {
	flag.Parse()
	if *tpmPath == "" {
		os.Exit(0)
	} else {
		os.Exit(m.Run())
	}
}

func TestExtendPcr(t *testing.T) {
	pcr1ValBefore := runTpm2Cmd(t, "readpcr", "-pcr", "1")
	runTpm2Cmd(t, "extendpcr", "-pcr", "1", "-data", "FF")
	pcr1ValAfter := runTpm2Cmd(t, "readpcr", "-pcr", "1")
	if pcr1ValBefore == pcr1ValAfter {
		t.Fail()
	}
}

func runTpm2Cmd(t *testing.T, cmdName string, args ...string) string {
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
