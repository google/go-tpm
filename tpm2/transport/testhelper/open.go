package testhelper

import (
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/simulator"
	"github.com/google/go-tpm/tpm2/transport/tcp"
)

var (
	tpmSimPath = flag.String("tpm-sim-path", "", "Path to a TPM simulator binary")
)

type process struct {
	tb   testing.TB
	cmd  *exec.Cmd
	conn *tcp.TPM
}

func startProcess(tb testing.TB, path string) *process {
	dir, err := os.MkdirTemp("", "tpm-sim-*")
	if err != nil {
		tb.Fatalf("failed to create temp dir: %v", err)
	}

	p := &process{
		tb:  tb,
		cmd: exec.Command(path, "--pick_ports"),
	}
	p.cmd.Dir = dir

	keep := false
	defer func() {
		if !keep {
			p.Close()
		}
	}()

	if err := p.cmd.Start(); err != nil {
		tb.Fatalf("failed to start simulator process: %v", err)
	}

	cPort, pPort, err := readPorts(p.cmd.Dir)
	if err != nil {
		tb.Fatalf("failed to read ports: %v", err)
	}
	p.conn, err = tcp.Open(tcp.Config{
		CommandAddress:  fmt.Sprintf("127.0.0.1:%d", cPort),
		PlatformAddress: fmt.Sprintf("127.0.0.1:%d", pPort),
	})
	if err != nil {
		tb.Fatalf("failed to open TCP connection to simulator: %v", err)
	}

	if err := p.conn.PowerOn(); err != nil {
		tb.Fatalf("failed to power on simulator: %v", err)
	}

	startupCmd := tpm2.Startup{StartupType: tpm2.TPMSUClear}
	if _, err = startupCmd.Execute(p.conn); err != nil {
		tb.Fatalf("failed to startup simulator: %v", err)
	}

	keep = true
	return p
}

func (p *process) Send(cmd []byte) ([]byte, error) {
	rsp, err := p.conn.Send(cmd)
	if err == nil {
		if hdr, err := tpm2.Unmarshal[tpm2.TPMRspHeader](rsp); err == nil {
			if hdr.ResponseCode == tpm2.TPMRCRetry {
				return p.conn.Send(cmd)
			}
		}
	}
	return rsp, err
}

// Close implements the TPMCloser interface.
func (p *process) Close() error {
	var err error
	var stopped bool
	if p.conn != nil {
		if err = p.conn.Stop(); err == nil {
			stopped = true
		} else {
			p.tb.Errorf("failed to stop simulator: %v", err)
		}
		if err = p.conn.Close(); err != nil {
			p.tb.Errorf("failed to close simulator connection: %v", err)
		}
	}

	if stopped {
		if err = p.cmd.Wait(); err != nil {
			p.tb.Errorf("failed to wait for simulator process: %v", err)
		}
	} else if p.cmd.Process != nil {
		if err = p.cmd.Process.Kill(); err != nil {
			p.tb.Errorf("failed to kill simulator process: %v", err)
		}
	}

	if err = os.RemoveAll(p.cmd.Dir); err != nil {
		p.tb.Errorf("failed to remove temp dir %q: %v", p.cmd.Dir, err)
	}
	return err
}

func Open(tb testing.TB) transport.TPMCloser {
	if *tpmSimPath != "" {
		return startProcess(tb, *tpmSimPath)
	}
	tpm, err := simulator.OpenSimulator()
	if err != nil {
		tb.Fatalf("Unable to OpenSimulator: %v", err)
	}
	return tpm
}

func readPorts(dir string) (cmdPort, platPort int, err error) {
	fsys := os.DirFS(dir)

	tryRead := func() (int, int, bool) {
		cBytes, err1 := fs.ReadFile(fsys, "command.port")
		pBytes, err2 := fs.ReadFile(fsys, "platform.port")
		if err1 != nil || err2 != nil {
			return 0, 0, false
		}
		cPort, err1 := strconv.Atoi(strings.TrimSpace(string(cBytes)))
		pPort, err2 := strconv.Atoi(strings.TrimSpace(string(pBytes)))
		if err1 != nil || err2 != nil {
			return 0, 0, false
		}
		return cPort, pPort, true
	}

	timeout := time.After(5 * time.Second)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-timeout:
			return 0, 0, fmt.Errorf("timed out waiting for simulator port files")
		case <-ticker.C:
			if cPort, pPort, ok := tryRead(); ok {
				return cPort, pPort, nil
			}
		}
	}
}
