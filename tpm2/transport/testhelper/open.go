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
	dir  string
	conn *tcp.TPM
}

func startProcess(tb testing.TB, path string) *process {
	p := &process{tb: tb}
	keep := false
	defer func() {
		if !keep {
			p.Close()
		}
	}()

	dir, err := os.MkdirTemp("", "tpm-sim-*")
	if err != nil {
		tb.Fatalf("failed to create temp dir: %v", err)
	}
	p.dir = dir

	cmd := exec.Command(path, "--pick_ports")
	cmd.Dir = dir
	if err := cmd.Start(); err != nil {
		tb.Fatalf("failed to start simulator process: %v", err)
	}
	p.cmd = cmd

	cmdPort, platPort, err := readPorts(dir)
	if err != nil {
		tb.Fatalf("failed to read ports: %v", err)
	}
	conn, err := tcp.Open(tcp.Config{
		CommandAddress:  fmt.Sprintf("127.0.0.1:%d", cmdPort),
		PlatformAddress: fmt.Sprintf("127.0.0.1:%d", platPort),
	})
	if err != nil {
		tb.Fatalf("failed to open TCP connection to simulator: %v", err)
	}
	p.conn = conn

	if err := conn.PowerOn(); err != nil {
		tb.Fatalf("failed to power on simulator: %v", err)
	}

	_, err = tpm2.Startup{
		StartupType: tpm2.TPMSUClear,
	}.Execute(conn)
	if err != nil {
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
	var killed bool
	if p.conn != nil {
		if err = p.conn.Stop(); err != nil {
			p.tb.Errorf("failed to stop simulator: %v", err)
			if p.cmd != nil && p.cmd.Process != nil {
				p.cmd.Process.Kill()
				killed = true
			}
		}
		if err = p.conn.Close(); err != nil {
			p.tb.Errorf("failed to close simulator connection: %v", err)
		}
	} else {
		if p.cmd != nil && p.cmd.Process != nil {
			p.cmd.Process.Kill()
			killed = true
		}
	}
	if p.cmd != nil {
		if werr := p.cmd.Wait(); werr != nil && !killed {
			p.tb.Errorf("failed to wait for simulator process: %v", werr)
			err = werr
		}
	}
	if p.dir != "" {
		if derr := os.RemoveAll(p.dir); derr != nil {
			p.tb.Errorf("failed to remove temp dir %q: %v", p.dir, derr)
			err = derr
		}
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
		cmdPortBytes, err1 := fs.ReadFile(fsys, "command.port")
		platPortBytes, err2 := fs.ReadFile(fsys, "platform.port")
		if err1 == nil && err2 == nil {
			cmdPortStr := strings.TrimSpace(string(cmdPortBytes))
			platPortStr := strings.TrimSpace(string(platPortBytes))
			if cmdPortStr != "" && platPortStr != "" {
				cmdPort, err1 := strconv.Atoi(cmdPortStr)
				platPort, err2 := strconv.Atoi(platPortStr)
				if err1 == nil && err2 == nil {
					return cmdPort, platPort, true
				}
			}
		}
		return 0, 0, false
	}

	timeout := time.After(5 * time.Second)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-timeout:
			return 0, 0, fmt.Errorf("timed out waiting for simulator port files")
		case <-ticker.C:
			if cmdPort, platPort, ok := tryRead(); ok {
				return cmdPort, platPort, nil
			}
		}
	}
}
