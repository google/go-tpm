//go:build !windows

// Package googlemtd provides support for communicating with a Titan TPM via Linux mtd (Memory Technology Device).
package googlemtd

import (
	"context"
	"fmt"
	"os"
	"syscall"

	"github.com/google/go-tpm/tpm2/transport/googleec"
)

const (
	// DefaultMailboxAddress is the default flash address of the Titan EC mailbox
	DefaultMailboxAddress = 0x3ff0000
	// DefaultMailboxSize is the default size of the Titan EC mailbox
	DefaultMailboxSize = 1024

	minMailboxSize = 1024
	maxMailboxSize = 4096
)

// Dispatcher implements the googleec.CommandDispatcher interface.
type Dispatcher struct {
	mtd            *os.File
	mailboxAddress int64
	mailboxSize    int64
}

// DispatchCommand implements googleec.CommandDispatcher.
func (d *Dispatcher) DispatchCommand(ctx context.Context, cmd []byte) ([]byte, error) {
	if err := d.lock(); err != nil {
		return nil, err
	}
	defer d.unlock() // It's safe to call unlock multiple times.

	if err := d.send(cmd); err != nil {
		return nil, err
	}

	rsp, err := d.receive()
	if err != nil {
		return nil, err
	}

	if err := d.unlock(); err != nil {
		return nil, err
	}

	return rsp, nil
}

// DispatchCommandNoResponse implements googleec.CommandDispatcher.
func (d *Dispatcher) DispatchCommandNoResponse(ctx context.Context, cmd []byte) error {
	if err := d.lock(); err != nil {
		return err
	}
	defer d.unlock() // It's safe to call unlock multiple times.

	if err := d.send(cmd); err != nil {
		return err
	}

	return d.unlock()
}

// Options contain the configuration settings for connecting to a Titan over MTD.
type Options struct {
	// The path to the MTD device, e.g., /dev/mtd0.
	Path string
	// The address of the mailbox for requests and responses.
	// If one is not provided (is 0), uses 0x3ff0000.
	MailboxAddress int64
	// The size of the mailbox, in bytes.
	// If one is not provided (is 0), uses 1024.
	MailboxSize int64
}

// NewDispatcher initializes a new connection to the Titan over mtd.
func NewDispatcher(opts Options) (*Dispatcher, error) {
	mailbox := opts.MailboxAddress
	if mailbox == 0 {
		mailbox = DefaultMailboxAddress
	}
	mailboxSize := opts.MailboxSize
	if mailboxSize == 0 {
		mailboxSize = DefaultMailboxSize
	}

	if mailboxSize < minMailboxSize {
		return nil, fmt.Errorf("mailbox size %v is too small (minimum %d bytes)", mailboxSize, minMailboxSize)
	}
	if mailboxSize > maxMailboxSize {
		return nil, fmt.Errorf("mailbox size %v is too large (maximum %d bytes)", mailboxSize, maxMailboxSize)
	}

	mtd, err := os.OpenFile(opts.Path, os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("could not open mtd device: %w", err)
	}

	return &Dispatcher{
		mtd:            mtd,
		mailboxAddress: mailbox,
		mailboxSize:    mailboxSize,
	}, nil
}

// Close closes the mtd connection to the Titan.
func (d *Dispatcher) Close() error {
	return d.mtd.Close()
}

// lock performs a file lock on the mtd file.
func (d *Dispatcher) lock() error {
	fd := int(d.mtd.Fd())
	if err := syscall.Flock(fd, syscall.LOCK_EX); err != nil {
		return fmt.Errorf("could not lock mtd file: %w", err)
	}
	return nil
}

// unlock performs a file unlock on the mtd file. It's safe to call this multiple times.
func (d *Dispatcher) unlock() error {
	fd := int(d.mtd.Fd())
	if err := syscall.Flock(fd, syscall.LOCK_UN); err != nil {
		return fmt.Errorf("could not unlock mtd file: %w", err)
	}
	return nil
}

// send writes a request to the mtd device's mailbox.
func (d *Dispatcher) send(cmd []byte) error {
	if int64(len(cmd)) > d.mailboxSize {
		return fmt.Errorf("command of size %v doesn't fit into the mailbox of size %v", len(cmd), d.mailboxSize)
	}

	n, err := d.mtd.WriteAt(cmd, d.mailboxAddress)
	if err != nil {
		return fmt.Errorf("could not write to mailbox: %w", err)
	}
	if n != len(cmd) {
		return fmt.Errorf("only sent %v out of %v bytes", n, len(cmd))
	}

	return nil
}

// receive reads the response from the mtd device's mailbox.
func (d *Dispatcher) receive() ([]byte, error) {
	// Read the size of the response from the mailbox.
	rsp := make([]byte, d.mailboxSize)
	read, err := d.mtd.ReadAt(rsp[:googleec.HostHeaderLen], d.mailboxAddress)
	if err != nil {
		return nil, err
	}
	if read != googleec.HostHeaderLen {
		return nil, fmt.Errorf("did not read enough data for an EC response header (only %v bytes)", read)
	}

	// Parse the EC response header to get the size.
	rest, err := googleec.PeekResponse(rsp[:googleec.HostHeaderLen])
	if err != nil {
		return nil, fmt.Errorf("could not read EC response header from mailbox: %w", err)
	}

	if int64(rest) > d.mailboxSize-int64(googleec.HostHeaderLen) {
		return nil, fmt.Errorf("reported response size of %v bytes was too large to fit into the mailbox (size %v bytes)", int(rest)+googleec.HostHeaderLen, d.mailboxSize)
	}

	// Read the rest of the response.
	read, err = d.mtd.ReadAt(rsp[googleec.HostHeaderLen:googleec.HostHeaderLen+rest], d.mailboxAddress+int64(googleec.HostHeaderLen))
	if err != nil {
		return nil, fmt.Errorf("could not read EC response from mailbox: %w", err)
	}
	if read != int(rest) {
		return nil, fmt.Errorf("did not read all of the EC response after the header (only %v bytes)", read)
	}

	return rsp[:googleec.HostHeaderLen+rest], nil
}
