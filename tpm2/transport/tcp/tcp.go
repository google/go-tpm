// Package tcp provides access to a TPM over TCP.
package tcp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

var (
	ErrPlatformFailed = errors.New("platform command failed")
	ErrTPMFailed      = errors.New("TPM command failed")
	ErrResponseTooBig = errors.New("response too big")
	ErrTransport      = errors.New("TCP transport error")
	ErrEmptyResponse  = errors.New("TPM returned empty response (does it need to be powered on?)")
)

const (
	maxBufferSize = 1048576
)

// The de-facto TPM-over-TCP protocol is defined by the Reference Implementation.
// See https://github.com/TrustedComputingGroup/TPM/blob/main/TPMCmd/Simulator/include/TpmTcpProtocol.h

type regularCommand uint32

const (
	tpmHashStart            regularCommand = 5
	tpmHashData             regularCommand = 6
	tpmHashEnd              regularCommand = 7
	tpmSendCommand          regularCommand = 8
	tpmRemoteHandshake      regularCommand = 15
	tpmSetAlternativeResult regularCommand = 16
	tpmSessionEnd           regularCommand = 20
	tpmStop                 regularCommand = 21
)

func (c regularCommand) String() string {
	switch c {
	case tpmHashStart:
		return "HASH_START"
	case tpmHashData:
		return "HASH_DATA"
	case tpmHashEnd:
		return "HASH_END"
	case tpmSendCommand:
		return "SEND_COMMAND"
	case tpmRemoteHandshake:
		return "REMOTE_HANDSHAKE"
	case tpmSetAlternativeResult:
		return "SET_ALTERNATIVE_RESULT"
	case tpmSessionEnd:
		return "SESSION_END"
	case tpmStop:
		return "STOP"
	default:
		return fmt.Sprintf("unknown TPM command (%v)", uint32(c))
	}
}

type platformCommand uint32

const (
	platformPowerOn                 platformCommand = 1
	platformPowerOff                platformCommand = 2
	platformPPOn                    platformCommand = 3
	platformPPOff                   platformCommand = 4
	platformCancelOn                platformCommand = 9
	platformCancelOff               platformCommand = 10
	platformNVOn                    platformCommand = 11
	platformNVOff                   platformCommand = 12
	platformKeyCacheOn              platformCommand = 13
	platformKeyCacheOff             platformCommand = 14
	platformReset                   platformCommand = 17
	platformRestart                 platformCommand = 18
	platformSessionEnd              platformCommand = 20
	platformStop                    platformCommand = 21
	platformGetCommandResponseSizes platformCommand = 25
	platformACTGetSignaled          platformCommand = 26
	platformTestFailureMode         platformCommand = 30
	platformSetFWHash               platformCommand = 35
	platformSetFWSVN                platformCommand = 36
)

func (c platformCommand) String() string {
	switch c {
	case platformPowerOn:
		return "POWER_ON"
	case platformPowerOff:
		return "POWER_OFF"
	case platformPPOn:
		return "PP_ON"
	case platformPPOff:
		return "PP_OFF"
	case platformCancelOn:
		return "CANCEL_ON"
	case platformCancelOff:
		return "CANCEL_OFF"
	case platformNVOn:
		return "NV_ON"
	case platformNVOff:
		return "NV_OFF"
	case platformKeyCacheOn:
		return "KEY_CACHE_ON"
	case platformKeyCacheOff:
		return "KEY_CACHE_OFF"
	case platformReset:
		return "RESET"
	case platformRestart:
		return "RESTART"
	case platformSessionEnd:
		return "SESSION_END"
	case platformStop:
		return "STOP"
	case platformGetCommandResponseSizes:
		return "GET_COMMAND_RESPONSE_SIZES"
	case platformACTGetSignaled:
		return "ACT_GET_SIGNALED"
	case platformTestFailureMode:
		return "TEST_FAILURE_MODE"
	case platformSetFWHash:
		return "SET_FW_HASH"
	case platformSetFWSVN:
		return "SET_FW_SVN"
	default:
		return fmt.Sprintf("unknown platform command (%v)", uint32(c))
	}
}

type TPM struct {
	cmd  *net.TCPConn
	plat *net.TCPConn
}

type tpmCommandHeader struct {
	tcpCommand regularCommand
	locality   uint8
	cmdLen     uint32
}

// Send implements the TPMCloser interface.
func (t *TPM) Send(cmd []byte) ([]byte, error) {
	hdr := tpmCommandHeader{
		tcpCommand: tpmSendCommand,
		locality:   0,
		cmdLen:     uint32(len(cmd)),
	}
	// Write the header followed by the request
	if err := binary.Write(t.cmd, binary.BigEndian, hdr); err != nil {
		return nil, fmt.Errorf("%w: could not send TPM command to service: %v", ErrTransport, err)
	}
	if n, err := t.cmd.Write(cmd); err != nil {
		return nil, fmt.Errorf("%w: could not send TPM command to service: %v", ErrTransport, err)
	} else if n != len(cmd) {
		return nil, fmt.Errorf("%w: could not send full TPM command: only sent %v out of %v bytes", ErrTransport, n, len(cmd))
	}

	// Read the response
	var rspLen uint32
	if err := binary.Read(t.cmd, binary.BigEndian, &rspLen); err != nil {
		return nil, fmt.Errorf("%w: could not read TPM response from service: %v", ErrTransport, err)
	}
	if rspLen > maxBufferSize {
		return nil, fmt.Errorf("%w: response (%v bytes) was bigger than max size (%v bytes)", ErrResponseTooBig, rspLen, maxBufferSize)
	}
	rsp := make([]byte, int(rspLen))
	if n, err := t.cmd.Read(rsp); err != nil {
		return nil, fmt.Errorf("%w: could not read TPM response from service: %v", ErrTransport, err)
	} else if n != len(rsp) {
		return nil, fmt.Errorf("%w: could not read full TPM response: only got %v out of %v bytes", ErrTransport, n, len(rsp))
	}
	// The server also provides a TCP error code at the end.
	var rspCode uint32
	if err := binary.Read(t.cmd, binary.BigEndian, &rspCode); err != nil {
		return nil, fmt.Errorf("%w: %v returned %v", ErrTPMFailed, hdr.tcpCommand, rspCode)
	}
	if rspLen == 0 {
		return nil, ErrEmptyResponse
	}
	return rsp, nil
}

// Close implements the TPMCloser interface.
func (t *TPM) Close() error {
	return errors.Join(t.cmd.Close(), t.plat.Close())
}

// PowerOn powers on the TPM.
// Note: This is distinct from sending the TPM2_Startup command.
func (t *TPM) PowerOn() error {
	return errors.Join(t.sendBasicPlatformCommand(platformPowerOn),
		t.sendBasicPlatformCommand(platformNVOn))
}

// PowerOff powers off the TPM.
func (t *TPM) PowerOff() error {
	return errors.Join(t.sendBasicPlatformCommand(platformPowerOff),
		t.sendBasicPlatformCommand(platformNVOff))
}

// Reset power-cycles the TPM if it is already on. If it is not already on,
// nothing happens.
func (t *TPM) Reset() error {
	return t.sendBasicPlatformCommand(platformReset)
}

// Config provides the connection information for a running TCP TPM.
type Config struct {
	// CommandAddress is the full host:port address of the Command server, e.g.,
	// "localhost:2321"
	CommandAddress string
	// CommandAddress is the full host:port address of the Platform server, e.g.,
	// "localhost:2322"
	PlatformAddress string
}

func resolveAndConnect(addr string) (*net.TCPConn, error) {
	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("could not resolve %q: %w", addr, err)
	}

	conn, err := net.DialTCP("tcp", nil, tcpAddr)
	if err != nil {
		return nil, fmt.Errorf("could not dial %q: %w", addr, err)
	}
	return conn, nil
}

// Open opens a connection to the TPM. It may still need to be powered on using PowerOn().
func Open(config Config) (*TPM, error) {
	cmd, err := resolveAndConnect(config.CommandAddress)
	if err != nil {
		return nil, fmt.Errorf("could not connect to command service at %q: %w", config.CommandAddress, err)
	}
	plat, err := resolveAndConnect(config.PlatformAddress)
	if err != nil {
		return nil, fmt.Errorf("could not connect to platform service at %q: %w", config.PlatformAddress, err)
	}

	return &TPM{
		cmd:  cmd,
		plat: plat,
	}, nil
}

// sendBasicPlatformCommand sends a command to the platform service. This only
// supports 'basic' commands (i.e., send just a command code, receive just a
// response code).
func (t *TPM) sendBasicPlatformCommand(cmd platformCommand) error {
	if err := binary.Write(t.plat, binary.BigEndian, cmd); err != nil {
		return fmt.Errorf("could not write %v to platform service: %w", cmd, err)
	}
	var result uint32
	if err := binary.Read(t.plat, binary.BigEndian, &result); err != nil {
		return fmt.Errorf("could not read %v result from platform service: %w", cmd, err)
	}
	if result != 0 {
		return fmt.Errorf("%w: %v returned %v", ErrPlatformFailed, cmd, result)
	}
	return nil
}
