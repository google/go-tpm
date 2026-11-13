package googleipmi

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"math"
)

// commandDispatcher encapsulates how to send a raw (EC) command to Titan and
// read the response.
type commandDispatcher interface {
	// dispatchCommand submits a fully formatted command to the Titan and
	// returns the fully response (i.e., no wrapping or unwrapping; treats the
	// command and response as opaque byte arrays).
	dispatchCommand(ctx context.Context, cmd []byte) ([]byte, error)

	// dispatchCommandNoResponse submits a fully formatted command to the Titan,
	// but discards the response. This is useful for commands where the response
	// is not required (i.e. SoftReset).
	dispatchCommandNoResponse(ctx context.Context, cmd []byte) error

	// close closes the connection to the Titan, releasing any held resources.
	close() error
}

// getEcChecksum calculates the Titan EC checksum of the given data.
// The checksum is designed such that the sum of all octets in a valid Titan EC
// request or response is 0 (mod 256).
func getECChecksum(data ...[]byte) byte {
	sum := byte(0)
	for _, array := range data {
		for _, val := range array {
			sum += val
		}
	}

	// Intentional underflow because sum of all bytes should equal to 0.
	return -sum
}

// ecSendCommand delivers EC command and extra params(if any) to Titan using the
// given command dispatcher.
func ecSendCommand(ctx context.Context, cd commandDispatcher, cmd ecCommand, args ...any) ([]byte, error) {
	ecCmd, err := formatEcCommand(cmd, args...)
	if err != nil {
		return nil, err
	}

	rsp, err := cd.dispatchCommand(ctx, ecCmd)
	if err != nil {
		return nil, err
	}

	unwrappedRsp, err := parseResponse(rsp)
	if err != nil {
		return nil, err
	}

	return unwrappedRsp, nil
}

// ecCommand represents an EC command.
type ecCommand struct {
	Code    uint16
	Version uint8
}

// hostHeaderLen is the packed size of a Titan EC host request or response header.
const hostHeaderLen = 8

// ecHostRequestHeader is an ec_host_request and has size hostHeaderLen.
type ecHostRequestHeader struct {
	StructVersion  uint8
	Checksum       uint8
	Command        uint16
	CommandVersion uint8
	Reserved       uint8
	DataLen        uint16
}

// ecHostResponseHeader is an ec_host_response and has size hostHeaderLen.
type ecHostResponseHeader struct {
	StructVersion uint8
	Checksum      uint8
	ResultCode    uint16
	DataLen       uint16
	Reserved      uint16
}

// formatEcCommand formats a Titan host command with given parameters as a raw
// EC command byte array. All parameters must be either sized integral primitive
// types (e.g., uint16, int32), or structs containing valid parameters.
func formatEcCommand(cmd ecCommand, args ...any) ([]byte, error) {
	var argBuf bytes.Buffer
	for _, arg := range args {
		if err := binary.Write(&argBuf, binary.LittleEndian, arg); err != nil {
			return nil, err
		}
	}

	if len(argBuf.Bytes()) > math.MaxUint16 {
		return nil, fmt.Errorf("parameters exceeded %d bytes (%d bytes)", math.MaxUint16, len(argBuf.Bytes()))
	}

	hdr := ecHostRequestHeader{
		StructVersion:  3,
		Command:        cmd.Code,
		CommandVersion: cmd.Version,
		DataLen:        uint16(len(argBuf.Bytes())),
	}
	var hdrBuf bytes.Buffer
	if err := binary.Write(&hdrBuf, binary.LittleEndian, hdr); err != nil {
		return nil, err
	}

	check := getECChecksum(hdrBuf.Bytes(), argBuf.Bytes())
	// The checksum is always at offset 1 within the header byte array.
	hdrBuf.Bytes()[1] = check
	return append(hdrBuf.Bytes(), argBuf.Bytes()...), nil
}

// peekResponse parses the first bytes of the response (at least 8), validates
// it (except for the checksum), and returns the length of the rest of the response.
// peekResponse is exported for the benefit of Titan transport protocols that
// rely on the EC response header to tell how long the response should be.
func peekResponse(response []byte) (uint16, error) {
	if len(response) < hostHeaderLen {
		return 0, fmt.Errorf("response (%d bytes) was too short to be a Titan EC response", len(response))
	}
	rspRdr := bytes.NewReader(response)
	var rspHdr ecHostResponseHeader
	if err := binary.Read(rspRdr, binary.LittleEndian, &rspHdr); err != nil {
		return 0, err
	}
	if rspHdr.StructVersion != 3 {
		return 0, fmt.Errorf("unsupported EC header version (%d)", rspHdr.StructVersion)
	}
	if err := decodeError(rspHdr.ResultCode); err != nil {
		return 0, err
	}
	return rspHdr.DataLen, nil
}

// parseResponse parses the complete EC response from the Titan, validates it
// (including the checksum), and returns the data area.
func parseResponse(response []byte) ([]byte, error) {
	if len(response) > 0xffff+hostHeaderLen { // data length is a uint16, plus size of ecHostResponseHeader
		return nil, fmt.Errorf("response (%d bytes) was too long to be a Titan EC response", len(response))
	}

	if getECChecksum(response) != 0 {
		return nil, fmt.Errorf("incorrect checksum")
	}
	dataLen, err := peekResponse(response)
	if err != nil {
		return nil, err
	}
	if int(dataLen)+hostHeaderLen != len(response) {
		return nil, fmt.Errorf("EC header DataLen (%d bytes) did not agree total response (%d bytes)", dataLen, len(response))
	}
	return response[hostHeaderLen:], nil
}
