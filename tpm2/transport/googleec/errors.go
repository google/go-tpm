//go:build !windows

package googleec

import (
	"fmt"
)

// DecodeError returns the given error code as an error.
// Returns:
// * nil if the result code was success (0)
// * an Error if the error was within the EC error space
// * an ExtendedError otherwise
func DecodeError(code uint16) error {
	if code == success {
		return nil
	}
	if ecErr := Error(code); ecErr <= lastECError {
		return ecErr
	}
	return ExtendedError(code)
}

// Error represents an EC error code within the general EC error space.
type Error uint16

const (
	// success is EC_RES_SUCCESS, and is intentionally not exported or defined as an error (or an Error).
	success uint16 = 0
	// ErrInvalidCommand is EC_RES_INVALID_COMMAND
	ErrInvalidCommand Error = 1
	// ErrGenericError is EC_RES_ERROR
	ErrGenericError Error = 2
	// ErrInvalidParam is EC_RES_INVALID_PARAM
	ErrInvalidParam Error = 3
	// ErrAccessDenied is EC_RES_ACCESS_DENIED
	ErrAccessDenied Error = 4
	// ErrInvalidResponse is EC_RES_INVALID_RESPONSE
	ErrInvalidResponse Error = 5
	// ErrInvalidVersion is EC_RES_INVALID_VERSION
	ErrInvalidVersion Error = 6
	// ErrInvalidChecksum is EC_RES_INVALID_CHECKSUM
	ErrInvalidChecksum Error = 7
	// ErrInProgress is EC_RES_IN_PROGRESS
	ErrInProgress Error = 8
	// ErrUnavailable is EC_RES_UNAVAILABLE
	ErrUnavailable Error = 9
	// ErrTimeout is EC_RES_TIMEOUT
	ErrTimeout Error = 10
	// ErrOverflow is EC_RES_OVERFLOW
	ErrOverflow Error = 11
	// ErrInvalidHeader is EC_RES_INVALID_HEADER
	ErrInvalidHeader Error = 12
	// ErrRequestTruncated is EC_RES_REQUEST_TRUNCATED
	ErrRequestTruncated Error = 13
	// ErrResponseTooBig is EC_RES_RESPONSE_TOO_BIG
	ErrResponseTooBig Error = 14
	// ErrBusError is EC_RES_BUS_ERROR
	ErrBusError Error = 15
	// ErrBusy is EC_RES_BUSY
	ErrBusy Error = 16
	// ErrInvalidHeaderVersion is EC_RES_INVALID_HEADER_VERSION
	ErrInvalidHeaderVersion Error = 17
	// ErrInvalidHeaderCRC is EC_RES_INVALID_HEADER_CRC
	ErrInvalidHeaderCRC Error = 18
	// ErrInvalidDataCRC is EC_RES_INVALID_DATA_CRC
	ErrInvalidDataCRC Error = 19
	// ErrDupUnavailable is EC_RES_DUP_UNAVAILABLE
	ErrDupUnavailable Error = 20
	// lastECError is the highest-valued error in the ec namespace.
	lastECError = ErrDupUnavailable
)

// Error returns the string representation of the Error.
func (code Error) Error() string {
	switch code {
	case ErrInvalidCommand:
		return "EC_RES_INVALID_COMMAND"
	case ErrGenericError:
		return "EC_RES_ERROR"
	case ErrInvalidParam:
		return "EC_RES_INVALID_PARAM"
	case ErrAccessDenied:
		return "EC_RES_ACCESS_DENIED"
	case ErrInvalidResponse:
		return "EC_RES_INVALID_RESPONSE"
	case ErrInvalidVersion:
		return "EC_RES_INVALID_VERSION"
	case ErrInvalidChecksum:
		return "EC_RES_INVALID_CHECKSUM"
	case ErrInProgress:
		return "EC_RES_IN_PROGRESS"
	case ErrUnavailable:
		return "EC_RES_UNAVAILABLE"
	case ErrTimeout:
		return "EC_RES_TIMEOUT"
	case ErrOverflow:
		return "EC_RES_OVERFLOW"
	case ErrInvalidHeader:
		return "EC_RES_INVALID_HEADER"
	case ErrRequestTruncated:
		return "EC_RES_REQUEST_TRUNCATED"
	case ErrResponseTooBig:
		return "EC_RES_RESPONSE_TOO_BIG"
	case ErrBusError:
		return "EC_RES_BUS_ERROR"
	case ErrBusy:
		return "EC_RES_BUSY"
	case ErrInvalidHeaderVersion:
		return "EC_RES_INVALID_HEADER_VERSION"
	case ErrInvalidHeaderCRC:
		return "EC_RES_INVALID_HEADER_CRC"
	case ErrInvalidDataCRC:
		return "EC_RES_INVALID_DATA_CRC"
	case ErrDupUnavailable:
		return "EC_RES_DUP_UNAVAILABLE"
	default:
		return fmt.Sprintf("unknown EC error code (%x)", uint16(code))
	}
}

// ExtendedError represents an error code returned from an EC that is outside
// the EC error space. Packages that send EC commands may cast errors of this
// type into their own error space.
type ExtendedError uint16

// Error returns the string representation of the ExtendedError.
func (code ExtendedError) Error() string {
	return fmt.Sprintf("extended EC error code (%x)", uint16(code))
}
