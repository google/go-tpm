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

package tpmutil

import (
	"fmt"
	"io"
	"syscall"
	"unsafe"
)

// Tbs.dll provides an API for making calls to the TPM:
// https://docs.microsoft.com/en-us/windows/desktop/TBS/tpm-base-services-portal
var (
	tbsDLL           = syscall.NewLazyDLL("Tbs.dll")
	tbsCreateContext = tbsDLL.NewProc("Tbsi_Context_Create")
	tbsSubmitCommand = tbsDLL.NewProc("Tbsip_Submit_Command")
	tbsContextClose  = tbsDLL.NewProc("Tbsip_Context_Close")
)

// tbsContextParams2 specifies the version of TPM and TBS implementation:
// https://docs.microsoft.com/en-us/windows/desktop/api/Tbs/ns-tbs-tdtbs_context_params2
type tbsContextParams2 struct {
	version uint32
	flags   uint32
}

// tbs.h contains constants used in the TBS library:
// https://github.com/tpn/winsdk-10/blob/master/Include/10.0.10240.0/shared/tbs.h
const (
	tpm2Version            uint32  = 2 // value of TPM_VERSION_20 tbs.h constant
	bothTPMVersionsFlag    uint32  = 6 // value of union struct to include TPM 1.2 and 2.0 (see tbsContextParams2)
	tbsCommandLocalityZero uintptr = 0 // value of TBS_COMMAND_LOCALITY_ZERO tbs.h constant
)

// CommandPriority Parameter Docs:
// https://docs.microsoft.com/en-us/windows/desktop/api/Tbs/nf-tbs-tbsip_submit_command#parameters
type CommandPriority uint32

// CommandPriority is used to determine which pending command to submit whenever the TPM is free:
// https://docs.microsoft.com/en-us/windows/desktop/tbs/command-scheduling
const (
	LowPriority    CommandPriority = 100 // For low priority application use.
	NormalPriority CommandPriority = 200 // For normal priority application use.
	HighPriority   CommandPriority = 300 // For high priority application use.
	SystemPriority CommandPriority = 400 // For system tasks that access the TPM.
)

// TBS Error Codes:
// https://docs.microsoft.com/en-us/windows/desktop/TBS/tbs-return-codes
var errMap = map[uintptr]string{
	0x80284001: "An internal software error occurred.",
	0x80284002: "One or more parameter values are not valid.",
	0x80284003: "A specified output pointer is bad.",
	0x80284004: "The specified context handle does not refer to a valid context.",
	0x80284005: "The specified output buffer is too small.",
	0x80284006: "An error occurred while communicating with the TPM.",
	0x80284007: "A context parameter that is not valid was passed when attempting to create a TBS context.",
	0x80284008: "The TBS service is not running and could not be started.",
	0x80284009: "A new context could not be created because there are too many open contexts.",
	0x8028400A: "A new virtual resource could not be created because there are too many open virtual resources.",
	0x8028400B: "The TBS service has been started but is not yet running.",
	0x8028400C: "The physical presence interface is not supported.",
	0x8028400D: "The command was canceled.",
	0x8028400E: "The input or output buffer is too large.",
	0x8028400F: "A compatible Trusted Platform Module (TPM) Security Device cannot be found on this computer.",
	0x80284010: "The TBS service has been disabled.",
	0x80284011: "The TBS event log is not available.",
	0x80284012: "The caller does not have the appropriate rights to perform the requested operation.",
	0x80284013: "The TPM provisioning action is not allowed by the specified flags.",
	0x80284014: "The Physical Presence Interface of this firmware does not support the requested method.",
	0x80284015: "The requested TPM OwnerAuth value was not found.",
}

func tbsError(err uintptr) error {
	if err == 0 {
		return nil
	}
	if description, ok := errMap[err]; ok {
		return fmt.Errorf("TBS Error %v: %s", err, description)
	}
	return fmt.Errorf("Unrecognized TBS Error %v", err)
}

// winTPMBuffer is a ReadWriteCloser to access the TPM in Windows.
type winTPMBuffer struct {
	context   uintptr
	outBuffer []byte
	priority  CommandPriority
}

// Executes the TPM command specified by commandBuffer, returning the number of bytes in the command
// and any error code returned by executing the TPM command. Command response can be read by calling
// Read().
func (rwc *winTPMBuffer) Write(commandBuffer []byte) (int, error) {
	// TPM spec defines longest possible response to be maxTPMResponse.
	outBufferLen := maxTPMResponse
	rwc.outBuffer = rwc.outBuffer[:outBufferLen]

	// TBS_RESULT Tbsip_Submit_Command(
	//   _In_          TBS_HCONTEXT         hContext,
	//   _In_          TBS_COMMAND_LOCALITY Locality,
	//   _In_          TBS_COMMAND_PRIORITY Priority,
	//   _In_    const PCBYTE               *pabCommand,
	//   _In_          UINT32               cbCommand,
	//   _Out_         PBYTE                *pabResult,
	//   _Inout_       UINT32               *pcbOutput
	// );
	errResp, _, _ := tbsSubmitCommand.Call(
		rwc.context,
		tbsCommandLocalityZero, // Windows currently only supports TBS_COMMAND_LOCALITY_ZERO.
		uintptr(rwc.priority),
		uintptr(unsafe.Pointer(&(commandBuffer[0]))),
		uintptr(len(commandBuffer)),
		uintptr(unsafe.Pointer(&(rwc.outBuffer[0]))),
		uintptr(unsafe.Pointer(&outBufferLen)),
	)

	// Shrink outBuffer so it is length of response.
	rwc.outBuffer = rwc.outBuffer[:outBufferLen]
	return len(commandBuffer), tbsError(errResp)
}

// Provides TPM response from the command called in the last Write call.
func (rwc *winTPMBuffer) Read(responseBuffer []byte) (int, error) {
	if len(rwc.outBuffer) == 0 {
		return 0, io.EOF
	}
	lenCopied := copy(responseBuffer, rwc.outBuffer)
	// Implements same behavior as linux "/dev/tpm0": discard unread components after read.
	rwc.outBuffer = rwc.outBuffer[:0]
	return lenCopied, nil
}

func (rwc *winTPMBuffer) Close() error {
	// TBS_RESULT Tbsip_Context_Close(
	//   _In_ TBS_HCONTEXT hContext
	// );
	errResp, _, _ := tbsContextClose.Call(rwc.context)
	return tbsError(errResp)
}

// OpenTPM creates a new instance of a ReadWriteCloser which can interact with a
// Windows TPM. OpenTPM takes in the a CommandPriority at which to run commands.
func OpenTPM(commandPriority CommandPriority) (io.ReadWriteCloser, error) {
	params := tbsContextParams2{
		version: tpm2Version,
		flags:   bothTPMVersionsFlag,
	}

	rwc := winTPMBuffer{
		outBuffer: make([]byte, 0, maxTPMResponse),
		priority:  commandPriority,
	}
	// TBS_RESULT Tbsi_Context_Create(
	//   _In_  PCTBS_CONTEXT_PARAMS pContextParams,
	//   _Out_ PTBS_HCONTEXT        *phContext
	// );
	errResp, _, _ := tbsCreateContext.Call(
		uintptr(unsafe.Pointer(&params)),
		uintptr(unsafe.Pointer(&rwc.context)),
	)
	return &rwc, tbsError(errResp)
}
