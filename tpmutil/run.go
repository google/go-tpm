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

// Package tpmutil provides common utility functions for both TPM 1.2 and TPM 2.0 devices.
package tpmutil

import (
	"encoding/binary"
	"errors"
	"io"
)

const maxTPMResponse = 4096

// RunCommand executes cmd with given tag and arguments. Returns TPM response
// body (without response header) and response code from the header. Returned
// error may be nil if response code is not RCSuccess, caller should check
// both.
func RunCommand(rw io.ReadWriter, tag Tag, cmd Command, in ...interface{}) ([]byte, ResponseCode, error) {
	if rw == nil {
		return nil, 0, errors.New("nil TPM handle")
	}

	ch := commandHeader{tag, 0, cmd}
	inb, err := packWithHeader(ch, in...)
	if err != nil {
		return nil, 0, err
	}

	if _, err := rw.Write(inb); err != nil {
		return nil, 0, err
	}

	outb := make([]byte, maxTPMResponse)
	outlen, err := rw.Read(outb)
	if err != nil {
		return nil, 0, err
	}
	// Resize the buffer to match the amount read from the TPM.
	outb = outb[:outlen]

	var rh responseHeader
	rhSize := binary.Size(rh)
	if err := Unpack(outb[:rhSize], &rh); err != nil {
		return nil, 0, err
	}

	if rh.Res != RCSuccess {
		return nil, rh.Res, nil
	}

	return outb[rhSize:], rh.Res, nil
}
