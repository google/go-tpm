//go:build !windows

// Copyright (c) 2018, Google LLC All rights reserved.
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
	"os"
)

// OpenTPM opens a channel to the TPM at the given path.
func OpenTPM(path string) (io.ReadWriteCloser, error) {
	// If it's a regular file, then open it
	fi, err := os.Stat(path)

	if err != nil {
		return nil, err
	}

	if fi.Mode()&os.ModeDevice == 0 {
		return nil, fmt.Errorf("unsupported TPM file mode %s", fi.Mode().String())
	}

	var f *os.File
	if f, err = os.OpenFile(path, os.O_RDWR, 0600); err != nil {
		return nil, err
	}

	return io.ReadWriteCloser(f), nil
}
