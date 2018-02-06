// Copyright (c) 2014, Google Inc. All rights reserved.
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

// Package tpm2 supports direct communication with a TPM 2.0 device under Linux.
package tpm2

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"unsafe"
)

// OpenTPM opens a channel to the TPM at the given path. If the file is a
// device, then it treats it like a normal TPM device, and if the file is a
// Unix domain socket, then it opens a connection to the socket.
func OpenTPM(path string) (io.ReadWriteCloser, error) {
	// If it's a regular file, then open it
	var rwc io.ReadWriteCloser
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	if fi.Mode()&os.ModeDevice != 0 {
		var f *os.File
		f, err = os.OpenFile(path, os.O_RDWR, 0600)
		if err != nil {
			return nil, err
		}
		rwc = io.ReadWriteCloser(f)
	} else if fi.Mode()&os.ModeSocket != 0 {
		uc, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
		if err != nil {
			return nil, err
		}
		rwc = io.ReadWriteCloser(uc)
	} else {
		return nil, fmt.Errorf("unsupported TPM file mode %s", fi.Mode().String())
	}

	return rwc, nil
}

func encodeHandle(handle Handle) ([]byte, error) {
	return pack([]interface{}{handle})
}

func encodePasswordData(password string) ([]byte, error) {
	pw, err := hex.DecodeString(password)
	if err != nil {
		return nil, err
	}
	return pack([]interface{}{pw})
}

// returns: len0 PasswordSessionHandle 0000 01 password data as []byte
func encodePasswordAuthArea(password string, owner Handle) ([]byte, error) {
	ownerStr, err := encodeHandle(owner)
	if err != nil {
		return nil, err
	}
	suffix := []byte{0, 0, 1}
	pw, err := encodePasswordData(password)
	if err != nil {
		return nil, err
	}
	buf := append(ownerStr, suffix...)
	buf = append(buf, pw...)
	return pack([]interface{}{buf})
}

func encodeSensitiveArea(in1 []byte, in2 []byte) ([]byte, error) {
	t1, err := pack([]interface{}{in1})
	if err != nil {
		return nil, err
	}
	t2, err := pack([]interface{}{in2})
	if err != nil {
		return nil, err
	}

	t := append(t1, t2...)
	return pack([]interface{}{t})
}

func decodeRSABuf(rsaBuf []byte) (*RSAParams, error) {
	parms := new(RSAParams)
	current := 0
	template := []interface{}{&parms.EncAlg, &parms.HashAlg, &parms.Attributes, &parms.AuthPolicy}
	err := unpack(rsaBuf[current:], template)
	if err != nil {
		return nil, err
	}
	current += 10 + len(parms.AuthPolicy)
	template = []interface{}{&parms.SymAlg}
	err = unpack(rsaBuf[current:], template)
	if err != nil {
		return nil, err
	}
	current += 2
	if parms.SymAlg != AlgNULL {
		template = []interface{}{&parms.SymSize, &parms.Mode}
		err = unpack(rsaBuf[current:], template)
		if err != nil {
			return nil, err
		}
		current += 4
	} else {
		parms.SymSize = 0
		parms.Mode = 0
		parms.Scheme = 0
	}
	template = []interface{}{&parms.Scheme}
	err = unpack(rsaBuf[current:], template)
	if err != nil {
		return nil, err
	}
	current += 2
	if parms.Scheme == AlgRSASSA {
		template = []interface{}{&parms.SchemeHash}
		err = unpack(rsaBuf[current:], template)
		if err != nil {
			return nil, err
		}
		current += 2
	}

	template = []interface{}{&parms.ModSize, &parms.Exp, &parms.Modulus}
	err = unpack(rsaBuf[current:], template)
	if err != nil {
		return nil, err
	}
	return parms, nil
}

func decodeRSAArea(in []byte) (*RSAParams, error) {
	var rsaBuf []byte

	template := []interface{}{&rsaBuf}
	err := unpack(in, template)
	if err != nil {
		return nil, err
	}
	return decodeRSABuf(rsaBuf)
}

func encodeKeyedHashParams(parms KeyedHashParams) ([]byte, error) {
	template := []interface{}{
		&parms.TypeAlg,
		&parms.HashAlg,
		&parms.Attributes,
		&parms.AuthPolicy,
		&parms.Scheme,
		&parms.Unique,
	}
	return pack(template)
}

func encodeRSAParams(parms RSAParams) ([]byte, error) {
	template := []interface{}{
		&parms.EncAlg,
		&parms.HashAlg,
		&parms.Attributes,
		&parms.AuthPolicy,
	}
	t1, err := pack(template)
	if err != nil {
		return nil, err
	}

	if parms.SymAlg != AlgNULL {
		template = []interface{}{
			&parms.SymAlg,
			&parms.SymSize,
			&parms.Mode,
			&parms.Scheme,
		}
	} else {
		template = []interface{}{&parms.SymAlg, &parms.Scheme}
	}
	t2, err := pack(template)
	if err != nil {
		return nil, err
	}
	if parms.Scheme == AlgRSASSA {
		template3 := []interface{}{&parms.SchemeHash}
		t3, err := pack(template3)
		if err != nil {
			return nil, err
		}
		t2 = append(t2, t3...)
	}

	template4 := []interface{}{&parms.ModSize, &parms.Exp, parms.Modulus}
	t4, err := pack(template4)
	if err != nil {
		return nil, err
	}

	t5 := append(t1, t2...)
	t5 = append(t5, t4...)
	template5 := []interface{}{&t5}
	return pack(template5)
}

func encodeShortPCRs(pcrNums []int) ([]byte, error) {
	pcr := []byte{3, 0, 0, 0}
	var byteNum int
	var bytePos byte
	for _, e := range pcrNums {
		byteNum = 1 + e/8
		bytePos = 1 << uint16(e%8)
		pcr[byteNum] |= bytePos
	}
	return pcr, nil
}

func encodeLongPCR(count uint32, pcrNums []int) ([]byte, error) {
	if count == 0 {
		return pack([]interface{}{count})
	}
	b1, err := encodeShortPCRs(pcrNums)
	if err != nil {
		return nil, err
	}
	template := []interface{}{count, b1}
	return pack(template)
}

func encodeGetRandom(size uint16) ([]byte, error) {
	cmdHdr := commandHeader{Tag: tagNoSessions, Cmd: cmdGetRandom}
	return packWithHeader(cmdHdr, size)
}

func decodeGetRandom(in []byte) ([]byte, error) {
	var randBytes []byte

	out := []interface{}{&randBytes}
	err := unpack(in, out)
	if err != nil {
		return nil, err
	}
	return randBytes, nil
}

// GetRandom gets random bytes from the TPM.
func GetRandom(rw io.ReadWriteCloser, size uint16) ([]byte, error) {
	cmd, err := encodeGetRandom(size)
	if err != nil {
		return nil, err
	}

	resp, err := runCommand(rw, cmd)
	if err != nil {
		return nil, err
	}

	rand, err := decodeGetRandom(resp)
	if err != nil {
		return nil, err
	}
	return rand, nil
}

func encodeFlushContext(handle Handle) ([]byte, error) {
	cmdHdr := commandHeader{Tag: tagNoSessions, Cmd: cmdFlushContext}
	return packWithHeader(cmdHdr, handle)
}

// FlushContext removes an object or session under handle to be removed from
// the TPM. This must be called for any loaded handle to avoid out-of-memory
// errors in TPM.
func FlushContext(rw io.ReadWriter, handle Handle) error {
	cmd, err := encodeFlushContext(handle)
	if err != nil {
		return fmt.Errorf("failed building command: %v", err)
	}
	_, err = runCommand(rw, cmd)
	return err
}

func encodeReadPCRs(numSpec uint32, pcrs []byte) ([]byte, error) {
	cmdHdr := commandHeader{Tag: tagNoSessions, Cmd: cmdPCRRead}
	return packWithHeader(cmdHdr, numSpec, pcrs)
}

func decodeReadPCRs(in []byte) (uint32, []byte, uint16, []byte, error) {
	var pcr []byte
	var digest []byte
	var updateCounter uint32
	var t uint32
	var s uint32

	out := []interface{}{&t, &updateCounter, &pcr, &s, &digest}
	err := unpack(in, out)
	if err != nil {
		return 0, nil, 0, nil, err
	}
	return updateCounter, pcr, uint16(t), digest, nil
}

// ReadPCRs reads a PCR value from the TPM.
func ReadPCRs(rw io.ReadWriter, pcrSelect []byte) (uint32, []byte, uint16, []byte, error) {
	cmd, err := encodeReadPCRs(1, pcrSelect)
	if err != nil {
		return 1, nil, 0, nil, err
	}
	resp, err := runCommand(rw, cmd)
	if err != nil {
		return 0, nil, 0, nil, err
	}

	counter, pcr, alg, digest, err := decodeReadPCRs(resp)
	if err != nil {
		return 0, nil, 0, nil, err
	}
	return counter, pcr, alg, digest, err
}

func encodeReadClock() ([]byte, error) {
	cmdHdr := commandHeader{Tag: tagNoSessions, Cmd: cmdReadClock}
	return packWithBytes(cmdHdr, nil)
}

func decodeReadClock(in []byte) (uint64, uint64, error) {
	var curTime, curClock uint64

	template := []interface{}{&curTime, &curClock}
	err := unpack(in, template)
	if err != nil {
		return 0, 0, err
	}
	return curTime, curClock, nil
}

// ReadClock returns current clock values from the TPM.
//
// First return value is time in milliseconds since TPM was initialized (since
// system startup).
//
// Second return value is time in milliseconds since TPM reset (since Storage
// Primary Seed is changed).
func ReadClock(rw io.ReadWriter) (uint64, uint64, error) {
	cmd, err := encodeReadClock()
	if err != nil {
		return 0, 0, fmt.Errorf("building ReadClock command: %v", err)
	}
	resp, err := runCommand(rw, cmd)
	if err != nil {
		return 0, 0, err
	}
	curTime, curClock, err := decodeReadClock(resp)
	if err != nil {
		return 0, 0, err
	}
	return curTime, curClock, nil
}

func encodeGetCapability(cap Capability, count uint32, property uint32) ([]byte, error) {
	cmdHdr := commandHeader{Tag: tagNoSessions, Cmd: cmdGetCapability}
	return packWithHeader(cmdHdr, cap, property, count)
}

func decodeGetCapability(in []byte) (Capability, []Handle, error) {
	var numHandles uint32
	var capReported Capability

	out := []interface{}{&capReported, &numHandles}
	err := unpack(in[1:9], out)
	if err != nil {
		return 0, nil, err
	}
	// only TPM_CAP_HANDLES handled
	if capReported != CapabilityHandles {
		return 0, nil, fmt.Errorf("Only TPM_CAP_HANDLES supported, got %v", capReported)
	}
	var handles []Handle
	var handle Handle
	handleOut := []interface{}{&handle}
	for i := 0; i < int(numHandles); i++ {
		err := unpack(in[8+4*i:12+4*i], handleOut)
		if err != nil {
			return 0, nil, err
		}
		handles = append(handles, handle)
	}

	return capReported, handles, nil
}

// GetCapability returns various information about the TPM state.
//
// Currently only CapabilityHandles is supported (list active handles).
func GetCapability(rw io.ReadWriter, cap Capability, count uint32, property uint32) ([]Handle, error) {
	cmd, err := encodeGetCapability(cap, count, property)
	if err != nil {
		return nil, err
	}
	resp, err := runCommand(rw, cmd)
	if err != nil {
		return nil, err
	}
	_, handles, err := decodeGetCapability(resp)
	if err != nil {
		return nil, err
	}
	return handles, nil
}

func encodePCREvent(pcrNum uint32, eventData []byte) ([]byte, error) {
	cmdHdr := commandHeader{Tag: tagSessions, Cmd: cmdPCREvent}
	b1, err := pack([]interface{}{pcrNum, []byte(nil)})
	if err != nil {
		return nil, err
	}
	b2, err := encodePasswordAuthArea("", PasswordSessionHandle)
	if err != nil {
		return nil, err
	}
	b3, err := pack([]interface{}{eventData})
	if err != nil {
		return nil, err
	}
	return packWithBytes(cmdHdr, append(append(b1, b2...), b3...))
}

// PCREvent writes an update to the specified PCR.
func PCREvent(rw io.ReadWriter, pcrNum uint32, eventData []byte) error {
	cmd, err := encodePCREvent(pcrNum, eventData)
	if err != nil {
		return err
	}
	_, err = runCommand(rw, cmd)
	return err
}

func encodeCreatePrimary(owner Handle, pcrNums []int, parentPassword, ownerPassword string, parms RSAParams) ([]byte, error) {
	cmdHdr := commandHeader{Tag: tagSessions, Cmd: cmdCreatePrimary}
	b1, err := encodeHandle(Handle(owner))
	if err != nil {
		return nil, err
	}
	b2, err := pack([]interface{}{[]byte(nil)})
	if err != nil {
		return nil, err
	}
	b3, err := encodePasswordAuthArea(parentPassword, PasswordSessionHandle)
	if err != nil {
		return nil, err
	}
	t1, err := encodePasswordData(ownerPassword)
	if err != nil {
		return nil, err
	}
	b4, err := encodeSensitiveArea(t1[2:], []byte(nil))
	if err != nil {
		return nil, err
	}
	b5, err := encodeRSAParams(parms)
	if err != nil {
		return nil, err
	}
	b6, err := pack([]interface{}{[]byte(nil)})
	if err != nil {
		return nil, err
	}
	var b7 []byte
	if len(pcrNums) > 0 {
		b7, err = encodeLongPCR(1, pcrNums)
	} else {
		b7, err = encodeLongPCR(0, pcrNums)
	}
	if err != nil {
		return nil, err
	}
	args := append(b1, b2...)
	args = append(args, b3...)
	args = append(args, b4...)
	args = append(args, b5...)
	args = append(args, b6...)
	args = append(args, b7...)
	return packWithBytes(cmdHdr, args)
}

func decodeCreatePrimary(in []byte) (Handle, []byte, error) {
	var handle Handle
	var auth []byte

	// handle and auth data
	template := []interface{}{&handle, &auth}
	err := unpack(in, template)
	if err != nil {
		return 0, nil, err
	}

	var current int
	current = 6 + 2*len(auth)
	// size, size-public
	var tpm2Public []byte
	template = []interface{}{&tpm2Public}
	err = unpack(in[current:], template)
	if err != nil {
		return 0, nil, err
	}

	var rsaParamsBuf []byte
	template = []interface{}{&rsaParamsBuf}
	err = unpack(tpm2Public, template)
	if err != nil {
		return 0, nil, err
	}
	var pub tpmtPublic
	if err := unpack(rsaParamsBuf, []interface{}{&pub}); err != nil {
		return 0, nil, err
	}
	return Handle(handle), pub.Unique, nil
}

// CreatePrimary initializes the primary key in a given hierarchy.
// Second return value is the public part of the generated key.
func CreatePrimary(rw io.ReadWriter, owner Handle, pcrNums []int, parentPassword, ownerPassword string, parms RSAParams) (Handle, []byte, error) {
	cmd, err := encodeCreatePrimary(owner, pcrNums, parentPassword, ownerPassword, parms)
	if err != nil {
		return 0, nil, err
	}
	resp, err := runCommand(rw, cmd)
	if err != nil {
		return 0, nil, err
	}

	handle, publicBlob, err := decodeCreatePrimary(resp)
	if err != nil {
		return 0, nil, err
	}
	return Handle(handle), publicBlob, nil
}

func encodeReadPublic(handle Handle) ([]byte, error) {
	cmdHdr := commandHeader{Tag: tagNoSessions, Cmd: cmdReadPublic}
	return packWithHeader(cmdHdr, handle)
}

func decodeReadPublic(in []byte) ([]byte, []byte, []byte, error) {
	var publicBlob []byte
	var name []byte
	var qualifiedName []byte

	out := []interface{}{&publicBlob, &name, &qualifiedName}
	err := unpack(in, out)
	if err != nil {
		return nil, nil, nil, err
	}
	return publicBlob, name, qualifiedName, nil
}

// ReadPublic reads the public part of the object under handle.
// Returns the public data, name and qualified name.
func ReadPublic(rw io.ReadWriter, handle Handle) ([]byte, []byte, []byte, error) {
	cmd, err := encodeReadPublic(handle)
	if err != nil {
		return nil, nil, nil, err
	}
	resp, err := runCommand(rw, cmd)
	if err != nil {
		return nil, nil, nil, err
	}

	publicBlob, name, qualifiedName, err := decodeReadPublic(resp)
	if err != nil {
		return nil, nil, nil, err
	}
	return publicBlob, name, qualifiedName, nil
}

func encodeCreateKey(owner Handle, pcrNums []int, parentPassword, ownerPassword string, parms RSAParams) ([]byte, error) {
	cmdHdr := commandHeader{Tag: tagSessions, Cmd: cmdCreate}
	b1, err := encodeHandle(Handle(owner))
	if err != nil {
		return nil, err
	}
	b2, err := pack([]interface{}{[]byte(nil)})
	if err != nil {
		return nil, err
	}
	b3, err := encodePasswordAuthArea(parentPassword, PasswordSessionHandle)
	if err != nil {
		return nil, err
	}
	t1, err := encodePasswordData(ownerPassword)
	if err != nil {
		return nil, err
	}
	b4, err := encodeSensitiveArea(t1[2:], []byte(nil))
	if err != nil {
		return nil, err
	}
	b5, err := encodeRSAParams(parms)
	if err != nil {
		return nil, err
	}
	b6, err := pack([]interface{}{[]byte(nil)})
	if err != nil {
		return nil, err
	}
	b7, err := encodeLongPCR(1, pcrNums)
	if err != nil {
		return nil, err
	}
	args := append(b1, b2...)
	args = append(args, b3...)
	args = append(args, b4...)
	args = append(args, b5...)
	args = append(args, b6...)
	args = append(args, b7...)
	return packWithBytes(cmdHdr, args)
}

func decodeCreateKey(in []byte) ([]byte, []byte, error) {
	var tpm2bPrivate []byte
	var tpm2bPublic []byte

	out := []interface{}{&tpm2bPrivate, &tpm2bPublic}
	err := unpack(in[4:], out)
	if err != nil {
		return nil, nil, err
	}
	return tpm2bPrivate, tpm2bPublic, nil
}

// CreateKey creates a new RSA key pair under the owner handle.
// Returns private key and public key blobs.
func CreateKey(rw io.ReadWriter, owner Handle, pcrNums []int, parentPassword, ownerPassword string, parms RSAParams) ([]byte, []byte, error) {
	cmd, err := encodeCreateKey(owner, pcrNums, parentPassword, ownerPassword, parms)
	if err != nil {
		return nil, nil, err
	}
	resp, err := runCommand(rw, cmd)
	if err != nil {
		return nil, nil, err
	}
	privateBlob, publicBlob, err := decodeCreateKey(resp)
	if err != nil {
		return nil, nil, err
	}
	return privateBlob, publicBlob, nil
}

func encodeLoad(parentHandle Handle, parentAuth, ownerAuth string, publicBlob, privateBlob []byte) ([]byte, error) {
	cmdHdr := commandHeader{Tag: tagSessions, Cmd: cmdLoad}
	b1, err := encodeHandle(parentHandle)
	if err != nil {
		return nil, err
	}
	b3, err := encodePasswordData(parentAuth)
	if err != nil {
		return nil, err
	}
	b4, err := encodePasswordAuthArea(ownerAuth, PasswordSessionHandle)
	if err != nil {
		return nil, err
	}
	b5, err := pack([]interface{}{privateBlob, publicBlob})
	if err != nil {
		return nil, err
	}
	args := append(b1, b3...)
	args = append(args, b4...)
	args = append(args, b5...)
	return packWithBytes(cmdHdr, args)
}

func decodeLoad(in []byte) (Handle, []byte, error) {
	var handle Handle
	var auth []byte
	var name []byte

	out := []interface{}{&handle, &auth, &name}
	err := unpack(in, out)
	if err != nil {
		return 0, nil, err
	}
	return Handle(handle), name, nil
}

// Load loads public/private blobs into an object in the TPM.
// Returns loaded object handle and its name.
func Load(rw io.ReadWriter, parentHandle Handle, parentAuth, ownerAuth string, publicBlob, privateBlob []byte) (Handle, []byte, error) {
	cmd, err := encodeLoad(parentHandle, parentAuth, ownerAuth, publicBlob, privateBlob)
	if err != nil {
		return 0, nil, err
	}
	resp, err := runCommand(rw, cmd)
	if err != nil {
		return 0, nil, err
	}
	handle, name, err := decodeLoad(resp)
	if err != nil {
		return 0, nil, err
	}
	return handle, name, nil
}

func encodePolicyPCR(handle Handle, expectedDigest []byte, pcrNums []int) ([]byte, error) {
	cmdHdr := commandHeader{Tag: tagNoSessions, Cmd: cmdPolicyPCR}
	template := []interface{}{handle, expectedDigest}
	b1, err := pack(template)
	if err != nil {
		return nil, err
	}
	b2, err := encodeLongPCR(1, pcrNums)
	if err != nil {
		return nil, err
	}
	return packWithBytes(cmdHdr, append(b1, b2...))
}

func encodePolicyPassword(handle Handle) ([]byte, error) {
	cmdHdr := commandHeader{Tag: tagNoSessions, Cmd: cmdPolicyPassword}
	template := []interface{}{handle}
	b1, err := pack(template)
	if err != nil {
		return nil, err
	}
	return packWithBytes(cmdHdr, b1)
}

// PolicyPassword sets password authorization requirement on the object.
func PolicyPassword(rw io.ReadWriter, handle Handle) error {
	cmd, err := encodePolicyPassword(handle)
	if err != nil {
		return err
	}
	_, err = runCommand(rw, cmd)
	return err
}

// PolicyPCR sets PCR state binding for authorization on the object.
func PolicyPCR(rw io.ReadWriter, handle Handle, expectedDigest []byte, pcrNums []int) error {
	cmd, err := encodePolicyPCR(handle, expectedDigest, pcrNums)
	if err != nil {
		return err
	}
	_, err = runCommand(rw, cmd)
	return err
}

func encodePolicyGetDigest(handle Handle) ([]byte, error) {
	cmdHdr := commandHeader{Tag: tagNoSessions, Cmd: cmdPolicyGetDigest}
	template := []interface{}{handle}
	b1, err := pack(template)
	if err != nil {
		return nil, err
	}
	return packWithBytes(cmdHdr, b1)
}

func decodePolicyGetDigest(in []byte) ([]byte, error) {
	var digest []byte

	out := []interface{}{&digest}
	err := unpack(in, out)
	if err != nil {
		return nil, err
	}
	return digest, nil
}

// PolicyGetDigest returns the current policyDigest of the session.
func PolicyGetDigest(rw io.ReadWriter, handle Handle) ([]byte, error) {
	cmd, err := encodePolicyGetDigest(handle)
	if err != nil {
		return nil, err
	}
	resp, err := runCommand(rw, cmd)
	if err != nil {
		return nil, err
	}

	digest, err := decodePolicyGetDigest(resp)
	if err != nil {
		return nil, err
	}
	return digest, nil
}

func encodeStartAuthSession(tpmKey, bindKey Handle, nonceCaller, secret []byte, se SessionType, sym, hashAlg Algorithm) ([]byte, error) {
	cmdHdr := commandHeader{Tag: tagNoSessions, Cmd: cmdStartAuthSession}
	b1, err := encodeHandle(tpmKey)
	if err != nil {
		return nil, err
	}
	b2, err := encodeHandle(bindKey)
	if err != nil {
		return nil, err
	}
	b3, err := pack([]interface{}{nonceCaller, secret})
	if err != nil {
		return nil, err
	}
	b5, err := pack([]interface{}{sym, hashAlg})
	if err != nil {
		return nil, err
	}
	args := append(b1, b2...)
	args = append(args, b3...)
	args = append(args, byte(se))
	args = append(args, b5...)
	return packWithBytes(cmdHdr, args)
}

func decodeStartAuthSession(in []byte) (Handle, []byte, error) {
	var handle Handle
	var nonce []byte
	template := []interface{}{&handle, &nonce}
	err := unpack(in, template)
	if err != nil {
		return 0, nil, err
	}
	return Handle(handle), nonce, nil
}

// StartAuthSession initializes a session object.
// Returns session handle and the initial nonce from the TPM.
func StartAuthSession(rw io.ReadWriter, tpmKey, bindKey Handle, nonceCaller, secret []byte, se SessionType, sym, hashAlg Algorithm) (Handle, []byte, error) {
	cmd, err := encodeStartAuthSession(tpmKey, bindKey, nonceCaller, secret, se, sym, hashAlg)
	if err != nil {
		return 0, nil, err
	}
	resp, err := runCommand(rw, cmd)
	if err != nil {
		return 0, nil, err
	}
	handle, nonce, err := decodeStartAuthSession(resp)
	if err != nil {
		return 0, nil, fmt.Errorf("decoding StartAuthSession response: %v", err)
	}
	return handle, nonce, nil
}

func encodeUnseal(itemHandle Handle, password string, sessionHandle Handle) ([]byte, error) {
	cmdHdr := commandHeader{Tag: tagSessions, Cmd: cmdUnseal}
	template := []interface{}{itemHandle, []byte(nil)}
	b1, err := pack(template)
	if err != nil {
		return nil, err
	}
	sessionAttributes := uint8(1)
	b2, err := encodePasswordAuthArea(password, sessionHandle)
	if err != nil {
		return nil, err
	}
	template = []interface{}{[]byte(nil), sessionAttributes}
	return packWithBytes(cmdHdr, append(b1, b2...))
}

func decodeUnseal(in []byte) ([]byte, []byte, error) {
	var unsealed []byte
	var digest []byte

	template := []interface{}{&unsealed, &digest}
	err := unpack(in[4:], template)
	if err != nil {
		return nil, nil, err
	}
	return unsealed, digest, nil
}

// Unseal returns the data for a loaded sealed object.
// Returns unsealed data and a digest.
func Unseal(rw io.ReadWriter, itemHandle Handle, password string, sessionHandle Handle, digest []byte) ([]byte, []byte, error) {
	cmd, err := encodeUnseal(itemHandle, password, sessionHandle)
	if err != nil {
		return nil, nil, err
	}
	resp, err := runCommand(rw, cmd)
	if err != nil {
		return nil, nil, err
	}
	unsealed, nonce, err := decodeUnseal(resp)
	if err != nil {
		return nil, nil, fmt.Errorf("decoding Unseal response: %v", err)
	}
	return unsealed, nonce, nil
}

func encodeQuote(signingHandle Handle, parentPassword, ownerPassword string, toQuote []byte, pcrNums []int, sigAlg Algorithm) ([]byte, error) {
	cmdHdr := commandHeader{Tag: tagSessions, Cmd: cmdQuote}
	b1, err := encodeHandle(signingHandle)
	if err != nil {
		return nil, err
	}
	b2, err := pack([]interface{}{[]byte(nil)})
	if err != nil {
		return nil, err
	}
	b3, err := encodePasswordAuthArea(parentPassword, PasswordSessionHandle)
	if err != nil {
		return nil, err
	}
	b4, err := pack([]interface{}{toQuote, sigAlg})
	if err != nil {
		return nil, err
	}
	b5, err := encodeLongPCR(1, pcrNums)
	if err != nil {
		return nil, err
	}
	args := append(b1, b2...)
	args = append(args, b3...)
	args = append(args, b4...)
	args = append(args, b5...)
	return packWithBytes(cmdHdr, args)
}

func decodeQuote(in []byte) ([]byte, uint16, uint16, []byte, error) {
	var empty []byte
	var buf []byte
	var attest []byte
	var signature []byte
	var s1 uint16
	var s2 uint16

	template := []interface{}{&empty, &buf}
	err := unpack(in, template)
	if err != nil {
		return nil, 0, 0, nil, err
	}

	template = []interface{}{&attest, &s1, &s2, &signature}
	err = unpack(buf, template)
	if err != nil {
		return nil, 0, 0, nil, err
	}
	return attest, s1, s2, signature, nil
}

// Quote returns a quote of PCR values.
// Returns attestation data and the signature.
func Quote(rw io.ReadWriter, signingHandle Handle, parentPassword, ownerPassword string, toQuote []byte, pcrNums []int, sigAlg Algorithm) ([]byte, []byte, error) {
	cmd, err := encodeQuote(signingHandle, parentPassword, ownerPassword, toQuote, pcrNums, sigAlg)
	if err != nil {
		return nil, nil, err
	}
	resp, err := runCommand(rw, cmd)
	if err != nil {
		return nil, nil, err
	}
	attest, _, _, sig, err := decodeQuote(resp)
	if err != nil {
		return nil, nil, fmt.Errorf("decoding Quote response: %v", err)
	}
	return attest, sig, nil
}

func encodeActivateCredential(activeHandle Handle, keyHandle Handle, activePassword, protectorPassword string, credBlob, secret []byte) ([]byte, error) {
	cmdHdr := commandHeader{Tag: tagSessions, Cmd: cmdActivateCredential}
	b1, err := encodeHandle(activeHandle)
	if err != nil {
		return nil, err
	}
	b2, err := encodeHandle(keyHandle)
	if err != nil {
		return nil, err
	}
	b3, err := pack([]interface{}{[]byte(nil)})
	if err != nil {
		return nil, err
	}
	b4a, err := encodePasswordAuthArea(activePassword, PasswordSessionHandle)
	if err != nil {
		return nil, err
	}
	b4b, err := encodePasswordAuthArea(protectorPassword, PasswordSessionHandle)
	if err != nil {
		return nil, err
	}
	b4t := append(b4a[2:], b4b[2:]...)
	b4, err := pack([]interface{}{b4t})
	if err != nil {
		return nil, err
	}
	b5, err := pack([]interface{}{credBlob, secret})
	if err != nil {
		return nil, err
	}
	args := append(b1, b2...)
	args = append(args, b3...)
	args = append(args, b4...)
	args = append(args, b5...)
	return packWithBytes(cmdHdr, args)
}

func decodeActivateCredential(in []byte) ([]byte, error) {
	var empty []byte
	var buf []byte
	var certInfo []byte

	template := []interface{}{&empty, &buf}
	err := unpack(in, template)
	if err != nil {
		return nil, err
	}
	template = []interface{}{&certInfo}
	err = unpack(buf, template)
	if err != nil {
		return nil, err
	}
	return certInfo, nil
}

// ActivateCredential associates an object with a credential.
// Returns decrypted certificate information.
func ActivateCredential(rw io.ReadWriter, activeHandle, keyHandle Handle, activePassword, protectorPassword string, credBlob, secret []byte) ([]byte, error) {
	cmd, err := encodeActivateCredential(activeHandle, keyHandle, activePassword, protectorPassword, credBlob, secret)
	if err != nil {
		return nil, err
	}
	resp, err := runCommand(rw, cmd)
	if err != nil {
		return nil, err
	}
	cred, err := decodeActivateCredential(resp)
	if err != nil {
		return nil, fmt.Errorf("decoding ActivateCredential response: %v", err)
	}
	return cred, nil
}

func encodeMakeCredential(protectorHandle Handle, credential, activeName []byte) ([]byte, error) {
	cmdHdr := commandHeader{Tag: tagNoSessions, Cmd: cmdMakeCredential}
	b1, err := encodeHandle(protectorHandle)
	if err != nil {
		return nil, err
	}
	b2, err := pack([]interface{}{credential, activeName})
	if err != nil {
		return nil, err
	}
	return packWithBytes(cmdHdr, append(b1, b2...))
}

func decodeMakeCredential(in []byte) ([]byte, []byte, error) {
	var credBlob []byte
	var encryptedSecret []byte

	template := []interface{}{&credBlob, &encryptedSecret}
	err := unpack(in, template)
	if err != nil {
		return nil, nil, err
	}
	return credBlob, encryptedSecret, nil
}

// MakeCredential creates an encrypted credential for use in MakeCredential.
// Returns encrypted credential and wrapped secret used to encrypt it.
func MakeCredential(rw io.ReadWriter, protectorHandle Handle, credential, activeName []byte) ([]byte, []byte, error) {
	cmd, err := encodeMakeCredential(protectorHandle, credential, activeName)
	if err != nil {
		return nil, nil, err
	}
	resp, err := runCommand(rw, cmd)
	if err != nil {
		return nil, nil, err
	}
	credBlob, encryptedSecret, err := decodeMakeCredential(resp)
	if err != nil {
		return nil, nil, fmt.Errorf("decoding MakeCredential response: %v", err)
	}
	return credBlob, encryptedSecret, nil
}

func encodeEvictControl(owner Handle, tmpHandle, persistantHandle Handle) ([]byte, error) {
	cmdHdr := commandHeader{Tag: tagSessions, Cmd: cmdEvictControl}
	b1, err := encodeHandle(owner)
	if err != nil {
		return nil, err
	}
	b2, err := encodeHandle(tmpHandle)
	if err != nil {
		return nil, err
	}
	b3, err := pack([]interface{}{[]byte(nil)})
	if err != nil {
		return nil, err
	}
	b4, err := encodePasswordAuthArea("", PasswordSessionHandle)
	if err != nil {
		return nil, err
	}
	b5, err := encodeHandle(persistantHandle)
	if err != nil {
		return nil, err
	}
	args := append(b1, b2...)
	args = append(args, b3...)
	args = append(args, b4...)
	args = append(args, b5...)
	return packWithBytes(cmdHdr, args)
}

// EvictControl toggles persistence of an object within the TPM.
func EvictControl(rw io.ReadWriter, owner, tmpHandle, persistantHandle Handle) error {
	cmd, err := encodeEvictControl(owner, tmpHandle, persistantHandle)
	if err != nil {
		return err
	}
	_, err = runCommand(rw, cmd)
	return err
}

func encodeSaveContext(handle Handle) ([]byte, error) {
	cmdHdr := commandHeader{Tag: tagNoSessions, Cmd: cmdContextSave}
	b1, err := encodeHandle(handle)
	if err != nil {
		return nil, err
	}
	return packWithBytes(cmdHdr, b1)
}

// ContextSave returns an encrypted version of the session, object or sequence
// context for storage outside of the TPM.
func ContextSave(rw io.ReadWriter, handle Handle) ([]byte, error) {
	cmd, err := encodeSaveContext(handle)
	if err != nil {
		return nil, err
	}
	return runCommand(rw, cmd)
}

func encodeLoadContext(saveArea []byte) ([]byte, error) {
	cmdHdr := commandHeader{Tag: tagNoSessions, Cmd: cmdContextLoad}
	return packWithBytes(cmdHdr, saveArea[0:len(saveArea)])
}

func decodeLoadContext(in []byte) (Handle, error) {
	var handle Handle
	template := []interface{}{&handle}
	err := unpack(in, template)
	if err != nil {
		return 0, err
	}
	return Handle(handle), nil
}

// ContextLoad reloads context data created by ContextSave.
func ContextLoad(rw io.ReadWriter, saveArea []byte) (Handle, error) {
	cmd, err := encodeLoadContext(saveArea)
	if err != nil {
		return 0, err
	}
	resp, err := runCommand(rw, cmd)
	if err != nil {
		return 0, err
	}
	handle, err := decodeLoadContext(resp)
	if err != nil {
		return 0, fmt.Errorf("decoding LoadContext response: %v", err)
	}
	return handle, nil
}

func encodeIncrementNv(handle Handle, authString string) ([]byte, error) {
	auth, err := encodePasswordAuthArea(authString, PasswordSessionHandle)
	if err != nil {
		return nil, err
	}
	numBytes := []interface{}{handle, handle, []byte(nil)}
	out, err := pack(numBytes)
	if err != nil {
		return nil, err
	}
	out = append(out, auth...)
	cmdHdr := commandHeader{Tag: tagSessions, Cmd: cmdIncrementNvCounter}
	return packWithBytes(cmdHdr, out)
}

// NVIncrement increments a counter NV index.
func NVIncrement(rw io.ReadWriter, handle Handle, authString string) error {
	cmd, err := encodeIncrementNv(handle, authString)
	if err != nil {
		return err
	}
	_, err = runCommand(rw, cmd)
	return err
}

func encodeUndefineSpace(owner, handle Handle) ([]byte, error) {
	cmdHdr := commandHeader{Tag: tagSessions, Cmd: cmdUndefineSpace}
	auth, err := encodePasswordAuthArea("", PasswordSessionHandle)
	if err != nil {
		return nil, err
	}
	numBytes := []interface{}{owner, handle, uint16(0)}
	out, err := pack(numBytes)
	if err != nil {
		return nil, err
	}
	out = append(out, auth...)
	return packWithBytes(cmdHdr, out)
}

// NVUndefineSpace removes an index from TPM's NV storage.
func NVUndefineSpace(rw io.ReadWriter, owner, handle Handle) error {
	cmd, err := encodeUndefineSpace(owner, handle)
	if err != nil {
		return err
	}
	_, err = runCommand(rw, cmd)
	return err
}

func encodeDefineSpace(owner, handle Handle, authString string, attributes uint32, policy []byte, dataSize uint16) ([]byte, error) {
	pw, err := encodePasswordData(authString)
	if err != nil {
		return nil, err
	}
	auth, err := encodePasswordAuthArea("", PasswordSessionHandle)
	if err != nil {
		return nil, err
	}
	numBytes := []interface{}{owner, []byte(nil)}
	out1, err := pack(numBytes)
	if err != nil {
		return nil, err
	}
	hashAlg := AlgSHA1
	sizeNvArea := uint16(2*int(unsafe.Sizeof(owner)) + 3*int(unsafe.Sizeof(dataSize)) + len(policy))
	out1 = append(append(out1, auth...), pw...)
	numBytes2 := []interface{}{sizeNvArea, handle, hashAlg, attributes, policy, dataSize}
	out2, err := pack(numBytes2)
	if err != nil {
		return nil, err
	}
	cmdHdr := commandHeader{Tag: tagSessions, Cmd: cmdDefineSpace}
	return packWithBytes(cmdHdr, append(out1, out2...))
}

// NVDefineSpace creates an index in TPM's NV storage.
func NVDefineSpace(rw io.ReadWriter, owner, handle Handle, authString string, policy []byte, attributes uint32, dataSize uint16) error {
	cmd, err := encodeDefineSpace(owner, handle, authString, attributes, policy, dataSize)
	if err != nil {
		return err
	}
	_, err = runCommand(rw, cmd)
	return err
}

func encodeNVReadPublic(handle Handle) ([]byte, error) {
	cmdHdr := commandHeader{Tag: tagNoSessions, Cmd: cmdReadPublicNv}
	return packWithHeader(cmdHdr, handle)
}

func decodeNVReadPublic(in []byte) (NVPublic, error) {
	var pub NVPublic
	var buf []byte
	if err := unpack(in, []interface{}{&buf}); err != nil {
		return pub, err
	}
	err := unpack(buf, []interface{}{&pub})
	return pub, err
}

func decodeNVRead(in []byte) ([]byte, error) {
	var sessionAttributes uint32
	var data []byte
	if err := unpack(in, []interface{}{&sessionAttributes, &data}); err != nil {
		return nil, err
	}
	return data, nil
}

func encodeNVRead(handle Handle, authString string, offset, dataSize uint16) ([]byte, error) {
	out, err := pack([]interface{}{handle, handle, []byte(nil)})
	if err != nil {
		return nil, err
	}
	auth, err := encodePasswordAuthArea(authString, PasswordSessionHandle)
	if err != nil {
		return nil, err
	}
	out = append(out, auth...)
	params, err := pack([]interface{}{dataSize, offset})
	if err != nil {
		return nil, err
	}
	out = append(out, params...)
	cmdHdr := commandHeader{Tag: tagSessions, Cmd: cmdReadNv}
	return packWithBytes(cmdHdr, out)
}

// NVRead reads full data blob from NV index.
func NVRead(rw io.ReadWriter, index Handle) ([]byte, error) {
	// Read public area to determine data size.
	cmd, err := encodeNVReadPublic(index)
	if err != nil {
		return nil, fmt.Errorf("building NV_ReadPublic command: %v", err)
	}
	resp, err := runCommand(rw, cmd)
	if err != nil {
		return nil, fmt.Errorf("running NV_ReadPublic command: %v", err)
	}
	pub, err := decodeNVReadPublic(resp)
	if err != nil {
		return nil, fmt.Errorf("decoding NV_ReadPublic response: %v", err)
	}

	// Read pub.DataSize of actual data.
	cmd, err = encodeNVRead(index, "", 0, pub.DataSize)
	if err != nil {
		return nil, fmt.Errorf("building NV_Read command: %v", err)
	}
	resp, err = runCommand(rw, cmd)
	if err != nil {
		return nil, fmt.Errorf("running NV_Read command: %v", err)
	}
	return decodeNVRead(resp)
}

// Hash computes a hash of data in buf using the TPM.
func Hash(rw io.ReadWriter, alg Algorithm, buf []byte) ([]byte, error) {
	out, err := pack([]interface{}{buf, alg, HandleNull})
	if err != nil {
		return nil, err
	}
	cmdHdr := commandHeader{Tag: tagNoSessions, Cmd: cmdHash}
	cmd, err := packWithBytes(cmdHdr, out)
	if err != nil {
		return nil, err
	}

	resp, err := runCommand(rw, cmd)
	if err != nil {
		return nil, err
	}

	var digest []byte
	if err = unpack(resp, []interface{}{&digest}); err != nil {
		return nil, fmt.Errorf("decoding Hash response: %v", err)
	}
	return digest, nil
}

// Startup initializes a TPM (usually done by the OS).
func Startup(rw io.ReadWriter, typ StartupType) error {
	out, err := pack([]interface{}{typ})
	if err != nil {
		return err
	}
	cmdHdr := commandHeader{Tag: tagNoSessions, Cmd: cmdStartup}
	cmd, err := packWithBytes(cmdHdr, out)
	if err != nil {
		return err
	}

	_, err = runCommand(rw, cmd)
	return err
}

// Shutdown shuts down a TPM (usually done by the OS).
func Shutdown(rw io.ReadWriter, typ StartupType) error {
	out, err := pack([]interface{}{typ})
	if err != nil {
		return err
	}
	cmdHdr := commandHeader{Tag: tagNoSessions, Cmd: cmdShutdown}
	cmd, err := packWithBytes(cmdHdr, out)
	if err != nil {
		return err
	}

	_, err = runCommand(rw, cmd)
	return err
}

func encodeSign(key Handle, password string, digest []byte) ([]byte, error) {
	out, err := pack([]interface{}{key, []byte(nil)})
	if err != nil {
		return nil, err
	}
	auth, err := encodePasswordAuthArea(password, PasswordSessionHandle)
	if err != nil {
		return nil, err
	}
	out = append(out, auth...)
	params, err := pack([]interface{}{digest, AlgNULL})
	if err != nil {
		return nil, err
	}
	out = append(out, params...)
	ticket, err := pack([]interface{}{tagHashcheck, HandleNull, []byte(nil)})
	if err != nil {
		return nil, err
	}
	out = append(out, ticket...)
	cmdHdr := commandHeader{Tag: tagSessions, Cmd: cmdReadNv}
	return packWithBytes(cmdHdr, out)
}

func decodeSign(buf []byte) (Algorithm, []byte, error) {
	var signAlg Algorithm
	var hashAlg Algorithm
	var signature []byte
	if err := unpack(buf, []interface{}{&signAlg, &hashAlg, &signature}); err != nil {
		return 0, nil, err
	}
	return signAlg, signature, nil
}

// Sign computes a signature for data using a given loaded key. Signature
// algorithm depends on the key type.
func Sign(rw io.ReadWriter, key Handle, data []byte) (Algorithm, []byte, error) {
	digest, err := Hash(rw, AlgSHA256, data)
	if err != nil {
		return 0, nil, err
	}
	cmd, err := encodeSign(key, "", digest)
	if err != nil {
		return 0, nil, err
	}
	resp, err := runCommand(rw, cmd)
	if err != nil {
		return 0, nil, err
	}
	return decodeSign(resp)
}

func runCommand(rw io.ReadWriter, cmd []byte) ([]byte, error) {
	_, err := rw.Write(cmd)
	if err != nil {
		return nil, err
	}

	resp := make([]byte, maxTPMResponse)
	read, err := rw.Read(resp)
	if err != nil {
		return nil, err
	}
	headerSize := binary.Size(responseHeader{})
	if read < headerSize {
		return nil, errors.New("response buffer too small")
	}

	header, resp := resp[:headerSize], resp[headerSize:read]

	_, _, status, err := decodeCommandResponse(header)
	if err != nil {
		return nil, err
	}
	if status != rcSuccess {
		return nil, fmt.Errorf("response status 0x%x", status)
	}

	return resp, nil
}
