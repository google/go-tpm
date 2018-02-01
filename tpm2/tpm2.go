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

// Package tpm2 supports direct communication with a tpm 2.0 device under Linux.
package tpm2

import (
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

func constructHandle(handle Handle) ([]byte, error) {
	uh := uint32(handle)
	return pack([]interface{}{&uh})
}

func constructPasswordData(password string) ([]byte, error) {
	pw, err := hex.DecodeString(password)
	if err != nil {
		return nil, err
	}
	return pack([]interface{}{&pw})
}

// returns: len0 TPM_RS_PW 0000 01 password data as []byte
func constructPasswordAuthArea(password string, owner Handle) ([]byte, error) {
	ownerStr, err := constructHandle(owner)
	if err != nil {
		return nil, err
	}
	suffix := []byte{0, 0, 1}
	pw, err := constructPasswordData(password)
	if err != nil {
		return nil, err
	}
	buf := append(ownerStr, suffix...)
	buf = append(buf, pw...)
	return pack([]interface{}{&buf})
}

func constructSensitiveArea(in1 []byte, in2 []byte) ([]byte, error) {
	t1, err := pack([]interface{}{&in1})
	if err != nil {
		return nil, err
	}
	t2, err := pack([]interface{}{&in2})
	if err != nil {
		return nil, err
	}

	t := append(t1, t2...)
	return pack([]interface{}{&t})
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
	if parms.SymAlg != uint16(AlgTPM_ALG_NULL) {
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
	if parms.Scheme == uint16(AlgTPM_ALG_RSASSA) {
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

func constructKeyedHashParams(parms KeyedHashParams) ([]byte, error) {
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

func constructRSAParams(parms RSAParams) ([]byte, error) {
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

	if parms.SymAlg != uint16(AlgTPM_ALG_NULL) {
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
	if parms.Scheme == uint16(AlgTPM_ALG_RSASSA) {
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

func constructShortPcrs(pcrNums []int) ([]byte, error) {
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

func constructLongPCR(count uint32, pcrNums []int) ([]byte, error) {
	if count == 0 {
		return pack([]interface{}{&count})
	}
	b1, err := constructShortPcrs(pcrNums)
	if err != nil {
		return nil, err
	}
	template := []interface{}{&count, &b1}
	return pack(template)
}

// constructGetRandom constructs a GetRandom command.
func constructGetRandom(size uint32) ([]byte, error) {
	cmdHdr := commandHeader{Tag: tagNO_SESSIONS, Cmd: cmdGetRandom}
	return packWithHeader(cmdHdr, uint16(size))
}

// decodeGetRandom decodes a GetRandom response.
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
func GetRandom(rw io.ReadWriteCloser, size uint32) ([]byte, error) {
	cmd, err := constructGetRandom(size)
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

// constructFlushContext constructs a FlushContext command.
func constructFlushContext(handle Handle) ([]byte, error) {
	cmdHdr := commandHeader{Tag: tagNO_SESSIONS, Cmd: cmdFlushContext}
	return packWithHeader(cmdHdr, uint32(handle))
}

func FlushContext(rw io.ReadWriter, handle Handle) error {
	cmd, err := constructFlushContext(handle)
	if err != nil {
		return fmt.Errorf("failed building command: %v", err)
	}
	_, err = runCommand(rw, cmd)
	return err
}

// constructReadPcrs constructs a ReadPcr command.
func constructReadPcrs(numSpec int, pcrs []byte) ([]byte, error) {
	cmdHdr := commandHeader{Tag: tagNO_SESSIONS, Cmd: cmdPCR_Read}
	num := uint32(numSpec)
	return packWithHeader(cmdHdr, &num, &pcrs)
}

// decodeReadPcrs decodes a ReadPcr response.
func decodeReadPcrs(in []byte) (uint32, []byte, uint16, []byte, error) {
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

// ReadPcr reads a PCR value from the TPM.
// Output: updatecounter, selectout, digest
func ReadPcrs(rw io.ReadWriter, PCRSelect []byte) (uint32, []byte, uint16, []byte, error) {
	cmd, err := constructReadPcrs(1, PCRSelect)
	if err != nil {
		return 1, nil, 0, nil, err
	}
	resp, err := runCommand(rw, cmd)
	if err != nil {
		return 0, nil, 0, nil, err
	}

	counter, pcr, alg, digest, err := decodeReadPcrs(resp)
	if err != nil {
		return 0, nil, 0, nil, err
	}
	return counter, pcr, alg, digest, err
}

// constructReadClock constructs a ReadClock command.
func constructReadClock() ([]byte, error) {
	cmdHdr := commandHeader{Tag: tagNO_SESSIONS, Cmd: cmdReadClock}
	return packWithBytes(cmdHdr, nil)
}

// decodeReadClock decodes a ReadClock response.
func decodeReadClock(in []byte) (uint64, uint64, error) {
	var curTime, curClock uint64

	template := []interface{}{&curTime, &curClock}
	err := unpack(in, template)
	if err != nil {
		return 0, 0, err
	}
	return curTime, curClock, nil
}

// ReadClock
// Output: current time, current clock
func ReadClock(rw io.ReadWriter) (uint64, uint64, error) {
	cmd, err := constructReadClock()
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

// constructGetCapabilities constructs a GetCapabilities command.
func constructGetCapabilities(cap uint32, count uint32, property uint32) ([]byte, error) {
	cmdHdr := commandHeader{Tag: tagNO_SESSIONS, Cmd: cmdGetCapability}
	return packWithHeader(cmdHdr, &cap, &property, &count)
}

// decodeGetCapabilities decodes a GetCapabilities response.
func decodeGetCapabilities(in []byte) (uint32, []uint32, error) {
	var numHandles uint32
	var capReported uint32

	out := []interface{}{&capReported, &numHandles}
	err := unpack(in[1:9], out)
	if err != nil {
		return 0, nil, err
	}
	// only OrdTPM_CAP_HANDLES handled
	if capReported != OrdTPM_CAP_HANDLES {
		return 0, nil, fmt.Errorf("Only OrdTPM_CAP_HANDLES supported, got %v", capReported)
	}
	var handles []uint32
	var handle uint32
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

// GetCapabilities
// Output: output buf
func GetCapabilities(rw io.ReadWriter, cap uint32, count uint32, property uint32) ([]uint32, error) {
	cmd, err := constructGetCapabilities(cap, count, property)
	if err != nil {
		return nil, err
	}
	resp, err := runCommand(rw, cmd)
	if err != nil {
		return nil, err
	}
	_, handles, err := decodeGetCapabilities(resp)
	if err != nil {
		return nil, err
	}
	return handles, nil
}

// constructPcrEvent
func constructPcrEvent(pcrNum int, eventData []byte) ([]byte, error) {
	cmdHdr := commandHeader{Tag: tagSESSIONS, Cmd: cmdPcrEvent}
	var empty []byte
	pc := uint32(pcrNum)
	b1, err := pack([]interface{}{&pc, &empty})
	if err != nil {
		return nil, err
	}
	b2, err := constructPasswordAuthArea("", Handle(OrdTPM_RS_PW))
	if err != nil {
		return nil, err
	}
	b3, err := pack([]interface{}{&eventData})
	if err != nil {
		return nil, err
	}
	return packWithBytes(cmdHdr, append(append(b1, b2...), b3...))
}

func PcrEvent(rw io.ReadWriter, pcrNum int, eventData []byte) error {
	cmd, err := constructPcrEvent(pcrNum, eventData)
	if err != nil {
		return err
	}
	_, err = runCommand(rw, cmd)
	return err
}

func FlushAll(rw io.ReadWriter) error {
	handles, err := GetCapabilities(rw, OrdTPM_CAP_HANDLES, 1, 0x80000000)
	if err != nil {
		return err
	}
	for _, e := range handles {
		FlushContext(rw, Handle(e))
	}
	return nil
}

// constructCreatePrimary constructs a CreatePrimary command.
func constructCreatePrimary(owner uint32, pcrNums []int, parentPassword, ownerPassword string, parms RSAParams) ([]byte, error) {
	cmdHdr := commandHeader{Tag: tagSESSIONS, Cmd: cmdCreatePrimary}
	var empty []byte
	b1, err := constructHandle(Handle(owner))
	if err != nil {
		return nil, err
	}
	b2, err := pack([]interface{}{&empty})
	if err != nil {
		return nil, err
	}
	b3, err := constructPasswordAuthArea(parentPassword, Handle(OrdTPM_RS_PW))
	if err != nil {
		return nil, err
	}
	t1, err := constructPasswordData(ownerPassword)
	if err != nil {
		return nil, err
	}
	b4, err := constructSensitiveArea(t1[2:], empty)
	if err != nil {
		return nil, err
	}
	b5, err := constructRSAParams(parms)
	if err != nil {
		return nil, err
	}
	b6, err := pack([]interface{}{&empty})
	if err != nil {
		return nil, err
	}
	var b7 []byte
	if len(pcrNums) > 0 {
		b7, err = constructLongPCR(1, pcrNums)
	} else {
		b7, err = constructLongPCR(0, pcrNums)
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

// decodeCreatePrimary decodes a CreatePrimary response.
func decodeCreatePrimary(in []byte) (Handle, []byte, error) {
	var handle uint32
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

	// Creation data
	current = 2 + len(rsaParamsBuf)
	var creationData []byte
	template = []interface{}{&creationData}
	err = unpack(tpm2Public[current:], template)
	if err != nil {
		return 0, nil, err
	}
	current += len(creationData) + 2

	// Digest
	var digest []byte
	template = []interface{}{&digest}
	err = unpack(tpm2Public[current:], template)
	if err != nil {
		return 0, nil, err
	}
	current += len(digest) + 2

	// TPMT_TK_CREATION
	current += 6
	var crap []byte
	template = []interface{}{&crap}
	err = unpack(tpm2Public[current:], template)
	if err != nil {
		return 0, nil, err
	}
	current += len(crap) + 2

	// Name
	var name []byte
	template = []interface{}{&name}
	err = unpack(tpm2Public[current:], template)
	if err != nil {
		return 0, nil, err
	}

	return Handle(handle), tpm2Public, nil
}

// CreatePrimary
// Output: handle, public key blob
func CreatePrimary(rw io.ReadWriter, owner uint32, pcrNums []int, parentPassword, ownerPassword string, parms RSAParams) (Handle, []byte, error) {
	cmd, err := constructCreatePrimary(uint32(owner), pcrNums, parentPassword, ownerPassword, parms)
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

// constructReadPublic constructs a ReadPublic command.
func constructReadPublic(handle Handle) ([]byte, error) {
	cmdHdr := commandHeader{Tag: tagNO_SESSIONS, Cmd: cmdReadPublic}
	return packWithHeader(cmdHdr, uint32(handle))
}

// decodeReadPublic decodes a ReadPublic response.
// Returns: public, name, qualified name
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

// ReadPublic
// Output: key blob, name, qualified name
func ReadPublic(rw io.ReadWriter, handle Handle) ([]byte, []byte, []byte, error) {
	cmd, err := constructReadPublic(handle)
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

// constructCreateKey constructs a CreateKey command.
func constructCreateKey(owner uint32, pcrNums []int, parentPassword, ownerPassword string, parms RSAParams) ([]byte, error) {
	cmdHdr := commandHeader{Tag: tagSESSIONS, Cmd: cmdCreate}
	var empty []byte
	b1, err := constructHandle(Handle(owner))
	if err != nil {
		return nil, err
	}
	b2, err := pack([]interface{}{&empty})
	if err != nil {
		return nil, err
	}
	b3, err := constructPasswordAuthArea(parentPassword, Handle(OrdTPM_RS_PW))
	if err != nil {
		return nil, err
	}
	t1, err := constructPasswordData(ownerPassword)
	if err != nil {
		return nil, err
	}
	b4, err := constructSensitiveArea(t1[2:], empty)
	if err != nil {
		return nil, err
	}
	b5, err := constructRSAParams(parms)
	if err != nil {
		return nil, err
	}
	b6, err := pack([]interface{}{&empty})
	if err != nil {
		return nil, err
	}
	b7, err := constructLongPCR(uint32(1), pcrNums)
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

// decodeCreateKey decodes a CreateKey response.
// Output: privateBlob, publicBlob
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

// Output: public blob, private blob, digest
func CreateKey(rw io.ReadWriter, owner uint32, pcrNums []int, parentPassword, ownerPassword string, parms RSAParams) ([]byte, []byte, error) {
	cmd, err := constructCreateKey(uint32(owner), pcrNums, parentPassword, ownerPassword, parms)
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

// constructLoad constructs a Load command.
func constructLoad(parentHandle Handle, parentAuth, ownerAuth string, publicBlob, privateBlob []byte) ([]byte, error) {
	cmdHdr := commandHeader{Tag: tagSESSIONS, Cmd: cmdLoad}
	b1, err := constructHandle(parentHandle)
	if err != nil {
		return nil, err
	}
	b3, err := constructPasswordData(parentAuth)
	if err != nil {
		return nil, err
	}
	b4, err := constructPasswordAuthArea(ownerAuth, Handle(OrdTPM_RS_PW))
	if err != nil {
		return nil, err
	}
	b5, err := pack([]interface{}{&privateBlob, &publicBlob})
	if err != nil {
		return nil, err
	}
	args := append(b1, b3...)
	args = append(args, b4...)
	args = append(args, b5...)
	return packWithBytes(cmdHdr, args)
}

// decodeLoad decodes a Load response.
// Returns: handle, name
func decodeLoad(in []byte) (Handle, []byte, error) {
	var handle uint32
	var auth []byte
	var name []byte

	out := []interface{}{&handle, &auth, &name}
	err := unpack(in, out)
	if err != nil {
		return 0, nil, err
	}
	return Handle(handle), name, nil
}

// Load
// Output: handle
func Load(rw io.ReadWriter, parentHandle Handle, parentAuth, ownerAuth string, publicBlob, privateBlob []byte) (Handle, []byte, error) {
	cmd, err := constructLoad(parentHandle, parentAuth, ownerAuth, publicBlob, privateBlob)
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

// construct PolicyPcr command.
func constructPolicyPcr(handle Handle, expectedDigest []byte, pcrNums []int) ([]byte, error) {
	cmdHdr := commandHeader{Tag: tagNO_SESSIONS, Cmd: cmdPolicyPCR}
	uHandle := uint32(handle)
	template := []interface{}{&uHandle, &expectedDigest}
	b1, err := pack(template)
	if err != nil {
		return nil, err
	}
	b2, err := constructLongPCR(1, pcrNums)
	if err != nil {
		return nil, err
	}
	return packWithBytes(cmdHdr, append(b1, b2...))
}

// constructPolicyPassword constructs a PolicyPassword command.
func constructPolicyPassword(handle Handle) ([]byte, error) {
	cmdHdr := commandHeader{Tag: tagNO_SESSIONS, Cmd: cmdPolicyPassword}
	uHandle := uint32(handle)
	template := []interface{}{&uHandle}
	b1, err := pack(template)
	if err != nil {
		return nil, err
	}
	return packWithBytes(cmdHdr, b1)
}

func PolicyPassword(rw io.ReadWriter, handle Handle) error {
	cmd, err := constructPolicyPassword(handle)
	if err != nil {
		return err
	}
	_, err = runCommand(rw, cmd)
	return err
}

func PolicyPcr(rw io.ReadWriter, handle Handle, expectedDigest []byte, pcrNums []int) error {
	cmd, err := constructPolicyPcr(handle, expectedDigest, pcrNums)
	if err != nil {
		return err
	}
	_, err = runCommand(rw, cmd)
	return err
}

// constructPolicyGetDigest constructs a PolicyGetDigest command.
func constructPolicyGetDigest(handle Handle) ([]byte, error) {
	cmdHdr := commandHeader{Tag: tagNO_SESSIONS, Cmd: cmdPolicyGetDigest}
	uHandle := uint32(handle)
	template := []interface{}{&uHandle}
	b1, err := pack(template)
	if err != nil {
		return nil, err
	}
	return packWithBytes(cmdHdr, b1)
}

// decodePolicyGetDigest decodes a PolicyGetDigest response.
func decodePolicyGetDigest(in []byte) ([]byte, error) {
	var digest []byte

	out := []interface{}{&digest}
	err := unpack(in, out)
	if err != nil {
		return nil, err
	}
	return digest, nil
}

// PolicyGetDigest
// Output: digest
func PolicyGetDigest(rw io.ReadWriter, handle Handle) ([]byte, error) {
	cmd, err := constructPolicyGetDigest(handle)
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

// constructStartAuthSession constructs a StartAuthSession command.
func constructStartAuthSession(tpmKey Handle, bindKey Handle, nonceCaller, secret []byte, se byte, sym, hashAlg uint16) ([]byte, error) {
	cmdHdr := commandHeader{Tag: tagNO_SESSIONS, Cmd: cmdStartAuthSession}
	b1, err := constructHandle(tpmKey)
	if err != nil {
		return nil, err
	}
	b2, err := constructHandle(bindKey)
	if err != nil {
		return nil, err
	}
	b3, err := pack([]interface{}{&nonceCaller, &secret})
	if err != nil {
		return nil, err
	}
	b4 := []byte{se}
	b5, err := pack([]interface{}{&sym, &hashAlg})
	if err != nil {
		return nil, err
	}
	args := append(b1, b2...)
	args = append(args, b3...)
	args = append(args, b4...)
	args = append(args, b5...)
	return packWithBytes(cmdHdr, args)
}

// decodeStartAuthSession decodes a StartAuthSession response.
// Output: sessionHandle, nonce
func decodeStartAuthSession(in []byte) (Handle, []byte, error) {
	var handle uint32
	var nonce []byte
	template := []interface{}{&handle, &nonce}
	err := unpack(in, template)
	if err != nil {
		return 0, nil, err
	}
	return Handle(handle), nonce, nil
}

func StartAuthSession(rw io.ReadWriter, tpmKey, bindKey Handle, nonceCaller, secret []byte, se byte, sym, hashAlg uint16) (Handle, []byte, error) {
	cmd, err := constructStartAuthSession(tpmKey, bindKey, nonceCaller, secret, se, sym, hashAlg)
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

// constructCreateSealed constructs a CreateSealed command.
func constructCreateSealed(parent Handle, policyDigest []byte, parentPassword, ownerPassword string, toSeal []byte, pcrNums []int, parms KeyedHashParams) ([]byte, error) {
	cmdHdr := commandHeader{Tag: tagSESSIONS, Cmd: cmdCreate}
	var empty []byte
	b1, err := constructHandle(parent)
	if err != nil {
		return nil, err
	}
	b2, err := pack([]interface{}{&empty})
	if err != nil {
		return nil, err
	}
	b3, err := constructPasswordAuthArea(parentPassword, Handle(OrdTPM_RS_PW))
	if err != nil {
		return nil, err
	}
	t1, err := constructPasswordData(ownerPassword)
	if err != nil {
		return nil, err
	}
	b4, err := constructSensitiveArea(t1[2:], toSeal)
	if err != nil {
		return nil, err
	}
	parms.AuthPolicy = policyDigest
	b5, err := constructKeyedHashParams(parms)
	if err != nil {
		return nil, err
	}
	b6, err := pack([]interface{}{&b5})
	if err != nil {
		return nil, err
	}
	b7, err := pack([]interface{}{&empty})
	if err != nil {
		return nil, err
	}
	b8, err := constructLongPCR(uint32(1), pcrNums)
	if err != nil {
		return nil, err
	}
	args := append(b1, b2...)
	args = append(args, b3...)
	args = append(args, b4...)
	args = append(args, b6...)
	args = append(args, b7...)
	args = append(args, b8...)
	return packWithBytes(cmdHdr, args)
}

// decodeCreateSealed decodes a CreateSealed response.
// 	Output: private, public, creationOut, digestOut, creationTicket
func decodeCreateSealed(in []byte) ([]byte, []byte, error) {
	var tpm2bPrivate []byte
	var tpm2bPublic []byte

	template := []interface{}{&tpm2bPrivate, &tpm2bPublic}
	err := unpack(in[4:], template)
	if err != nil {
		return nil, nil, err
	}
	return tpm2bPrivate, tpm2bPublic, nil
}

// CreateSealed
// 	Output: public blob, private blob
func CreateSealed(rw io.ReadWriter, parent Handle, policyDigest []byte, parentPassword string, ownerPassword string, toSeal []byte, pcrNums []int, parms KeyedHashParams) ([]byte, []byte, error) {
	cmd, err := constructCreateSealed(parent, policyDigest, parentPassword, ownerPassword, toSeal, pcrNums, parms)
	if err != nil {
		return nil, nil, err
	}
	resp, err := runCommand(rw, cmd)
	if err != nil {
		return nil, nil, err
	}
	handle, nonce, err := decodeCreateSealed(resp)
	if err != nil {
		return nil, nil, fmt.Errorf("decoding CreateSealed response: %v", err)
	}
	return handle, nonce, nil
}

// constructUnseal constructs a Unseal command.
func constructUnseal(itemHandle Handle, password string, sessionHandle Handle) ([]byte, error) {
	cmdHdr := commandHeader{Tag: tagSESSIONS, Cmd: cmdUnseal}
	var empty []byte
	handle1 := uint32(itemHandle)
	template := []interface{}{&handle1, &empty}
	b1, err := pack(template)
	if err != nil {
		return nil, err
	}
	sessionAttributes := uint8(1)
	b2, err := constructPasswordAuthArea(password, sessionHandle)
	if err != nil {
		return nil, err
	}
	template = []interface{}{&empty, &sessionAttributes} // null hmac
	return packWithBytes(cmdHdr, append(b1, b2...))
}

// decodeUnseal decodes a Unseal response.
// Output: sensitive data
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

func Unseal(rw io.ReadWriter, itemHandle Handle, password string, sessionHandle Handle, digest []byte) ([]byte, []byte, error) {
	cmd, err := constructUnseal(itemHandle, password, sessionHandle)
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

// constructQuote constructs a Quote command.
func constructQuote(signingHandle Handle, parentPassword, ownerPassword string, toQuote []byte, pcrNums []int, sigAlg uint16) ([]byte, error) {
	cmdHdr := commandHeader{Tag: tagSESSIONS, Cmd: cmdQuote}
	var empty []byte
	b1, err := constructHandle(signingHandle)
	if err != nil {
		return nil, err
	}
	b2, err := pack([]interface{}{&empty})
	if err != nil {
		return nil, err
	}
	b3, err := constructPasswordAuthArea(parentPassword, Handle(OrdTPM_RS_PW))
	if err != nil {
		return nil, err
	}
	b4, err := pack([]interface{}{&toQuote, &sigAlg})
	if err != nil {
		return nil, err
	}
	b5, err := constructLongPCR(uint32(1), pcrNums)
	if err != nil {
		return nil, err
	}
	args := append(b1, b2...)
	args = append(args, b3...)
	args = append(args, b4...)
	args = append(args, b5...)
	return packWithBytes(cmdHdr, args)
}

// decodeQuote decodes a Quote response.
// Output: attest, signature
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

// Quote
// 	Output: attest, sig
func Quote(rw io.ReadWriter, signingHandle Handle, parentPassword, ownerPassword string, toQuote []byte, pcrNums []int, sigAlg uint16) ([]byte, []byte, error) {
	cmd, err := constructQuote(signingHandle, parentPassword, ownerPassword, toQuote, pcrNums, sigAlg)
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

// constructActivateCredential constructs a ActivateCredential command.
func constructActivateCredential(activeHandle Handle, keyHandle Handle, activePassword, protectorPassword string, credBlob, secret []byte) ([]byte, error) {
	var empty []byte
	cmdHdr := commandHeader{Tag: tagSESSIONS, Cmd: cmdActivateCredential}
	b1, err := constructHandle(activeHandle)
	if err != nil {
		return nil, err
	}
	b2, err := constructHandle(keyHandle)
	if err != nil {
		return nil, err
	}
	b3, err := pack([]interface{}{&empty})
	if err != nil {
		return nil, err
	}
	b4a, err := constructPasswordAuthArea(activePassword, Handle(OrdTPM_RS_PW))
	if err != nil {
		return nil, err
	}
	b4b, err := constructPasswordAuthArea(protectorPassword, Handle(OrdTPM_RS_PW))
	if err != nil {
		return nil, err
	}
	b4t := append(b4a[2:], b4b[2:]...)
	b4, err := pack([]interface{}{&b4t})
	if err != nil {
		return nil, err
	}
	b5, err := pack([]interface{}{&credBlob, &secret})
	if err != nil {
		return nil, err
	}
	args := append(b1, b2...)
	args = append(args, b3...)
	args = append(args, b4...)
	args = append(args, b5...)
	return packWithBytes(cmdHdr, args)
}

// decodeActivateCredential decodes a ActivateCredential response.
// returns certInfo
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

// ActivateCredential
// 	Output: certinfo
func ActivateCredential(rw io.ReadWriter, activeHandle, keyHandle Handle, activePassword, protectorPassword string, credBlob, secret []byte) ([]byte, error) {
	cmd, err := constructActivateCredential(activeHandle, keyHandle, activePassword, protectorPassword, credBlob, secret)
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

// constructEvictControl constructs a EvictControl command.
func constructEvictControl(owner Handle, tmpHandle, persistantHandle Handle) ([]byte, error) {
	var empty []byte
	cmdHdr := commandHeader{Tag: tagSESSIONS, Cmd: cmdEvictControl}
	b1, err := constructHandle(owner)
	if err != nil {
		return nil, err
	}
	b2, err := constructHandle(tmpHandle)
	if err != nil {
		return nil, err
	}
	b3, err := pack([]interface{}{&empty})
	if err != nil {
		return nil, err
	}
	b4, err := constructPasswordAuthArea("", Handle(OrdTPM_RS_PW))
	if err != nil {
		return nil, err
	}
	b5, err := constructHandle(persistantHandle)
	if err != nil {
		return nil, err
	}
	args := append(b1, b2...)
	args = append(args, b3...)
	args = append(args, b4...)
	args = append(args, b5...)
	return packWithBytes(cmdHdr, args)
}

func EvictControl(rw io.ReadWriter, owner Handle, tmpHandle Handle, persistantHandle Handle) error {
	cmd, err := constructEvictControl(owner, tmpHandle, persistantHandle)
	if err != nil {
		return err
	}
	_, err = runCommand(rw, cmd)
	return err
}

// constructSaveContext constructs a SaveContext command.
func constructSaveContext(handle Handle) ([]byte, error) {
	cmdHdr := commandHeader{Tag: tagNO_SESSIONS, Cmd: cmdContextSave}
	b1, err := constructHandle(handle)
	if err != nil {
		return nil, err
	}
	return packWithBytes(cmdHdr, b1)
}

func SaveContext(rw io.ReadWriter, handle Handle) ([]byte, error) {
	cmd, err := constructSaveContext(handle)
	if err != nil {
		return nil, err
	}
	return runCommand(rw, cmd)
}

// constructLoadContext constructs a LoadContext command.
func constructLoadContext(saveArea []byte) ([]byte, error) {
	cmdHdr := commandHeader{Tag: tagNO_SESSIONS, Cmd: cmdContextLoad}
	return packWithBytes(cmdHdr, saveArea[0:len(saveArea)])
}

// decodeLoadContext decodes a LoadContext response.
func decodeLoadContext(in []byte) (Handle, error) {
	var handle uint32
	template := []interface{}{&handle}
	err := unpack(in, template)
	if err != nil {
		return 0, err
	}
	return Handle(handle), nil
}

func LoadContext(rw io.ReadWriter, saveArea []byte) (Handle, error) {
	cmd, err := constructLoadContext(saveArea)
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

// constructMakeCredential constructs a MakeCredential command.
func constructMakeCredential(protectorHandle Handle, credential, activeName []byte) ([]byte, error) {
	cmdHdr := commandHeader{Tag: tagNO_SESSIONS, Cmd: cmdMakeCredential}
	b1, err := constructHandle(protectorHandle)
	if err != nil {
		return nil, err
	}
	b2, err := pack([]interface{}{&credential, activeName})
	if err != nil {
		return nil, err
	}
	return packWithBytes(cmdHdr, append(b1, b2...))
}

// decodeMakeCredential decodes a MakeCredential response.
// returns blob, encryptedSecret
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

// MakeCredential
// 	Output: blob, secret
func MakeCredential(rw io.ReadWriter, protectorHandle Handle, credential, activeName []byte) ([]byte, []byte, error) {
	cmd, err := constructMakeCredential(protectorHandle, credential, activeName)
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

func constructUndefineSpace(owner Handle, handle Handle) ([]byte, error) {
	cmdHdr := commandHeader{Tag: tagSESSIONS, Cmd: cmdUndefineSpace}
	auth, err := constructPasswordAuthArea("", Handle(OrdTPM_RS_PW))
	if err != nil {
		return nil, err
	}
	numBytes := []interface{}{uint32(owner), uint32(handle), uint16(0)}
	out, err := pack(numBytes)
	if err != nil {
		return nil, err
	}
	out = append(out, auth...)
	return packWithBytes(cmdHdr, out)
}

func UndefineSpace(rw io.ReadWriter, owner Handle, handle Handle) error {
	cmd, err := constructUndefineSpace(owner, handle)
	if err != nil {
		return err
	}
	_, err = runCommand(rw, cmd)
	return err
}

func constructDefineSpace(owner, handle Handle, authString string, attributes uint32, policy []byte, dataSize uint16) ([]byte, error) {
	pw, err := constructPasswordData(authString)
	if err != nil {
		return nil, err
	}
	auth, err := constructPasswordAuthArea("", Handle(OrdTPM_RS_PW))
	if err != nil {
		return nil, err
	}
	var empty []byte
	numBytes := []interface{}{uint32(owner), empty}
	out1, err := pack(numBytes)
	if err != nil {
		return nil, err
	}
	hashAlg := uint16(AlgTPM_ALG_SHA1)
	sizeNvArea := uint16(2*int(unsafe.Sizeof(owner)) + 3*int(unsafe.Sizeof(dataSize)) + len(policy))
	out1 = append(append(out1, auth...), pw...)
	numBytes2 := []interface{}{sizeNvArea, uint32(handle), hashAlg, attributes, policy, dataSize}
	out2, err := pack(numBytes2)
	if err != nil {
		return nil, err
	}
	cmdHdr := commandHeader{Tag: tagSESSIONS, Cmd: cmdDefineSpace}
	return packWithBytes(cmdHdr, append(out1, out2...))
}

func DefineSpace(rw io.ReadWriter, owner, handle Handle, authString string, policy []byte, attributes uint32, dataSize uint16) error {
	cmd, err := constructDefineSpace(owner, handle, authString, attributes, policy, dataSize)
	if err != nil {
		return err
	}
	_, err = runCommand(rw, cmd)
	return err
}

func constructIncrementNv(handle Handle, authString string) ([]byte, error) {
	auth, err := constructPasswordAuthArea(authString, Handle(OrdTPM_RS_PW))
	if err != nil {
		return nil, err
	}
	var empty []byte
	numBytes := []interface{}{uint32(handle), int32(handle), empty}
	out, err := pack(numBytes)
	if err != nil {
		return nil, err
	}
	out = append(out, auth...)
	cmdHdr := commandHeader{Tag: tagSESSIONS, Cmd: cmdIncrementNvCounter}
	return packWithBytes(cmdHdr, out)
}

func IncrementNv(rw io.ReadWriter, handle Handle, authString string) error {
	cmd, err := constructIncrementNv(handle, authString)
	if err != nil {
		return err
	}
	_, err = runCommand(rw, cmd)
	return err
}

func decodeReadNv(in []byte) (uint64, error) {
	var respSize uint32
	var byteCounter []byte
	err := unpack(in, []interface{}{&respSize, &byteCounter})
	if err != nil {
		return 0, err
	}
	var c uint64
	for i := 0; i < len(byteCounter); i++ {
		c = c*256 + uint64(byteCounter[i])
	}
	return c, nil
}

func constructReadNv(handle Handle, authString string, offset, dataSize uint16) ([]byte, error) {
	auth, err := constructPasswordAuthArea(authString, Handle(OrdTPM_RS_PW))
	if err != nil {
		return nil, err
	}
	var empty []byte
	numBytes := []interface{}{uint32(handle), int32(handle), empty}
	out, err := pack(numBytes)
	if err != nil {
		return nil, err
	}
	out = append(out, auth...)
	numBytes2 := []interface{}{dataSize, offset}
	out2, err := pack(numBytes2)
	if err != nil {
		return nil, err
	}
	cmdHdr := commandHeader{Tag: tagSESSIONS, Cmd: cmdReadNv}
	return packWithBytes(cmdHdr, append(out, out2...))
}

func ReadNv(rw io.ReadWriter, handle Handle, authString string, offset, dataSize uint16) (uint64, error) {
	cmd, err := constructReadNv(handle, authString, offset, dataSize)
	if err != nil {
		return 0, err
	}
	resp, err := runCommand(rw, cmd)
	if err != nil {
		return 0, err
	}
	return decodeReadNv(resp)
}

func GetCounter(rw io.ReadWriter, nvHandle Handle, authString string) (int64, error) {
	c, err := ReadNv(rw, nvHandle, authString, 0, 8)
	if err != nil {
		return 0, err
	}
	return int64(c), nil
}

func InitCounter(rw io.ReadWriter, nvHandle Handle, authString string) error {
	owner := Handle(OrdTPM_RH_OWNER)
	dataSize := uint16(8)
	var tpmPolicy []byte // empty
	attributes := OrdNV_COUNTER | OrdNV_AUTHWRITE | OrdNV_AUTHREAD
	err := UndefineSpace(rw, owner, nvHandle)
	if err != nil {
		return fmt.Errorf("UndefineSpace: %v", err)
	}
	err = DefineSpace(rw, owner, nvHandle, authString, tpmPolicy, attributes, dataSize)
	if err != nil {
		return fmt.Errorf("DefineSpace: %v", err)
	}
	return IncrementNv(rw, nvHandle, authString)
}

func Hash(rw io.ReadWriter, alg uint16, buf []byte) ([]byte, error) {
	out, err := pack([]interface{}{buf, alg, OrdTPM_RH_NULL})
	if err != nil {
		return nil, err
	}
	cmdHdr := commandHeader{Tag: tagNO_SESSIONS, Cmd: cmdHash}
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

func Startup(rw io.ReadWriter, typ uint16) error {
	out, err := pack([]interface{}{typ})
	if err != nil {
		return err
	}
	cmdHdr := commandHeader{Tag: tagNO_SESSIONS, Cmd: cmdStartup}
	cmd, err := packWithBytes(cmdHdr, out)
	if err != nil {
		return err
	}

	_, err = runCommand(rw, cmd)
	return err
}

func Shutdown(rw io.ReadWriter, typ uint16) error {
	out, err := pack([]interface{}{typ})
	if err != nil {
		return err
	}
	cmdHdr := commandHeader{Tag: tagNO_SESSIONS, Cmd: cmdShutdown}
	cmd, err := packWithBytes(cmdHdr, out)
	if err != nil {
		return err
	}

	_, err = runCommand(rw, cmd)
	return err
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
	if read < responseHeaderSize {
		return nil, errors.New("response buffer too small")
	}

	header, resp := resp[:responseHeaderSize], resp[responseHeaderSize:read]

	_, _, status, err := decodeCommandResponse(header)
	if err != nil {
		return nil, err
	}
	if status != rcSuccess {
		return nil, fmt.Errorf("response status 0x%x", status)
	}

	return resp, nil
}
