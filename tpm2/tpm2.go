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

// Package tpm2 supports direct communication with a TPM 2.0 device under Linux.
package tpm2

import (
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"unsafe"

	"github.com/awly/go-tpm/tpmutil"
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

func encodePasswordData(password string) ([]byte, error) {
	pw, err := hex.DecodeString(password)
	if err != nil {
		return nil, err
	}
	return tpmutil.Pack(pw)
}

func encodePasswordAuthArea(password string, owner Handle) ([]byte, error) {
	ownerStr, err := tpmutil.Pack(owner)
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
	return tpmutil.Pack(buf)
}

func encodeSensitiveArea(in1 []byte, in2 []byte) ([]byte, error) {
	t1, err := tpmutil.Pack(in1)
	if err != nil {
		return nil, err
	}
	t2, err := tpmutil.Pack(in2)
	if err != nil {
		return nil, err
	}

	t := append(t1, t2...)
	return tpmutil.Pack(t)
}

func decodeRSABuf(rsaBuf []byte) (*RSAParams, error) {
	parms := new(RSAParams)
	current := 0
	err := tpmutil.Unpack(rsaBuf[current:], &parms.EncAlg, &parms.HashAlg, &parms.Attributes, &parms.AuthPolicy)
	if err != nil {
		return nil, err
	}
	current += 10 + len(parms.AuthPolicy)
	err = tpmutil.Unpack(rsaBuf[current:], &parms.SymAlg)
	if err != nil {
		return nil, err
	}
	current += 2
	if parms.SymAlg != AlgNull {
		err = tpmutil.Unpack(rsaBuf[current:], &parms.SymSize, &parms.Mode)
		if err != nil {
			return nil, err
		}
		current += 4
	} else {
		parms.SymSize = 0
		parms.Mode = 0
		parms.Scheme = 0
	}
	err = tpmutil.Unpack(rsaBuf[current:], &parms.Scheme)
	if err != nil {
		return nil, err
	}
	current += 2
	if parms.Scheme == AlgRSASSA {
		err = tpmutil.Unpack(rsaBuf[current:], &parms.SchemeHash)
		if err != nil {
			return nil, err
		}
		current += 2
	}

	err = tpmutil.Unpack(rsaBuf[current:], &parms.ModSize, &parms.Exp, &parms.Modulus)
	if err != nil {
		return nil, err
	}
	return parms, nil
}

func decodeRSAArea(in []byte) (*RSAParams, error) {
	var rsaBuf []byte

	err := tpmutil.Unpack(in, &rsaBuf)
	if err != nil {
		return nil, err
	}
	return decodeRSABuf(rsaBuf)
}

func encodeKeyedHashParams(parms KeyedHashParams) ([]byte, error) {
	return tpmutil.Pack(
		parms.TypeAlg,
		parms.HashAlg,
		parms.Attributes,
		parms.AuthPolicy,
		parms.Scheme,
		parms.Unique,
	)
}

func encodeRSAParams(parms RSAParams) ([]byte, error) {
	t1, err := tpmutil.Pack(
		parms.EncAlg,
		parms.HashAlg,
		parms.Attributes,
		parms.AuthPolicy,
	)
	if err != nil {
		return nil, err
	}

	var template []interface{}
	if parms.SymAlg != AlgNull {
		template = []interface{}{
			parms.SymAlg,
			parms.SymSize,
			parms.Mode,
			parms.Scheme,
		}
	} else {
		template = []interface{}{parms.SymAlg, parms.Scheme}
	}
	t2, err := tpmutil.Pack(template...)
	if err != nil {
		return nil, err
	}
	if parms.Scheme == AlgRSASSA {
		t3, err := tpmutil.Pack(parms.SchemeHash)
		if err != nil {
			return nil, err
		}
		t2 = append(t2, t3...)
	}

	t4, err := tpmutil.Pack(parms.ModSize, parms.Exp, parms.Modulus)
	if err != nil {
		return nil, err
	}

	t5 := append(t1, t2...)
	t5 = append(t5, t4...)
	return tpmutil.Pack(t5)
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
		return tpmutil.Pack(count)
	}
	b1, err := encodeShortPCRs(pcrNums)
	if err != nil {
		return nil, err
	}
	return tpmutil.Pack(count, b1)
}

func decodeGetRandom(in []byte) ([]byte, error) {
	var randBytes []byte

	err := tpmutil.Unpack(in, &randBytes)
	if err != nil {
		return nil, err
	}
	return randBytes, nil
}

// GetRandom gets random bytes from the TPM.
func GetRandom(rw io.ReadWriteCloser, size uint16) ([]byte, error) {
	resp, err := runCommand(rw, tagNoSessions, cmdGetRandom, size)
	if err != nil {
		return nil, err
	}

	rand, err := decodeGetRandom(resp)
	if err != nil {
		return nil, err
	}
	return rand, nil
}

// FlushContext removes an object or session under handle to be removed from
// the TPM. This must be called for any loaded handle to avoid out-of-memory
// errors in TPM.
func FlushContext(rw io.ReadWriter, handle Handle) error {
	_, err := runCommand(rw, tagNoSessions, cmdFlushContext, handle)
	return err
}

func decodeReadPCRs(in []byte) (uint32, []byte, uint16, []byte, error) {
	var pcr []byte
	var digest []byte
	var updateCounter uint32
	var t uint32
	var s uint32

	err := tpmutil.Unpack(in, &t, &updateCounter, &pcr, &s, &digest)
	if err != nil {
		return 0, nil, 0, nil, err
	}
	return updateCounter, pcr, uint16(t), digest, nil
}

// ReadPCRs reads a PCR value from the TPM.
func ReadPCRs(rw io.ReadWriter, pcrSelect []byte) (uint32, []byte, uint16, []byte, error) {
	resp, err := runCommand(rw, tagNoSessions, cmdPCRRead, 1, pcrSelect)
	if err != nil {
		return 0, nil, 0, nil, err
	}

	counter, pcr, alg, digest, err := decodeReadPCRs(resp)
	if err != nil {
		return 0, nil, 0, nil, err
	}
	return counter, pcr, alg, digest, err
}

func decodeReadClock(in []byte) (uint64, uint64, error) {
	var curTime, curClock uint64

	err := tpmutil.Unpack(in, &curTime, &curClock)
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
	resp, err := runCommand(rw, tagNoSessions, cmdReadClock)
	if err != nil {
		return 0, 0, err
	}
	curTime, curClock, err := decodeReadClock(resp)
	if err != nil {
		return 0, 0, err
	}
	return curTime, curClock, nil
}

func decodeGetCapability(in []byte) (Capability, []Handle, error) {
	var numHandles uint32
	var capReported Capability

	err := tpmutil.Unpack(in[1:9], &capReported, &numHandles)
	if err != nil {
		return 0, nil, err
	}
	// only TPM_CAP_HANDLES handled
	if capReported != CapabilityHandles {
		return 0, nil, fmt.Errorf("Only TPM_CAP_HANDLES supported, got %v", capReported)
	}
	var handles []Handle
	var handle Handle
	for i := 0; i < int(numHandles); i++ {
		err := tpmutil.Unpack(in[8+4*i:12+4*i], &handle)
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
	resp, err := runCommand(rw, tagNoSessions, cmdGetCapability, cap, property, count)
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
	b1, err := tpmutil.Pack(pcrNum, []byte(nil))
	if err != nil {
		return nil, err
	}
	b2, err := encodePasswordAuthArea("", HandlePasswordSession)
	if err != nil {
		return nil, err
	}
	b3, err := tpmutil.Pack(eventData)
	if err != nil {
		return nil, err
	}
	return append(append(b1, b2...), b3...), nil
}

// PCREvent writes an update to the specified PCR.
func PCREvent(rw io.ReadWriter, pcrNum uint32, eventData []byte) error {
	cmd, err := encodePCREvent(pcrNum, eventData)
	if err != nil {
		return err
	}
	_, err = runCommand(rw, tagSessions, cmdPCREvent, tpmutil.RawBytes(cmd))
	return err
}

func encodeCreatePrimary(owner Handle, pcrNums []int, parentPassword, ownerPassword string, parms RSAParams) ([]byte, error) {
	b1, err := tpmutil.Pack(Handle(owner))
	if err != nil {
		return nil, err
	}
	b2, err := tpmutil.Pack([]byte(nil))
	if err != nil {
		return nil, err
	}
	b3, err := encodePasswordAuthArea(parentPassword, HandlePasswordSession)
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
	b6, err := tpmutil.Pack([]byte(nil))
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
	return args, nil
}

func decodeCreatePrimary(in []byte) (Handle, []byte, error) {
	var handle Handle
	var auth []byte

	// handle and auth data
	err := tpmutil.Unpack(in, &handle, &auth)
	if err != nil {
		return 0, nil, err
	}

	var current int
	current = 6 + 2*len(auth)
	// size, size-public
	var tpm2Public []byte
	err = tpmutil.Unpack(in[current:], &tpm2Public)
	if err != nil {
		return 0, nil, err
	}

	var rsaParamsBuf []byte
	err = tpmutil.Unpack(tpm2Public, &rsaParamsBuf)
	if err != nil {
		return 0, nil, err
	}
	var pub tpmtPublic
	if err := tpmutil.Unpack(rsaParamsBuf, &pub); err != nil {
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
	resp, err := runCommand(rw, tagSessions, cmdCreatePrimary, tpmutil.RawBytes(cmd))
	if err != nil {
		return 0, nil, err
	}

	handle, publicBlob, err := decodeCreatePrimary(resp)
	if err != nil {
		return 0, nil, err
	}
	return Handle(handle), publicBlob, nil
}

func decodeReadPublic(in []byte) ([]byte, []byte, []byte, error) {
	var publicBlob []byte
	var name []byte
	var qualifiedName []byte

	err := tpmutil.Unpack(in, &publicBlob, &name, &qualifiedName)
	if err != nil {
		return nil, nil, nil, err
	}
	return publicBlob, name, qualifiedName, nil
}

// ReadPublic reads the public part of the object under handle.
// Returns the public data, name and qualified name.
func ReadPublic(rw io.ReadWriter, handle Handle) ([]byte, []byte, []byte, error) {
	resp, err := runCommand(rw, tagNoSessions, cmdReadPublic, handle)
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
	b1, err := tpmutil.Pack(Handle(owner))
	if err != nil {
		return nil, err
	}
	b2, err := tpmutil.Pack([]byte(nil))
	if err != nil {
		return nil, err
	}
	b3, err := encodePasswordAuthArea(parentPassword, HandlePasswordSession)
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
	b6, err := tpmutil.Pack([]byte(nil))
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
	return args, nil
}

func decodeCreateKey(in []byte) ([]byte, []byte, error) {
	var tpm2bPrivate []byte
	var tpm2bPublic []byte

	err := tpmutil.Unpack(in[4:], &tpm2bPrivate, &tpm2bPublic)
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
	resp, err := runCommand(rw, tagSessions, cmdCreate, tpmutil.RawBytes(cmd))
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
	b1, err := tpmutil.Pack(parentHandle)
	if err != nil {
		return nil, err
	}
	b3, err := encodePasswordData(parentAuth)
	if err != nil {
		return nil, err
	}
	b4, err := encodePasswordAuthArea(ownerAuth, HandlePasswordSession)
	if err != nil {
		return nil, err
	}
	b5, err := tpmutil.Pack(privateBlob, publicBlob)
	if err != nil {
		return nil, err
	}
	args := append(b1, b3...)
	args = append(args, b4...)
	args = append(args, b5...)
	return args, nil
}

func decodeLoad(in []byte) (Handle, []byte, error) {
	var handle Handle
	var auth []byte
	var name []byte

	err := tpmutil.Unpack(in, &handle, &auth, &name)
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
	resp, err := runCommand(rw, tagSessions, cmdLoad, tpmutil.RawBytes(cmd))
	if err != nil {
		return 0, nil, err
	}
	handle, name, err := decodeLoad(resp)
	if err != nil {
		return 0, nil, err
	}
	return handle, name, nil
}

// PolicyPassword sets password authorization requirement on the object.
func PolicyPassword(rw io.ReadWriter, handle Handle) error {
	_, err := runCommand(rw, tagNoSessions, cmdPolicyPassword, handle)
	return err
}

func encodePolicyPCR(handle Handle, expectedDigest []byte, pcrNums []int) ([]byte, error) {
	b1, err := tpmutil.Pack(handle, expectedDigest)
	if err != nil {
		return nil, err
	}
	b2, err := encodeLongPCR(1, pcrNums)
	if err != nil {
		return nil, err
	}
	return append(b1, b2...), nil
}

// PolicyPCR sets PCR state binding for authorization on the object.
func PolicyPCR(rw io.ReadWriter, handle Handle, expectedDigest []byte, pcrNums []int) error {
	cmd, err := encodePolicyPCR(handle, expectedDigest, pcrNums)
	if err != nil {
		return err
	}
	_, err = runCommand(rw, tagNoSessions, cmdPolicyPCR, tpmutil.RawBytes(cmd))
	return err
}

func decodePolicyGetDigest(in []byte) ([]byte, error) {
	var digest []byte

	err := tpmutil.Unpack(in, &digest)
	if err != nil {
		return nil, err
	}
	return digest, nil
}

// PolicyGetDigest returns the current policyDigest of the session.
func PolicyGetDigest(rw io.ReadWriter, handle Handle) ([]byte, error) {
	resp, err := runCommand(rw, tagNoSessions, cmdPolicyGetDigest, handle)
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
	b1, err := tpmutil.Pack(tpmKey)
	if err != nil {
		return nil, err
	}
	b2, err := tpmutil.Pack(bindKey)
	if err != nil {
		return nil, err
	}
	b3, err := tpmutil.Pack(nonceCaller, secret)
	if err != nil {
		return nil, err
	}
	b5, err := tpmutil.Pack(sym, hashAlg)
	if err != nil {
		return nil, err
	}
	args := append(b1, b2...)
	args = append(args, b3...)
	args = append(args, byte(se))
	args = append(args, b5...)
	return args, nil
}

func decodeStartAuthSession(in []byte) (Handle, []byte, error) {
	var handle Handle
	var nonce []byte
	err := tpmutil.Unpack(in, &handle, &nonce)
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
	resp, err := runCommand(rw, tagNoSessions, cmdStartAuthSession, tpmutil.RawBytes(cmd))
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
	b1, err := tpmutil.Pack(itemHandle, []byte(nil))
	if err != nil {
		return nil, err
	}
	b2, err := encodePasswordAuthArea(password, sessionHandle)
	if err != nil {
		return nil, err
	}
	return append(b1, b2...), nil
}

func decodeUnseal(in []byte) ([]byte, []byte, error) {
	var unsealed []byte
	var digest []byte

	err := tpmutil.Unpack(in[4:], &unsealed, &digest)
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
	resp, err := runCommand(rw, tagSessions, cmdUnseal, tpmutil.RawBytes(cmd))
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
	b1, err := tpmutil.Pack(signingHandle)
	if err != nil {
		return nil, err
	}
	b2, err := tpmutil.Pack([]byte(nil))
	if err != nil {
		return nil, err
	}
	b3, err := encodePasswordAuthArea(parentPassword, HandlePasswordSession)
	if err != nil {
		return nil, err
	}
	b4, err := tpmutil.Pack(toQuote, sigAlg)
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
	return args, nil
}

func decodeQuote(in []byte) ([]byte, uint16, uint16, []byte, error) {
	var empty []byte
	var buf []byte
	var attest []byte
	var signature []byte
	var s1 uint16
	var s2 uint16

	err := tpmutil.Unpack(in, &empty, &buf)
	if err != nil {
		return nil, 0, 0, nil, err
	}

	err = tpmutil.Unpack(buf, &attest, &s1, &s2, &signature)
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
	resp, err := runCommand(rw, tagSessions, cmdQuote, tpmutil.RawBytes(cmd))
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
	b1, err := tpmutil.Pack(activeHandle)
	if err != nil {
		return nil, err
	}
	b2, err := tpmutil.Pack(keyHandle)
	if err != nil {
		return nil, err
	}
	b3, err := tpmutil.Pack([]byte(nil))
	if err != nil {
		return nil, err
	}
	b4a, err := encodePasswordAuthArea(activePassword, HandlePasswordSession)
	if err != nil {
		return nil, err
	}
	b4b, err := encodePasswordAuthArea(protectorPassword, HandlePasswordSession)
	if err != nil {
		return nil, err
	}
	b4t := append(b4a[2:], b4b[2:]...)
	b4, err := tpmutil.Pack(b4t)
	if err != nil {
		return nil, err
	}
	b5, err := tpmutil.Pack(credBlob, secret)
	if err != nil {
		return nil, err
	}
	args := append(b1, b2...)
	args = append(args, b3...)
	args = append(args, b4...)
	args = append(args, b5...)
	return args, nil
}

func decodeActivateCredential(in []byte) ([]byte, error) {
	var empty []byte
	var buf []byte
	var certInfo []byte

	err := tpmutil.Unpack(in, &empty, &buf)
	if err != nil {
		return nil, err
	}
	err = tpmutil.Unpack(buf, &certInfo)
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
	resp, err := runCommand(rw, tagSessions, cmdActivateCredential, tpmutil.RawBytes(cmd))
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
	b1, err := tpmutil.Pack(protectorHandle)
	if err != nil {
		return nil, err
	}
	b2, err := tpmutil.Pack(credential, activeName)
	if err != nil {
		return nil, err
	}
	return append(b1, b2...), nil
}

func decodeMakeCredential(in []byte) ([]byte, []byte, error) {
	var credBlob []byte
	var encryptedSecret []byte

	err := tpmutil.Unpack(in, &credBlob, &encryptedSecret)
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
	resp, err := runCommand(rw, tagNoSessions, cmdMakeCredential, tpmutil.RawBytes(cmd))
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
	b1, err := tpmutil.Pack(owner)
	if err != nil {
		return nil, err
	}
	b2, err := tpmutil.Pack(tmpHandle)
	if err != nil {
		return nil, err
	}
	b3, err := tpmutil.Pack([]byte(nil))
	if err != nil {
		return nil, err
	}
	b4, err := encodePasswordAuthArea("", HandlePasswordSession)
	if err != nil {
		return nil, err
	}
	b5, err := tpmutil.Pack(persistantHandle)
	if err != nil {
		return nil, err
	}
	args := append(b1, b2...)
	args = append(args, b3...)
	args = append(args, b4...)
	args = append(args, b5...)
	return args, nil
}

// EvictControl toggles persistence of an object within the TPM.
func EvictControl(rw io.ReadWriter, owner, tmpHandle, persistantHandle Handle) error {
	cmd, err := encodeEvictControl(owner, tmpHandle, persistantHandle)
	if err != nil {
		return err
	}
	_, err = runCommand(rw, tagSessions, cmdEvictControl, tpmutil.RawBytes(cmd))
	return err
}

// ContextSave returns an encrypted version of the session, object or sequence
// context for storage outside of the TPM.
func ContextSave(rw io.ReadWriter, handle Handle) ([]byte, error) {
	return runCommand(rw, tagNoSessions, cmdContextSave, handle)
}

func decodeLoadContext(in []byte) (Handle, error) {
	var handle Handle
	err := tpmutil.Unpack(in, &handle)
	if err != nil {
		return 0, err
	}
	return Handle(handle), nil
}

// ContextLoad reloads context data created by ContextSave.
func ContextLoad(rw io.ReadWriter, saveArea []byte) (Handle, error) {
	resp, err := runCommand(rw, tagNoSessions, cmdContextLoad, tpmutil.RawBytes(saveArea))
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
	auth, err := encodePasswordAuthArea(authString, HandlePasswordSession)
	if err != nil {
		return nil, err
	}
	out, err := tpmutil.Pack(handle, handle, []byte(nil))
	if err != nil {
		return nil, err
	}
	out = append(out, auth...)
	return out, nil
}

// NVIncrement increments a counter NV index.
func NVIncrement(rw io.ReadWriter, handle Handle, authString string) error {
	cmd, err := encodeIncrementNv(handle, authString)
	if err != nil {
		return err
	}
	_, err = runCommand(rw, tagSessions, cmdIncrementNvCounter, tpmutil.RawBytes(cmd))
	return err
}

func encodeUndefineSpace(owner, handle Handle) ([]byte, error) {
	auth, err := encodePasswordAuthArea("", HandlePasswordSession)
	if err != nil {
		return nil, err
	}
	out, err := tpmutil.Pack(owner, handle, uint16(0))
	if err != nil {
		return nil, err
	}
	out = append(out, auth...)
	return out, nil
}

// NVUndefineSpace removes an index from TPM's NV storage.
func NVUndefineSpace(rw io.ReadWriter, owner, handle Handle) error {
	cmd, err := encodeUndefineSpace(owner, handle)
	if err != nil {
		return err
	}
	_, err = runCommand(rw, tagSessions, cmdUndefineSpace, tpmutil.RawBytes(cmd))
	return err
}

func encodeDefineSpace(owner, handle Handle, authString string, attributes uint32, policy []byte, dataSize uint16) ([]byte, error) {
	pw, err := encodePasswordData(authString)
	if err != nil {
		return nil, err
	}
	auth, err := encodePasswordAuthArea("", HandlePasswordSession)
	if err != nil {
		return nil, err
	}
	out1, err := tpmutil.Pack(owner, []byte(nil))
	if err != nil {
		return nil, err
	}
	hashAlg := AlgSHA1
	sizeNvArea := uint16(2*int(unsafe.Sizeof(owner)) + 3*int(unsafe.Sizeof(dataSize)) + len(policy))
	out1 = append(append(out1, auth...), pw...)
	out2, err := tpmutil.Pack(sizeNvArea, handle, hashAlg, attributes, policy, dataSize)
	if err != nil {
		return nil, err
	}
	return append(out1, out2...), nil
}

// NVDefineSpace creates an index in TPM's NV storage.
func NVDefineSpace(rw io.ReadWriter, owner, handle Handle, authString string, policy []byte, attributes uint32, dataSize uint16) error {
	cmd, err := encodeDefineSpace(owner, handle, authString, attributes, policy, dataSize)
	if err != nil {
		return err
	}
	_, err = runCommand(rw, tagSessions, cmdDefineSpace, tpmutil.RawBytes(cmd))
	return err
}

func decodeNVReadPublic(in []byte) (NVPublic, error) {
	var pub NVPublic
	var buf []byte
	if err := tpmutil.Unpack(in, &buf); err != nil {
		return pub, err
	}
	err := tpmutil.Unpack(buf, &pub)
	return pub, err
}

func decodeNVRead(in []byte) ([]byte, error) {
	var sessionAttributes uint32
	var data []byte
	if err := tpmutil.Unpack(in, &sessionAttributes, &data); err != nil {
		return nil, err
	}
	return data, nil
}

func encodeNVRead(handle Handle, authString string, offset, dataSize uint16) ([]byte, error) {
	out, err := tpmutil.Pack(handle, handle, []byte(nil))
	if err != nil {
		return nil, err
	}
	auth, err := encodePasswordAuthArea(authString, HandlePasswordSession)
	if err != nil {
		return nil, err
	}
	out = append(out, auth...)
	params, err := tpmutil.Pack(dataSize, offset)
	if err != nil {
		return nil, err
	}
	out = append(out, params...)
	return out, nil
}

// NVRead reads full data blob from NV index.
func NVRead(rw io.ReadWriter, index Handle) ([]byte, error) {
	// Read public area to determine data size.
	resp, err := runCommand(rw, tagNoSessions, cmdReadPublicNv, index)
	if err != nil {
		return nil, fmt.Errorf("running NV_ReadPublic command: %v", err)
	}
	pub, err := decodeNVReadPublic(resp)
	if err != nil {
		return nil, fmt.Errorf("decoding NV_ReadPublic response: %v", err)
	}

	// Read pub.DataSize of actual data.
	cmd, err := encodeNVRead(index, "", 0, pub.DataSize)
	if err != nil {
		return nil, fmt.Errorf("building NV_Read command: %v", err)
	}
	resp, err = runCommand(rw, tagSessions, cmdReadNv, tpmutil.RawBytes(cmd))
	if err != nil {
		return nil, fmt.Errorf("running NV_Read command: %v", err)
	}
	return decodeNVRead(resp)
}

// Hash computes a hash of data in buf using the TPM.
func Hash(rw io.ReadWriter, alg Algorithm, buf []byte) ([]byte, error) {
	resp, err := runCommand(rw, tagNoSessions, cmdHash, buf, alg, HandleNull)
	if err != nil {
		return nil, err
	}

	var digest []byte
	if err = tpmutil.Unpack(resp, &digest); err != nil {
		return nil, fmt.Errorf("decoding Hash response: %v", err)
	}
	return digest, nil
}

// Startup initializes a TPM (usually done by the OS).
func Startup(rw io.ReadWriter, typ StartupType) error {
	_, err := runCommand(rw, tagNoSessions, cmdStartup, typ)
	return err
}

// Shutdown shuts down a TPM (usually done by the OS).
func Shutdown(rw io.ReadWriter, typ StartupType) error {
	_, err := runCommand(rw, tagNoSessions, cmdShutdown, typ)
	return err
}

func encodeSign(key Handle, password string, digest []byte) ([]byte, error) {
	out, err := tpmutil.Pack(key, []byte(nil))
	if err != nil {
		return nil, err
	}
	auth, err := encodePasswordAuthArea(password, HandlePasswordSession)
	if err != nil {
		return nil, err
	}
	out = append(out, auth...)
	params, err := tpmutil.Pack(digest, AlgNull)
	if err != nil {
		return nil, err
	}
	out = append(out, params...)
	ticket, err := tpmutil.Pack(tagHashcheck, HandleNull, []byte(nil))
	if err != nil {
		return nil, err
	}
	out = append(out, ticket...)
	return out, nil
}

func decodeSign(buf []byte) (Algorithm, []byte, error) {
	var signAlg Algorithm
	var hashAlg Algorithm
	var signature []byte
	if err := tpmutil.Unpack(buf, &signAlg, &hashAlg, &signature); err != nil {
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
	resp, err := runCommand(rw, tagSessions, cmdReadNv, tpmutil.RawBytes(cmd))
	if err != nil {
		return 0, nil, err
	}
	return decodeSign(resp)
}

func runCommand(rw io.ReadWriter, tag tpmutil.Tag, cmd tpmutil.Command, in ...interface{}) ([]byte, error) {
	resp, code, err := tpmutil.RunCommand(rw, tag, cmd, in...)
	if err != nil {
		return nil, err
	}
	if code != tpmutil.RCSuccess {
		return nil, fmt.Errorf("response status 0x%x", code)
	}
	return resp, nil
}
