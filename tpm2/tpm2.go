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
	"unsafe"

	"github.com/google/go-tpm/tpmutil"
)

// OpenTPM opens a channel to the TPM at the given path. If the file is a
// device, then it treats it like a normal TPM device, and if the file is a
// Unix domain socket, then it opens a connection to the socket.
var OpenTPM = tpmutil.OpenTPM

func encodePasswordData(password string) ([]byte, error) {
	pw, err := hex.DecodeString(password)
	if err != nil {
		return nil, err
	}
	return tpmutil.Pack(pw)
}

func encodePasswordAuthArea(password string, owner tpmutil.Handle) ([]byte, error) {
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

func encodeSensitiveArea(in1, in2 []byte) ([]byte, error) {
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
	params := new(RSAParams)
	current := 0
	err := tpmutil.Unpack(rsaBuf[current:], &params.EncAlg, &params.HashAlg, &params.Attributes, &params.AuthPolicy)
	if err != nil {
		return nil, err
	}
	current += 10 + len(params.AuthPolicy)
	err = tpmutil.Unpack(rsaBuf[current:], &params.SymAlg)
	if err != nil {
		return nil, err
	}
	current += 2
	if params.SymAlg != AlgNull {
		err = tpmutil.Unpack(rsaBuf[current:], &params.SymSize, &params.Mode)
		if err != nil {
			return nil, err
		}
		current += 4
	} else {
		params.SymSize = 0
		params.Mode = 0
		params.Scheme = 0
	}
	err = tpmutil.Unpack(rsaBuf[current:], &params.Scheme)
	if err != nil {
		return nil, err
	}
	current += 2
	if params.Scheme == AlgRSASSA {
		err = tpmutil.Unpack(rsaBuf[current:], &params.SchemeHash)
		if err != nil {
			return nil, err
		}
		current += 2
	}

	err = tpmutil.Unpack(rsaBuf[current:], &params.ModSize, &params.Exp, &params.Modulus)
	if err != nil {
		return nil, err
	}
	return params, nil
}

func decodeRSAArea(in []byte) (*RSAParams, error) {
	var rsaBuf []byte

	err := tpmutil.Unpack(in, &rsaBuf)
	if err != nil {
		return nil, err
	}
	return decodeRSABuf(rsaBuf)
}

func encodeKeyedHashParams(params KeyedHashParams) ([]byte, error) {
	return tpmutil.Pack(
		params.TypeAlg,
		params.HashAlg,
		params.Attributes,
		params.AuthPolicy,
		params.Scheme,
		params.Unique,
	)
}

func encodeRSAParams(params RSAParams) ([]byte, error) {
	t1, err := tpmutil.Pack(
		params.EncAlg,
		params.HashAlg,
		params.Attributes,
		params.AuthPolicy,
	)
	if err != nil {
		return nil, err
	}

	var template []interface{}
	if params.SymAlg != AlgNull {
		template = []interface{}{
			params.SymAlg,
			params.SymSize,
			params.Mode,
			params.Scheme,
		}
	} else {
		template = []interface{}{params.SymAlg, params.Scheme}
	}
	t2, err := tpmutil.Pack(template...)
	if err != nil {
		return nil, err
	}
	if params.Scheme == AlgRSASSA {
		t3, err := tpmutil.Pack(params.SchemeHash)
		if err != nil {
			return nil, err
		}
		t2 = append(t2, t3...)
	}

	t4, err := tpmutil.Pack(params.ModSize, params.Exp, params.Modulus)
	if err != nil {
		return nil, err
	}

	t5 := append(t1, t2...)
	t5 = append(t5, t4...)
	return tpmutil.Pack(t5)
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
func FlushContext(rw io.ReadWriter, handle tpmutil.Handle) error {
	_, err := runCommand(rw, tagNoSessions, cmdFlushContext, handle)
	return err
}

func encodeShortPCRs(pcrNums []int) ([]byte, error) {
	// PCR selection is a variable-size bitmask, where position of a set bit is
	// the selected PCR index.
	// Size of the bitmask in bytes is pre-pended. It should be at least
	// sizeOfPCRSelect.
	//
	// For example, selecting PCRs 3 and 9 looks like:
	// size(3)  mask     mask     mask
	// 00000011 00000000 00000001 00000100
	pcr := make([]byte, sizeOfPCRSelect+1)
	pcr[0] = sizeOfPCRSelect
	// pcrNums parameter is indexes of PCRs, convert that to set bits.
	for _, n := range pcrNums {
		byteNum := 1 + n/8
		bytePos := byte(1 << byte(n%8))
		pcr[byteNum] |= bytePos
	}
	return pcr, nil
}

func encodeLongPCR(pcrNums []int) ([]byte, error) {
	if len(pcrNums) == 0 {
		return tpmutil.Pack(uint32(0))
	}
	pcrs, err := encodeShortPCRs(pcrNums)
	if err != nil {
		return nil, err
	}
	// Only encode 1 TPMS_PCR_SELECTION value.
	return tpmutil.Pack(uint32(1), pcrs)
}

func encodeReadPCRs(hash Algorithm, pcrs []int) ([]byte, error) {
	// Only encode 1 TPMS_PCR_SELECTION value.
	req, err := tpmutil.Pack(uint32(1), hash)
	if err != nil {
		return nil, err
	}
	enc, err := encodeShortPCRs(pcrs)
	if err != nil {
		return nil, err
	}
	req = append(req, enc...)
	return req, nil
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

// ReadPCRs reads PCR values from the TPM.
func ReadPCRs(rw io.ReadWriter, hash Algorithm, pcrs []int) (uint32, []byte, uint16, []byte, error) {
	cmd, err := encodeReadPCRs(hash, pcrs)
	if err != nil {
		return 0, nil, 0, nil, err
	}
	resp, err := runCommand(rw, tagNoSessions, cmdPCRRead, tpmutil.RawBytes(cmd))
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

func decodeGetCapability(in []byte) (Capability, []tpmutil.Handle, error) {
	var numHandles uint32
	var capReported Capability

	err := tpmutil.Unpack(in[1:9], &capReported, &numHandles)
	if err != nil {
		return 0, nil, err
	}
	// Only TPM_CAP_HANDLES handled.
	if capReported != CapabilityHandles {
		return 0, nil, fmt.Errorf("Only TPM_CAP_HANDLES supported, got %v", capReported)
	}
	var handles []tpmutil.Handle
	var handle tpmutil.Handle
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
func GetCapability(rw io.ReadWriter, cap Capability, count uint32, property uint32) ([]tpmutil.Handle, error) {
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

// encodeCreate works for both TPM2_Create and TPM2_CreatePrimary.
func encodeCreate(owner tpmutil.Handle, pcrNums []int, parentPassword, ownerPassword string, params RSAParams) ([]byte, error) {
	b1, err := tpmutil.Pack(owner)
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
	b5, err := encodeRSAParams(params)
	if err != nil {
		return nil, err
	}
	b6, err := tpmutil.Pack([]byte(nil))
	if err != nil {
		return nil, err
	}
	b7, err := encodeLongPCR(pcrNums)
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

func decodeCreatePrimary(in []byte) (tpmutil.Handle, []byte, error) {
	var handle tpmutil.Handle
	var auth []byte

	// Handle and auth data.
	err := tpmutil.Unpack(in, &handle, &auth)
	if err != nil {
		return 0, nil, err
	}

	var current int
	current = 6 + 2*len(auth)
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
	return handle, pub.Unique, nil
}

// CreatePrimary initializes the primary key in a given hierarchy.
// Second return value is the public part of the generated key.
func CreatePrimary(rw io.ReadWriter, owner tpmutil.Handle, pcrNums []int, parentPassword, ownerPassword string, params RSAParams) (tpmutil.Handle, []byte, error) {
	cmd, err := encodeCreate(owner, pcrNums, parentPassword, ownerPassword, params)
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
	return handle, publicBlob, nil
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
func ReadPublic(rw io.ReadWriter, handle tpmutil.Handle) ([]byte, []byte, []byte, error) {
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
func CreateKey(rw io.ReadWriter, owner tpmutil.Handle, pcrNums []int, parentPassword, ownerPassword string, params RSAParams) ([]byte, []byte, error) {
	cmd, err := encodeCreate(owner, pcrNums, parentPassword, ownerPassword, params)
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

func encodeLoad(parentHandle tpmutil.Handle, parentAuth, ownerAuth string, publicBlob, privateBlob []byte) ([]byte, error) {
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

func decodeLoad(in []byte) (tpmutil.Handle, []byte, error) {
	var handle tpmutil.Handle
	var auth []byte
	var name []byte

	err := tpmutil.Unpack(in, &handle, &auth, &name)
	if err != nil {
		return 0, nil, err
	}
	return handle, name, nil
}

// Load loads public/private blobs into an object in the TPM.
// Returns loaded object handle and its name.
func Load(rw io.ReadWriter, parentHandle tpmutil.Handle, parentAuth, ownerAuth string, publicBlob, privateBlob []byte) (tpmutil.Handle, []byte, error) {
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
func PolicyPassword(rw io.ReadWriter, handle tpmutil.Handle) error {
	_, err := runCommand(rw, tagNoSessions, cmdPolicyPassword, handle)
	return err
}

func encodePolicyPCR(handle tpmutil.Handle, expectedDigest []byte, pcrNums []int) ([]byte, error) {
	b1, err := tpmutil.Pack(handle, expectedDigest)
	if err != nil {
		return nil, err
	}
	b2, err := encodeLongPCR(pcrNums)
	if err != nil {
		return nil, err
	}
	return append(b1, b2...), nil
}

// PolicyPCR sets PCR state binding for authorization on the object.
func PolicyPCR(rw io.ReadWriter, handle tpmutil.Handle, expectedDigest []byte, pcrNums []int) error {
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
func PolicyGetDigest(rw io.ReadWriter, handle tpmutil.Handle) ([]byte, error) {
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

func encodeStartAuthSession(tpmKey, bindKey tpmutil.Handle, nonceCaller, secret []byte, se SessionType, sym, hashAlg Algorithm) ([]byte, error) {
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

func decodeStartAuthSession(in []byte) (tpmutil.Handle, []byte, error) {
	var handle tpmutil.Handle
	var nonce []byte
	err := tpmutil.Unpack(in, &handle, &nonce)
	if err != nil {
		return 0, nil, err
	}
	return handle, nonce, nil
}

// StartAuthSession initializes a session object.
// Returns session handle and the initial nonce from the TPM.
func StartAuthSession(rw io.ReadWriter, tpmKey, bindKey tpmutil.Handle, nonceCaller, secret []byte, se SessionType, sym, hashAlg Algorithm) (tpmutil.Handle, []byte, error) {
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

func encodeUnseal(itemHandle tpmutil.Handle, password string, sessionHandle tpmutil.Handle) ([]byte, error) {
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
func Unseal(rw io.ReadWriter, itemHandle tpmutil.Handle, password string, sessionHandle tpmutil.Handle, digest []byte) ([]byte, []byte, error) {
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

func encodeQuote(signingHandle tpmutil.Handle, parentPassword, ownerPassword string, toQuote []byte, pcrNums []int, sigAlg Algorithm) ([]byte, error) {
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
	b5, err := encodeLongPCR(pcrNums)
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

// Quote returns a quote of PCR values. A quote is a signature of the PCR
// values, created using a signing TPM key.
//
// Returns attestation data and the signature.
func Quote(rw io.ReadWriter, signingHandle tpmutil.Handle, parentPassword, ownerPassword string, toQuote []byte, pcrNums []int, sigAlg Algorithm) ([]byte, []byte, error) {
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

func encodeActivateCredential(activeHandle tpmutil.Handle, keyHandle tpmutil.Handle, activePassword, protectorPassword string, credBlob, secret []byte) ([]byte, error) {
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
func ActivateCredential(rw io.ReadWriter, activeHandle, keyHandle tpmutil.Handle, activePassword, protectorPassword string, credBlob, secret []byte) ([]byte, error) {
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

func encodeMakeCredential(protectorHandle tpmutil.Handle, credential, activeName []byte) ([]byte, error) {
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
func MakeCredential(rw io.ReadWriter, protectorHandle tpmutil.Handle, credential, activeName []byte) ([]byte, []byte, error) {
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

func encodeEvictControl(owner tpmutil.Handle, tmpHandle, persistentHandle tpmutil.Handle) ([]byte, error) {
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
	b5, err := tpmutil.Pack(persistentHandle)
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
func EvictControl(rw io.ReadWriter, owner, tmpHandle, persistentHandle tpmutil.Handle) error {
	cmd, err := encodeEvictControl(owner, tmpHandle, persistentHandle)
	if err != nil {
		return err
	}
	_, err = runCommand(rw, tagSessions, cmdEvictControl, tpmutil.RawBytes(cmd))
	return err
}

// ContextSave returns an encrypted version of the session, object or sequence
// context for storage outside of the TPM. The handle references context to
// store.
func ContextSave(rw io.ReadWriter, handle tpmutil.Handle) ([]byte, error) {
	return runCommand(rw, tagNoSessions, cmdContextSave, handle)
}

func decodeLoadContext(in []byte) (tpmutil.Handle, error) {
	var handle tpmutil.Handle
	err := tpmutil.Unpack(in, &handle)
	if err != nil {
		return 0, err
	}
	return handle, nil
}

// ContextLoad reloads context data created by ContextSave.
func ContextLoad(rw io.ReadWriter, saveArea []byte) (tpmutil.Handle, error) {
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

func encodeIncrementNV(handle tpmutil.Handle, authString string) ([]byte, error) {
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

// NVIncrement increments a counter in NVRAM.
func NVIncrement(rw io.ReadWriter, handle tpmutil.Handle, authString string) error {
	cmd, err := encodeIncrementNV(handle, authString)
	if err != nil {
		return err
	}
	_, err = runCommand(rw, tagSessions, cmdIncrementNVCounter, tpmutil.RawBytes(cmd))
	return err
}

func encodeUndefineSpace(owner, handle tpmutil.Handle) ([]byte, error) {
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
func NVUndefineSpace(rw io.ReadWriter, owner, handle tpmutil.Handle) error {
	cmd, err := encodeUndefineSpace(owner, handle)
	if err != nil {
		return err
	}
	_, err = runCommand(rw, tagSessions, cmdUndefineSpace, tpmutil.RawBytes(cmd))
	return err
}

func encodeDefineSpace(owner, handle tpmutil.Handle, authString string, attributes uint32, policy []byte, dataSize uint16) ([]byte, error) {
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
	sizeNVArea := uint16(2*int(unsafe.Sizeof(owner)) + 3*int(unsafe.Sizeof(dataSize)) + len(policy))
	out1 = append(append(out1, auth...), pw...)
	out2, err := tpmutil.Pack(sizeNVArea, handle, hashAlg, attributes, policy, dataSize)
	if err != nil {
		return nil, err
	}
	return append(out1, out2...), nil
}

// NVDefineSpace creates an index in TPM's NV storage.
func NVDefineSpace(rw io.ReadWriter, owner, handle tpmutil.Handle, authString string, policy []byte, attributes uint32, dataSize uint16) error {
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

func encodeNVRead(handle tpmutil.Handle, authString string, offset, dataSize uint16) ([]byte, error) {
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

// NVRead reads a full data blob from an NV index.
func NVRead(rw io.ReadWriter, index tpmutil.Handle) ([]byte, error) {
	// Read public area to determine data size.
	resp, err := runCommand(rw, tagNoSessions, cmdReadPublicNV, index)
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
	resp, err = runCommand(rw, tagSessions, cmdReadNV, tpmutil.RawBytes(cmd))
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

func encodeSign(key tpmutil.Handle, password string, digest []byte) ([]byte, error) {
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
func Sign(rw io.ReadWriter, key tpmutil.Handle, data []byte) (Algorithm, []byte, error) {
	digest, err := Hash(rw, AlgSHA256, data)
	if err != nil {
		return 0, nil, err
	}
	cmd, err := encodeSign(key, "", digest)
	if err != nil {
		return 0, nil, err
	}
	resp, err := runCommand(rw, tagSessions, cmdReadNV, tpmutil.RawBytes(cmd))
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
