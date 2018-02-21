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
	"bytes"
	"fmt"
	"io"

	"github.com/google/go-tpm/tpmutil"
)

// OpenTPM opens a channel to the TPM at the given path. If the file is a
// device, then it treats it like a normal TPM device, and if the file is a
// Unix domain socket, then it opens a connection to the socket.
var OpenTPM = tpmutil.OpenTPM

// GetRandom gets random bytes from the TPM.
func GetRandom(rw io.ReadWriteCloser, size uint16) ([]byte, error) {
	resp, err := runCommand(rw, tagNoSessions, cmdGetRandom, size)
	if err != nil {
		return nil, err
	}

	var randBytes []byte
	if _, err := tpmutil.Unpack(resp, &randBytes); err != nil {
		return nil, err
	}
	return randBytes, nil
}

// FlushContext removes an object or session under handle to be removed from
// the TPM. This must be called for any loaded handle to avoid out-of-memory
// errors in TPM.
func FlushContext(rw io.ReadWriter, handle tpmutil.Handle) error {
	_, err := runCommand(rw, tagNoSessions, cmdFlushContext, handle)
	return err
}

func encodeTPMLPCRSelection(sel PCRSelection) ([]byte, error) {
	if len(sel.PCRs) == 0 {
		return tpmutil.Pack(uint32(0))
	}

	// PCR selection is a variable-size bitmask, where position of a set bit is
	// the selected PCR index.
	// Size of the bitmask in bytes is pre-pended. It should be at least
	// sizeOfPCRSelect.
	//
	// For example, selecting PCRs 3 and 9 looks like:
	// size(3)  mask     mask     mask
	// 00000011 00000000 00000001 00000100
	ts := tpmsPCRSelection{
		Hash: sel.Hash,
		Size: sizeOfPCRSelect,
		PCRs: make([]byte, sizeOfPCRSelect),
	}
	// sel.PCRs parameter is indexes of PCRs, convert that to set bits.
	for _, n := range sel.PCRs {
		byteNum := n / 8
		bytePos := byte(1 << byte(n%8))
		ts.PCRs[byteNum] |= bytePos
	}
	// Only encode 1 TPMS_PCR_SELECT value.
	return tpmutil.Pack(uint32(1), ts)
}

func decodeTPMLPCRSelection(buf []byte) (int, PCRSelection, error) {
	initialLen := len(buf)

	var count uint32
	var sel PCRSelection
	read, err := tpmutil.Unpack(buf, &count)
	if err != nil {
		return 0, sel, err
	}
	buf = buf[read:]
	if count != 1 {
		return 0, sel, fmt.Errorf("decoding TPML_PCR_SELECTION list longer than 1 is not supported (got length %d)", count)
	}

	// See comment in encodeTPMLPCRSelection for details on this format.
	var ts tpmsPCRSelection
	read, err = tpmutil.Unpack(buf, &ts.Hash, &ts.Size)
	if err != nil {
		return 0, sel, err
	}
	buf = buf[read:]
	ts.PCRs, buf = buf[:ts.Size], buf[ts.Size:]

	sel.Hash = ts.Hash
	for i := 0; i < int(ts.Size); i++ {
		for j := 0; j < 8; j++ {
			set := ts.PCRs[i] & byte(1<<byte(j))
			if set == 0 {
				continue
			}
			sel.PCRs = append(sel.PCRs, 8*i+j)
		}
	}
	return initialLen - len(buf), sel, nil
}

func decodeReadPCRs(in []byte) (map[int][]byte, error) {
	var updateCounter uint32
	read, err := tpmutil.Unpack(in, &updateCounter)
	if err != nil {
		return nil, err
	}
	in = in[read:]

	read, sel, err := decodeTPMLPCRSelection(in)
	if err != nil {
		return nil, fmt.Errorf("decoding TPML_PCR_SELECTION: %v", err)
	}
	in = in[read:]

	var digestCount uint32
	read, err = tpmutil.Unpack(in, &digestCount)
	if err != nil {
		return nil, fmt.Errorf("decoding TPML_DIGEST length: %v", err)
	}
	in = in[read:]
	if int(digestCount) != len(sel.PCRs) {
		return nil, fmt.Errorf("received %d PCRs but %d digests", len(sel.PCRs), digestCount)
	}

	vals := make(map[int][]byte)
	for _, pcr := range sel.PCRs {
		var val []byte
		read, err = tpmutil.Unpack(in, &val)
		if err != nil {
			return nil, fmt.Errorf("decoding TPML_DIGEST item: %v", err)
		}
		in = in[read:]
		vals[pcr] = val
	}
	return vals, nil
}

// ReadPCRs reads PCR values from the TPM.
func ReadPCRs(rw io.ReadWriter, sel PCRSelection) (map[int][]byte, error) {
	cmd, err := encodeTPMLPCRSelection(sel)
	if err != nil {
		return nil, err
	}
	resp, err := runCommand(rw, tagNoSessions, cmdPCRRead, tpmutil.RawBytes(cmd))
	if err != nil {
		return nil, err
	}

	return decodeReadPCRs(resp)
}

func decodeReadClock(in []byte) (uint64, uint64, error) {
	var curTime, curClock uint64

	_, err := tpmutil.Unpack(in, &curTime, &curClock)
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
	return decodeReadClock(resp)
}

func decodeGetCapability(in []byte) (Capability, []tpmutil.Handle, error) {
	var moreData byte
	var capReported Capability

	read, err := tpmutil.Unpack(in, &moreData, &capReported)
	if err != nil {
		return 0, nil, err
	}
	in = in[read:]
	// Only TPM_CAP_HANDLES handled.
	if capReported != CapabilityHandles {
		return 0, nil, fmt.Errorf("Only TPM_CAP_HANDLES supported, got %v", capReported)
	}

	var numHandles uint32
	read, err = tpmutil.Unpack(in, &numHandles)
	if err != nil {
		return 0, nil, err
	}
	in = in[read:]

	var handles []tpmutil.Handle
	for i := 0; i < int(numHandles); i++ {
		var handle tpmutil.Handle
		read, err = tpmutil.Unpack(in, &handle)
		if err != nil {
			return 0, nil, err
		}
		in = in[read:]
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

func encodePasswordAuthArea(passwords ...string) ([]byte, error) {
	var res []byte
	for _, p := range passwords {
		// Empty nonce.
		var nonce []byte
		// continueSession set, all other bits clear.
		attributes := byte(1)
		buf, err := tpmutil.Pack(HandlePasswordSession, nonce, attributes, []byte(p))
		if err != nil {
			return nil, err
		}
		res = append(res, buf...)
	}

	size, err := tpmutil.Pack(uint32(len(res)))
	if err != nil {
		return nil, err
	}

	return concat(size, res)
}

func encodePCREvent(pcr tpmutil.Handle, eventData []byte) ([]byte, error) {
	ha, err := tpmutil.Pack(pcr, HandleNull)
	if err != nil {
		return nil, err
	}
	auth, err := encodePasswordAuthArea("")
	if err != nil {
		return nil, err
	}
	event, err := tpmutil.Pack(eventData)
	if err != nil {
		return nil, err
	}
	return concat(ha, auth, event)
}

// PCREvent writes an update to the specified PCR.
func PCREvent(rw io.ReadWriter, pcr tpmutil.Handle, eventData []byte) error {
	cmd, err := encodePCREvent(pcr, eventData)
	if err != nil {
		return err
	}
	_, err = runCommand(rw, tagSessions, cmdPCREvent, tpmutil.RawBytes(cmd))
	return err
}

func encodeSensitiveArea(s tpmsSensitiveCreate) ([]byte, error) {
	// TPMS_SENSITIVE_CREATE
	buf, err := tpmutil.Pack(s)
	if err != nil {
		return nil, err
	}
	// TPM2B_SENSITIVE_CREATE
	return tpmutil.Pack(buf)
}

func encodeRSAParams(params RSAParams) ([]byte, error) {
	fields := []interface{}{
		params.EncAlg,
		params.HashAlg,
		params.Attributes,
		params.AuthPolicy,
		params.SymAlg,
	}
	if params.SymAlg != AlgNull {
		fields = append(fields, params.SymSize, params.Mode)
	}
	fields = append(fields, params.Scheme)
	if params.Scheme == AlgRSASSA {
		fields = append(fields, params.SchemeHash)
	}
	fields = append(fields, params.ModSize, params.Exp, params.Modulus)

	// TPMT_PUBLIC structure.
	buf, err := tpmutil.Pack(fields...)
	if err != nil {
		return nil, err
	}
	// Pack TPMT_PUBLIC in TPM2B_PUBLIC.
	return tpmutil.Pack(buf)
}

// encodeCreate works for both TPM2_Create and TPM2_CreatePrimary.
func encodeCreate(owner tpmutil.Handle, sel PCRSelection, parentPassword, ownerPassword string, params RSAParams) ([]byte, error) {
	parent, err := tpmutil.Pack(owner)
	if err != nil {
		return nil, err
	}
	auth, err := encodePasswordAuthArea(parentPassword)
	if err != nil {
		return nil, err
	}
	inSensitive, err := encodeSensitiveArea(tpmsSensitiveCreate{UserAuth: []byte(ownerPassword)})
	if err != nil {
		return nil, err
	}
	inPublic, err := encodeRSAParams(params)
	if err != nil {
		return nil, err
	}
	outsideInfo, err := tpmutil.Pack([]byte(nil))
	if err != nil {
		return nil, err
	}
	creationPCR, err := encodeTPMLPCRSelection(sel)
	if err != nil {
		return nil, err
	}
	return concat(
		parent,
		auth,
		inSensitive,
		inPublic,
		outsideInfo,
		creationPCR,
	)
}

func decodeCreatePrimary(in []byte) (tpmutil.Handle, []byte, error) {
	var handle tpmutil.Handle
	var paramSize uint32

	// Handle and auth data.
	read, err := tpmutil.Unpack(in, &handle, &paramSize)
	if err != nil {
		return 0, nil, err
	}
	in = in[read:]

	var public []byte
	read, err = tpmutil.Unpack(in, &public)
	if err != nil {
		return 0, nil, fmt.Errorf("decoding TPM2B_PUBLIC: %v", err)
	}
	var pub tpmtPublic
	if _, err := tpmutil.Unpack(public, &pub); err != nil {
		return 0, nil, fmt.Errorf("decoding TPMT_PUBLIC: %v", err)
	}
	return handle, pub.Unique, nil
}

// CreatePrimary initializes the primary key in a given hierarchy.
// Second return value is the public part of the generated key.
func CreatePrimary(rw io.ReadWriter, owner tpmutil.Handle, sel PCRSelection, parentPassword, ownerPassword string, params RSAParams) (tpmutil.Handle, []byte, error) {
	cmd, err := encodeCreate(owner, sel, parentPassword, ownerPassword, params)
	if err != nil {
		return 0, nil, err
	}
	resp, err := runCommand(rw, tagSessions, cmdCreatePrimary, tpmutil.RawBytes(cmd))
	if err != nil {
		return 0, nil, err
	}

	return decodeCreatePrimary(resp)
}

func decodeReadPublic(in []byte) (Public, []byte, []byte, error) {
	var resp struct {
		Public        []byte
		Name          []byte
		QualifiedName []byte
	}
	_, err := tpmutil.Unpack(in, &resp)
	if err != nil {
		return Public{}, nil, nil, err
	}
	var pub Public
	if _, err := tpmutil.Unpack(resp.Public, &pub); err != nil {
		return Public{}, nil, nil, err
	}
	return pub, resp.Name, resp.QualifiedName, nil
}

// ReadPublic reads the public part of the object under handle.
// Returns the public data, name and qualified name.
func ReadPublic(rw io.ReadWriter, handle tpmutil.Handle) (Public, []byte, []byte, error) {
	resp, err := runCommand(rw, tagNoSessions, cmdReadPublic, handle)
	if err != nil {
		return Public{}, nil, nil, err
	}

	return decodeReadPublic(resp)
}

func decodeCreateKey(in []byte) ([]byte, []byte, error) {
	var resp struct {
		Handle  tpmutil.Handle
		Private []byte
		Public  []byte
	}

	_, err := tpmutil.Unpack(in, &resp)
	if err != nil {
		return nil, nil, err
	}
	return resp.Private, resp.Public, nil
}

// CreateKey creates a new RSA key pair under the owner handle.
// Returns private key and public key blobs.
func CreateKey(rw io.ReadWriter, owner tpmutil.Handle, sel PCRSelection, parentPassword, ownerPassword string, params RSAParams) ([]byte, []byte, error) {
	cmd, err := encodeCreate(owner, sel, parentPassword, ownerPassword, params)
	if err != nil {
		return nil, nil, err
	}
	resp, err := runCommand(rw, tagSessions, cmdCreate, tpmutil.RawBytes(cmd))
	if err != nil {
		return nil, nil, err
	}
	return decodeCreateKey(resp)
}

func encodeLoad(parentHandle tpmutil.Handle, parentAuth string, publicBlob, privateBlob []byte) ([]byte, error) {
	ah, err := tpmutil.Pack(parentHandle)
	if err != nil {
		return nil, err
	}
	auth, err := encodePasswordAuthArea(parentAuth)
	if err != nil {
		return nil, err
	}
	params, err := tpmutil.Pack(privateBlob, publicBlob)
	if err != nil {
		return nil, err
	}
	return concat(ah, auth, params)
}

func decodeLoad(in []byte) (tpmutil.Handle, []byte, error) {
	var handle tpmutil.Handle
	var paramSize uint32
	var name []byte

	_, err := tpmutil.Unpack(in, &handle, &paramSize, &name)
	if err != nil {
		return 0, nil, err
	}
	return handle, name, nil
}

// Load loads public/private blobs into an object in the TPM.
// Returns loaded object handle and its name.
func Load(rw io.ReadWriter, parentHandle tpmutil.Handle, parentAuth string, publicBlob, privateBlob []byte) (tpmutil.Handle, []byte, error) {
	cmd, err := encodeLoad(parentHandle, parentAuth, publicBlob, privateBlob)
	if err != nil {
		return 0, nil, err
	}
	resp, err := runCommand(rw, tagSessions, cmdLoad, tpmutil.RawBytes(cmd))
	if err != nil {
		return 0, nil, err
	}
	return decodeLoad(resp)
}

// PolicyPassword sets password authorization requirement on the object.
func PolicyPassword(rw io.ReadWriter, handle tpmutil.Handle) error {
	_, err := runCommand(rw, tagNoSessions, cmdPolicyPassword, handle)
	return err
}

func encodePolicyPCR(session tpmutil.Handle, expectedDigest []byte, sel PCRSelection) ([]byte, error) {
	params, err := tpmutil.Pack(session, expectedDigest)
	if err != nil {
		return nil, err
	}
	pcrs, err := encodeTPMLPCRSelection(sel)
	if err != nil {
		return nil, err
	}
	return concat(params, pcrs)
}

// PolicyPCR sets PCR state binding for authorization on a session.
func PolicyPCR(rw io.ReadWriter, session tpmutil.Handle, expectedDigest []byte, sel PCRSelection) error {
	cmd, err := encodePolicyPCR(session, expectedDigest, sel)
	if err != nil {
		return err
	}
	_, err = runCommand(rw, tagNoSessions, cmdPolicyPCR, tpmutil.RawBytes(cmd))
	return err
}

// PolicyGetDigest returns the current policyDigest of the session.
func PolicyGetDigest(rw io.ReadWriter, handle tpmutil.Handle) ([]byte, error) {
	resp, err := runCommand(rw, tagNoSessions, cmdPolicyGetDigest, handle)
	if err != nil {
		return nil, err
	}

	var digest []byte
	_, err = tpmutil.Unpack(resp, &digest)
	return digest, err
}

func encodeStartAuthSession(tpmKey, bindKey tpmutil.Handle, nonceCaller, secret []byte, se SessionType, sym, hashAlg Algorithm) ([]byte, error) {
	ha, err := tpmutil.Pack(tpmKey, bindKey)
	if err != nil {
		return nil, err
	}
	params, err := tpmutil.Pack(nonceCaller, secret, se, sym, hashAlg)
	if err != nil {
		return nil, err
	}
	return concat(ha, params)
}

func decodeStartAuthSession(in []byte) (tpmutil.Handle, []byte, error) {
	var handle tpmutil.Handle
	var nonce []byte
	_, err := tpmutil.Unpack(in, &handle, &nonce)
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
	return decodeStartAuthSession(resp)
}

func encodeUnseal(itemHandle tpmutil.Handle, password string) ([]byte, error) {
	ha, err := tpmutil.Pack(itemHandle)
	if err != nil {
		return nil, err
	}
	auth, err := encodePasswordAuthArea(password)
	if err != nil {
		return nil, err
	}
	return concat(ha, auth)
}

func decodeUnseal(in []byte) ([]byte, error) {
	var paramSize uint32
	var unsealed []byte

	_, err := tpmutil.Unpack(in, &paramSize, &unsealed)
	if err != nil {
		return nil, err
	}
	return unsealed, nil
}

// Unseal returns the data for a loaded sealed object.
func Unseal(rw io.ReadWriter, itemHandle tpmutil.Handle, password string) ([]byte, error) {
	cmd, err := encodeUnseal(itemHandle, password)
	if err != nil {
		return nil, err
	}
	resp, err := runCommand(rw, tagSessions, cmdUnseal, tpmutil.RawBytes(cmd))
	if err != nil {
		return nil, err
	}
	return decodeUnseal(resp)
}

func encodeQuote(signingHandle tpmutil.Handle, parentPassword, ownerPassword string, toQuote []byte, sel PCRSelection, sigAlg Algorithm) ([]byte, error) {
	ha, err := tpmutil.Pack(signingHandle)
	if err != nil {
		return nil, err
	}
	auth, err := encodePasswordAuthArea(parentPassword)
	if err != nil {
		return nil, err
	}
	params, err := tpmutil.Pack(toQuote, sigAlg)
	if err != nil {
		return nil, err
	}
	pcrs, err := encodeTPMLPCRSelection(sel)
	if err != nil {
		return nil, err
	}
	return concat(ha, auth, params, pcrs)
}

func decodeQuote(in []byte) ([]byte, []byte, error) {
	var paramSize uint32
	var attest []byte
	var signature tpmtSignatureRSA

	if _, err := tpmutil.Unpack(in, &paramSize, &attest, &signature); err != nil {
		return nil, nil, err
	}
	return attest, signature.Signature, nil
}

// Quote returns a quote of PCR values. A quote is a signature of the PCR
// values, created using a signing TPM key.
//
// Returns attestation data and the signature.
//
// Note: currently only RSA signatures are supported.
func Quote(rw io.ReadWriter, signingHandle tpmutil.Handle, parentPassword, ownerPassword string, toQuote []byte, sel PCRSelection, sigAlg Algorithm) ([]byte, []byte, error) {
	cmd, err := encodeQuote(signingHandle, parentPassword, ownerPassword, toQuote, sel, sigAlg)
	if err != nil {
		return nil, nil, err
	}
	resp, err := runCommand(rw, tagSessions, cmdQuote, tpmutil.RawBytes(cmd))
	if err != nil {
		return nil, nil, err
	}
	return decodeQuote(resp)
}

func encodeActivateCredential(activeHandle tpmutil.Handle, keyHandle tpmutil.Handle, activePassword, protectorPassword string, credBlob, secret []byte) ([]byte, error) {
	ha, err := tpmutil.Pack(activeHandle, keyHandle)
	if err != nil {
		return nil, err
	}
	auth, err := encodePasswordAuthArea(activePassword, protectorPassword)
	if err != nil {
		return nil, err
	}
	params, err := tpmutil.Pack(credBlob, secret)
	if err != nil {
		return nil, err
	}
	return concat(ha, auth, params)
}

func decodeActivateCredential(in []byte) ([]byte, error) {
	var paramSize uint32
	var certInfo []byte

	_, err := tpmutil.Unpack(in, &paramSize, &certInfo)
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
	return decodeActivateCredential(resp)
}

func encodeMakeCredential(protectorHandle tpmutil.Handle, credential, activeName []byte) ([]byte, error) {
	ha, err := tpmutil.Pack(protectorHandle)
	if err != nil {
		return nil, err
	}
	params, err := tpmutil.Pack(credential, activeName)
	if err != nil {
		return nil, err
	}
	return concat(ha, params)
}

func decodeMakeCredential(in []byte) ([]byte, []byte, error) {
	var credBlob []byte
	var encryptedSecret []byte

	_, err := tpmutil.Unpack(in, &credBlob, &encryptedSecret)
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
	return decodeMakeCredential(resp)
}

func encodeEvictControl(ownerAuth string, owner, objectHandle, persistentHandle tpmutil.Handle) ([]byte, error) {
	ha, err := tpmutil.Pack(owner, objectHandle)
	if err != nil {
		return nil, err
	}
	auth, err := encodePasswordAuthArea(ownerAuth)
	if err != nil {
		return nil, err
	}
	params, err := tpmutil.Pack(persistentHandle)
	if err != nil {
		return nil, err
	}
	return concat(ha, auth, params)
}

// EvictControl toggles persistence of an object within the TPM.
func EvictControl(rw io.ReadWriter, ownerAuth string, owner, objectHandle, persistentHandle tpmutil.Handle) error {
	cmd, err := encodeEvictControl(ownerAuth, owner, objectHandle, persistentHandle)
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

// ContextLoad reloads context data created by ContextSave.
func ContextLoad(rw io.ReadWriter, saveArea []byte) (tpmutil.Handle, error) {
	resp, err := runCommand(rw, tagNoSessions, cmdContextLoad, tpmutil.RawBytes(saveArea))
	if err != nil {
		return 0, err
	}
	var handle tpmutil.Handle
	_, err = tpmutil.Unpack(resp, &handle)
	return handle, err
}

func encodeIncrementNV(handle tpmutil.Handle, authString string) ([]byte, error) {
	auth, err := encodePasswordAuthArea(authString)
	if err != nil {
		return nil, err
	}
	out, err := tpmutil.Pack(handle, handle)
	if err != nil {
		return nil, err
	}
	return concat(out, auth)
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

func encodeUndefineSpace(ownerAuth string, owner, index tpmutil.Handle) ([]byte, error) {
	auth, err := encodePasswordAuthArea(ownerAuth)
	if err != nil {
		return nil, err
	}
	out, err := tpmutil.Pack(owner, index)
	if err != nil {
		return nil, err
	}
	return concat(out, auth)
}

// NVUndefineSpace removes an index from TPM's NV storage.
func NVUndefineSpace(rw io.ReadWriter, ownerAuth string, owner, index tpmutil.Handle) error {
	cmd, err := encodeUndefineSpace(ownerAuth, owner, index)
	if err != nil {
		return err
	}
	_, err = runCommand(rw, tagSessions, cmdUndefineSpace, tpmutil.RawBytes(cmd))
	return err
}

func encodeDefineSpace(owner, handle tpmutil.Handle, ownerAuth, authVal string, attributes uint32, policy []byte, dataSize uint16) ([]byte, error) {
	ha, err := tpmutil.Pack(owner)
	if err != nil {
		return nil, err
	}
	auth, err := encodePasswordAuthArea(ownerAuth)
	if err != nil {
		return nil, err
	}
	publicInfo, err := tpmutil.Pack(handle, AlgSHA1, attributes, policy, dataSize)
	if err != nil {
		return nil, err
	}
	params, err := tpmutil.Pack([]byte(authVal), publicInfo)
	if err != nil {
		return nil, err
	}
	return concat(ha, auth, params)
}

// NVDefineSpace creates an index in TPM's NV storage.
func NVDefineSpace(rw io.ReadWriter, owner, handle tpmutil.Handle, ownerAuth, authString string, policy []byte, attributes uint32, dataSize uint16) error {
	cmd, err := encodeDefineSpace(owner, handle, ownerAuth, authString, attributes, policy, dataSize)
	if err != nil {
		return err
	}
	_, err = runCommand(rw, tagSessions, cmdDefineSpace, tpmutil.RawBytes(cmd))
	return err
}

func decodeNVReadPublic(in []byte) (NVPublic, error) {
	var pub NVPublic
	var buf []byte
	if _, err := tpmutil.Unpack(in, &buf); err != nil {
		return pub, err
	}
	_, err := tpmutil.Unpack(buf, &pub)
	return pub, err
}

func decodeNVRead(in []byte) ([]byte, error) {
	var sessionAttributes uint32
	var data []byte
	if _, err := tpmutil.Unpack(in, &sessionAttributes, &data); err != nil {
		return nil, err
	}
	return data, nil
}

func encodeNVRead(handle tpmutil.Handle, authString string, offset, dataSize uint16) ([]byte, error) {
	ha, err := tpmutil.Pack(handle, handle)
	if err != nil {
		return nil, err
	}
	auth, err := encodePasswordAuthArea(authString)
	if err != nil {
		return nil, err
	}
	params, err := tpmutil.Pack(dataSize, offset)
	if err != nil {
		return nil, err
	}
	return concat(ha, auth, params)
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
	if _, err = tpmutil.Unpack(resp, &digest); err != nil {
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
	ha, err := tpmutil.Pack(key)
	if err != nil {
		return nil, err
	}
	auth, err := encodePasswordAuthArea(password)
	if err != nil {
		return nil, err
	}
	params, err := tpmutil.Pack(digest, AlgNull, tagHashcheck, HandleNull, []byte(nil))
	if err != nil {
		return nil, err
	}
	return concat(ha, auth, params)
}

func decodeSign(buf []byte) (Algorithm, []byte, error) {
	var signature tpmtSignatureRSA
	if _, err := tpmutil.Unpack(buf, &signature); err != nil {
		return 0, nil, err
	}
	return signature.SigAlg, signature.Signature, nil
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

// concat is a helper for encoding functions that separately encode handle,
// auth and param areas. A nil error is always returned, so that callers can
// simply return concat(a, b, c).
func concat(chunks ...[]byte) ([]byte, error) {
	return bytes.Join(chunks, nil), nil
}
